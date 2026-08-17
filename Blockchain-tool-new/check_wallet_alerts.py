"""
WALLET ALERTS - CHECKING SCRIPT

WHAT THIS IS: a standalone script, run on a schedule (hourly, per the
decision this was built for) as its own separate process - NOT part
of the web app itself. This is deliberate: a check running inside the
same process as the web server would stop firing the moment that
service goes to sleep on a lower-cost hosting tier. Running this as
its own genuinely separate scheduled process means alerts keep
checking on time regardless of whether anyone's actively using the
app right now.

HOW TO DEPLOY THIS ON RENDER:
1. In your Render dashboard, create a NEW service - choose "Cron Job",
   not "Web Service". This is a separate service from your main app,
   even though it lives in the same codebase/repo.
2. Set its Build Command the same as your main web service (installs
   the same dependencies - this script reuses link_tracer.py, auth.py,
   and email_sender.py directly).
3. Set its Start Command to:  python3 check_wallet_alerts.py
4. Set its Schedule to:  0 * * * *   (every hour, on the hour)
5. Give it the SAME environment variables as your main web service -
   it needs the same DATABASE_URL, SMTP_* settings, and blockchain API
   keys, since it's calling the exact same underlying functions.

WHAT IT DOES EACH RUN: loads every saved wallet alert, checks each
wallet's current latest transaction against what was seen last time,
and sends one email for anything genuinely new - then updates the
baseline so the same transaction is never reported twice.
"""

import sys
import traceback

import auth
import link_tracer as lt
import email_sender


def check_all_alerts():
    alerts = _load_all_alerts()
    print(f"Wallet alerts check starting - {len(alerts)} alert(s) to check.")

    checked = 0
    fired = 0
    errors = 0

    for alert in alerts:
        try:
            _check_one_alert(alert)
            checked += 1
        except Exception as error:
            errors += 1
            print(f"⚠️  Error checking alert {alert['id']} ({alert['wallet_address']}): {error}")
            traceback.print_exc()

    print(f"Wallet alerts check complete - {checked} checked, {errors} error(s).")


def _load_all_alerts():
    """Loads every alert across every user - list_wallet_alerts() in
    link_tracer.py is scoped to one user at a time (right, for the
    API), so this script reads the table directly instead."""
    try:
        with auth._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT wa.id, wa.username, wa.wallet_address, wa.chain, wa.label, "
                    "wa.last_seen_tx_hash, u.email "
                    "FROM wallet_alerts wa "
                    "LEFT JOIN users u ON lower(u.username) = lower(wa.username);"
                )
                rows = cur.fetchall()
    except Exception as error:
        print(f"⚠️  Could not load wallet alerts: {error}")
        return []
    return [
        {"id": r[0], "username": r[1], "wallet_address": r[2], "chain": r[3],
         "label": r[4], "last_seen_tx_hash": r[5], "email": r[6]}
        for r in rows
    ]


def _check_one_alert(alert):
    activity = lt.get_wallet_latest_activity(alert["wallet_address"])
    if activity.get("error"):
        print(f"  {alert['wallet_address']}: {activity['error']} - skipping.")
        return

    new_hash = activity.get("latest_tx_hash")
    baseline_hash = alert.get("last_seen_tx_hash")

    # Only fire if there WAS a prior baseline and it's genuinely
    # different now - a brand new alert with no prior check yet should
    # never fire on its own creation-time baseline.
    if new_hash and baseline_hash and new_hash != baseline_hash:
        _send_alert_email(alert, activity["latest_tx"])
    elif new_hash and not baseline_hash:
        print(f"  {alert['wallet_address']}: first activity ever seen ({new_hash}) - recording baseline, not alerting (nothing to compare against yet).")

    _update_alert_baseline(alert["id"], new_hash)


def _send_alert_email(alert, latest_tx):
    if not alert.get("email"):
        print(f"  {alert['wallet_address']}: new activity detected, but user \"{alert['username']}\" has no email on file - cannot notify.")
        return

    label_part = f' ("{alert["label"]}")' if alert.get("label") else ""
    subject = f"New activity on a wallet you're watching{label_part}"
    body = (
        f"New activity was just detected on a wallet you set an alert for.\n\n"
        f"Wallet: {alert['wallet_address']}\n"
        f"Chain: {alert['chain']}\n"
    )
    if alert.get("label"):
        body += f"Your label: {alert['label']}\n"
    body += "\n"
    if latest_tx:
        body += (
            f"Amount: {latest_tx.get('amount_label', 'unknown')}\n"
            f"Counterparty: {latest_tx.get('counterparty', 'unknown')}\n"
            f"Time: {latest_tx.get('tx_time_utc', 'unknown')} UTC\n"
        )
        if latest_tx.get("explorer_url"):
            body += f"View on explorer: {latest_tx['explorer_url']}\n"
    body += (
        "\n---\n"
        "This is an automated notice. Nothing here should be treated as proof of anything on "
        "its own - verify independently before relying on it professionally, same as any other "
        "finding from this tool."
    )

    try:
        email_sender.send_email(alert["email"], subject, body)
        print(f"  {alert['wallet_address']}: alert email sent to {alert['email']}.")
    except Exception as error:
        print(f"  {alert['wallet_address']}: FAILED to send alert email: {error}")


def _update_alert_baseline(alert_id, new_hash):
    try:
        with auth._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE wallet_alerts SET last_seen_tx_hash = COALESCE(%s, last_seen_tx_hash), "
                    "last_checked_at = now() WHERE id = %s;",
                    (new_hash, alert_id)
                )
                conn.commit()
    except Exception as error:
        print(f"⚠️  Could not update alert baseline for {alert_id}: {error}")


if __name__ == "__main__":
    check_all_alerts()
