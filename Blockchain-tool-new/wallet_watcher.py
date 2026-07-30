"""
====================================================================
 WALLET WATCHER - "Hacker Wallet" Activity Checker
 (Ethereum + Bitcoin)
====================================================================

WHAT THIS SCRIPT DOES (plain English):
This script takes a list of wallet addresses that your team has
flagged as suspicious (e.g. linked to a hack, scam, or theft) -
these can be ETHEREUM addresses (0x...) OR BITCOIN addresses
(1..., 3..., or bc1...), mixed freely in the same list - and checks
each one to see if any money has moved in or out of that wallet in
the last N hours (LOOKBACK_HOURS below).

If it finds recent activity, it prints a big, impossible-to-miss
ALERT in your terminal so you know which wallet(s) to investigate
further.

HOW TO RUN THIS SCRIPT (step-by-step, no coding knowledge needed):

STEP 1 - Install Python (if you don't already have it):
    Download from https://www.python.org/downloads/
    (During install, tick the box "Add Python to PATH")

STEP 2 - Install the one required library.
    Open your terminal (Command Prompt / Terminal app) and type:

        pip install requests

STEP 3 - Get a free Etherscan API key (only needed for ETH wallets).
    Etherscan is the standard public website/database used to look
    up Ethereum blockchain activity. Anyone can request a free key:
        1. Go to https://etherscan.io/register
        2. Create a free account
        3. Go to https://etherscan.io/myapikey
        4. Click "Add" to generate a key, then copy it

    NOTE: Bitcoin wallets do NOT need an API key. mempool.space's
    public API is free and open, no registration required.

STEP 4 - Paste your Etherscan API key into this script.
    Scroll down to the line that says:
        ETHERSCAN_API_KEY = "DSYVYN6A6E1FKWNGIPZRYDUR349XEUWYCZ"
    and replace the text between the quotes with your real key.

STEP 5 - Edit the wallet list.
    Scroll down to WATCHLIST_WALLETS below and replace the example
    addresses with your team's real list of flagged wallets. You can
    freely mix Ethereum (0x...) and Bitcoin (1..., 3..., bc1...)
    addresses in the same list - the script figures out which is
    which automatically.

STEP 6 - Run it.
    In your terminal, navigate to the folder this file is saved in,
    then type:

        python wallet_watcher.py

    The script will check every wallet and print a report.
====================================================================
"""

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import os
import json
import requests
import time
from datetime import datetime, timedelta, timezone


# ====================================================================
# SECTION 1: SETTINGS YOU CAN EDIT
# (Everything an analyst needs to change lives in this block)
# ====================================================================

# --------------------------------------------------------------
# Your free Etherscan API key (see STEP 3 above). Only used for
# wallets detected as Ethereum addresses.
# --------------------------------------------------------------

# Reads from the ETHERSCAN_API_KEY environment variable first (this
# is what the dashboard sets), falling back to whatever is pasted
# here directly if you're running this script on its own.
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "DSYVYN6A6E1FKWNGIPZRYDUR349XEUWYCZ")

# --------------------------------------------------------------
# "technical" (default) prints full alert detail: tx hash, exact
# UTC timestamp, block-explorer link. "simple" prints a shorter,
# plain-language version instead - useful when showing results to
# someone non-technical. Set via the OUTPUT_STYLE environment
# variable, or threat_intel_dashboard.py's view toggle sets this
# automatically.
# --------------------------------------------------------------
OUTPUT_STYLE = os.environ.get("OUTPUT_STYLE", "technical").strip().lower()
if OUTPUT_STYLE not in ("technical", "simple"):
    OUTPUT_STYLE = "technical"


def _friendly_datetime(dt):
    return dt.strftime("%d %b %Y at %I:%M %p UTC")

# --------------------------------------------------------------
# Which chain to query on Etherscan. Etherscan's v2 API is
# multichain and REQUIRES this parameter on every request.
# 1 = Ethereum mainnet.
# --------------------------------------------------------------
CHAIN_ID = "1"

# --------------------------------------------------------------
# Public XRP Ledger node used for XRP address lookups. No API key
# needed - this is Ripple's own free public server.
# --------------------------------------------------------------
XRPL_RPC_URL = "https://s1.ripple.com:51234"

# --------------------------------------------------------------
# Shared "case watchlist" file. crypto_address_watcher.py appends
# newly-discovered addresses here automatically. Every time this
# script runs (with no wallets typed in on the command line), it
# checks WATCHLIST_WALLETS below AND everything in this shared file -
# so a fresh discovery gets monitored for movement immediately,
# without you having to copy/paste it in by hand.
# --------------------------------------------------------------
CASE_WATCHLIST_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "case_watchlist.json"
)

# --------------------------------------------------------------
# EXAMPLE wallet addresses only - REPLACE these with your real
# list of flagged/hacker wallets. Mix Ethereum (0x...), Bitcoin
# (1..., 3..., bc1...), and XRP (r...) addresses freely - each is
# auto-detected.
#
# You don't have to edit this list by hand any more: run the script
# with wallets passed in on the command line instead, e.g.
#     python wallet_watcher.py 0xabc... bc1q... rDx...
# or comma-separated:
#     python wallet_watcher.py "0xabc...,bc1q...,rDx..."
# Wallets passed on the command line REPLACE this list entirely for
# that run. Leave the command line empty to use this list as-is.
# --------------------------------------------------------------
WATCHLIST_WALLETS = [
    "0x3f0da746e9c13901696535e78acb102330475a5d",  # EXAMPLE ETH address
    "0xae2Fc483527B8EF99EB5D9B44875F005ba1FaE13",  # EXAMPLE ETH address
    "0x74d1cdAB3D434C610beFa65C3bB30F602846939e",
    "0x1f2f10d1c40777ae1da742455c65828ff36df387",
    "bc1qwq5k2qw2s0wj3fjx9hpvtqgww9k63qywp4xelx",   # EXAMPLE BTC address
    "bc1q9zc252na3383vg490qn6hwmg7x3jxjvmzfraw2",
    "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh",            # EXAMPLE XRP address
]


def load_case_watchlist_addresses():
    """
    PLAIN ENGLISH: Reads the shared case_watchlist.json file (written
    to automatically by crypto_address_watcher.py) and pulls out just
    the address strings. Returns an empty list if the file doesn't
    exist yet (e.g. crypto_address_watcher.py has never been run) or
    can't be read.
    """
    if not os.path.isfile(CASE_WATCHLIST_FILE):
        return []
    try:
        with open(CASE_WATCHLIST_FILE, "r", encoding="utf-8") as file_handle:
            entries = json.load(file_handle)
        return [entry["address"] for entry in entries if entry.get("address")]
    except (json.JSONDecodeError, OSError, KeyError) as error:
        print(f"  ⚠️  Could not read shared case watchlist: {error}")
        return []


def get_watchlist_from_cli_or_default():
    """
    PLAIN ENGLISH: Works out the base list of wallets to check - from
    the command line if any were passed in, otherwise the built-in
    WATCHLIST_WALLETS above - and then ALWAYS merges in anything
    crypto_address_watcher.py has added to the shared case watchlist,
    so a freshly-discovered address gets checked automatically no
    matter how you're running this script.
    """
    cli_args = sys.argv[1:]
    if cli_args:
        wallets = []
        for arg in cli_args:
            wallets.extend(part.strip() for part in arg.split(",") if part.strip())
        base_wallets = wallets if wallets else WATCHLIST_WALLETS
    else:
        base_wallets = WATCHLIST_WALLETS

    case_watchlist_addresses = load_case_watchlist_addresses()
    if not case_watchlist_addresses:
        return base_wallets

    combined = list(base_wallets)
    existing_lowercase = {w.lower() for w in combined}
    added_from_case_file = 0
    for address in case_watchlist_addresses:
        if address.lower() not in existing_lowercase:
            combined.append(address)
            existing_lowercase.add(address.lower())
            added_from_case_file += 1

    if added_from_case_file:
        print(f"🔗 Pulled in {added_from_case_file} address(es) from the shared case "
              f"watchlist ({os.path.basename(CASE_WATCHLIST_FILE)}), found by "
              f"crypto_address_watcher.py.")

    return combined

# --------------------------------------------------------------
# How far back to check for activity (in hours). 24 = last 24 hrs.
# --------------------------------------------------------------
LOOKBACK_HOURS = 48

# --------------------------------------------------------------
# Pause (in seconds) between checking each wallet. Both Etherscan's
# and mempool.space's free tiers rate-limit requests, so this small
# delay prevents the script from being blocked.
# --------------------------------------------------------------
SECONDS_BETWEEN_REQUESTS = 0.25


# ====================================================================
# SECTION 2: ADDRESS DETECTION AND VALIDATION
# ====================================================================

def is_valid_ethereum_address(address):
    """
    PLAIN ENGLISH: Checks that an address looks like a real Ethereum
    address - starts with 0x and is followed by exactly 40
    hexadecimal characters (42 characters total).
    """
    if not address.startswith("0x") or len(address) != 42:
        return False
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False


def is_valid_bitcoin_address(address):
    """
    PLAIN ENGLISH: A basic sanity check that an address LOOKS like a
    real Bitcoin address (not a full checksum validation):
        - Legacy (P2PKH):  starts with "1"
        - Script (P2SH):   starts with "3"
        - SegWit/Taproot:  starts with "bc1"
    """
    if address.startswith("bc1"):
        return 14 <= len(address) <= 74
    if address.startswith("1") or address.startswith("3"):
        allowed_characters = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        if not (25 <= len(address) <= 35):
            return False
        return all(character in allowed_characters for character in address)
    return False


def is_valid_xrp_address(address):
    """
    PLAIN ENGLISH: A basic sanity check that an address LOOKS like a
    real XRP Ledger ("classic") address (not full checksum
    validation): starts with "r" and is base58-encoded, 25-35
    characters long. This does not (yet) validate X-address format
    (starting with "X"), only the more common classic "r..." form.
    """
    if not address.startswith("r"):
        return False
    if not (25 <= len(address) <= 35):
        return False
    allowed_characters = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return all(character in allowed_characters for character in address)


def detect_chain(address):
    """
    Returns "ethereum", "bitcoin", "xrp", or None if the address
    doesn't look valid for any supported chain.
    """
    if is_valid_ethereum_address(address):
        return "ethereum"
    if is_valid_bitcoin_address(address):
        return "bitcoin"
    if is_valid_xrp_address(address):
        return "xrp"
    return None


# ====================================================================
# SECTION 3: ETHEREUM LOGIC (via Etherscan)
# ====================================================================

def get_recent_eth_transactions(wallet_address, api_key):
    """
    PLAIN ENGLISH: Asks Etherscan for the most recent transactions
    for this Ethereum wallet address.
    """
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": CHAIN_ID,  # REQUIRED by Etherscan's v2 API
        "module": "account",
        "action": "txlist",
        "address": wallet_address,
        "sort": "desc",
        "apikey": api_key,
    }
    response = requests.get(url, params=params, timeout=15)
    data = response.json()

    # "1" = success. "0" with "No transactions found" = genuinely
    # empty. "0" with anything else = a real error - surface it
    # instead of silently treating it as "nothing happened".
    if data.get("status") == "1":
        return data.get("result", [])
    elif data.get("message") == "No transactions found":
        return []
    else:
        print(f"  ⚠️  Etherscan error: {data.get('message')} - {data.get('result')}")
        return []


def eth_moved_money_recently(transactions, lookback_hours):
    """
    PLAIN ENGLISH: Checks whether any Ethereum transaction happened
    within the lookback window. Returns (tx, tx_time) or (None, None).
    """
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    for tx in transactions:
        tx_time = datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc)
        if tx_time >= cutoff_time:
            return tx, tx_time

    return None, None


def print_eth_alert(wallet_address, tx, tx_time):
    """
    PLAIN ENGLISH: Prints a big, hard-to-miss warning banner for an
    Ethereum wallet that has moved money recently.
    """
    eth_value = int(tx["value"]) / 1_000_000_000_000_000_000

    if OUTPUT_STYLE == "simple":
        if tx.get("from", "").lower() == wallet_address.lower():
            action, counterparty_label = "sent", "to"
        else:
            action, counterparty_label = "received", "from"
        print(f"\n⚠️  This wallet has moved money recently.")
        print(f"  Wallet : {wallet_address}")
        print(f"  What happened: {action} {eth_value:.4f} ETH {counterparty_label} another wallet")
        print(f"  When: {_friendly_datetime(tx_time)}")
        print("  (Full technical detail - the transaction reference and a verify link - "
              "is available in Technical View.)")
        return

    print("\n" + "🚨" * 20)
    print("🚨  ALERT: FLAGGED ETHEREUM WALLET HAS MOVED FUNDS  🚨")
    print("🚨" * 20)
    print(f"  Wallet Address : {wallet_address}")
    print(f"  Transaction Time (UTC): {tx_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Amount Moved   : {eth_value:.6f} ETH")
    print(f"  From           : {tx['from']}")
    print(f"  To             : {tx['to']}")
    print(f"  Tx Hash        : {tx['hash']}")
    print(f"  View on Etherscan: https://etherscan.io/tx/{tx['hash']}")
    print("🚨" * 20 + "\n")


def check_ethereum_wallet(wallet_address):
    """
    PLAIN ENGLISH: Runs the full recent-activity check for one
    Ethereum wallet. Returns True if an alert was raised.
    """
    try:
        transactions = get_recent_eth_transactions(wallet_address, ETHERSCAN_API_KEY)
    except requests.exceptions.RequestException as error:
        print(f"  ⚠️  Could not reach Etherscan for this wallet: {error}")
        return False

    if not transactions:
        print("  No transaction history found for this wallet.")
        return False

    recent_tx, tx_time = eth_moved_money_recently(transactions, LOOKBACK_HOURS)

    if recent_tx:
        print_eth_alert(wallet_address, recent_tx, tx_time)
        return True
    else:
        print("  ✅ No activity in the lookback window. Nothing to report.")
        return False


# ====================================================================
# SECTION 4: BITCOIN LOGIC (via mempool.space)
# ====================================================================

def get_recent_bitcoin_transactions(address):
    """
    PLAIN ENGLISH: Asks mempool.space for this Bitcoin address's most
    recent activity - both pending (mempool) and confirmed
    transactions, newest first. For a recent-activity watcher we only
    need the first page (mempool.space returns pending mempool tx
    plus the first batch of confirmed tx, which is plenty for a
    lookback window of a few days).
    """
    url = f"https://mempool.space/api/address/{address}/txs"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as error:
        print(f"  ⚠️  Could not reach mempool.space: {error}")
        return []
    except ValueError:
        print("  ⚠️  mempool.space returned an unexpected response "
              "(the address may not exist or may be malformed).")
        return []


def bitcoin_moved_recently(transactions, lookback_hours):
    """
    PLAIN ENGLISH: Checks whether any Bitcoin transaction touching
    this address happened within the lookback window.

    - Unconfirmed (mempool) transactions count as "recent" straight
      away, since they've only just been broadcast to the network.
    - Confirmed transactions are checked against their block time,
      same as the Ethereum lookback check.

    Returns (tx, tx_time, is_pending) or (None, None, None).
    """
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    for tx in transactions:
        status = tx.get("status", {})
        if not status.get("confirmed", False):
            # Sitting in the mempool right now = as recent as it gets.
            return tx, datetime.now(timezone.utc), True

        block_time = status.get("block_time")
        if block_time is None:
            continue
        tx_time = datetime.fromtimestamp(block_time, tz=timezone.utc)
        if tx_time >= cutoff_time:
            return tx, tx_time, False

    return None, None, None


def print_bitcoin_alert(wallet_address, tx, tx_time, is_pending):
    """
    PLAIN ENGLISH: Prints a big, hard-to-miss warning banner for a
    Bitcoin wallet that has moved money recently. Shows both how
    much value touched the address as an OUTPUT (received) and as
    an INPUT (spent), since Bitcoin transactions can do either or
    both at once (e.g. spending funds and getting change back).
    """
    received_sats = sum(
        output.get("value", 0)
        for output in tx.get("vout", [])
        if output.get("scriptpubkey_address", "").lower() == wallet_address.lower()
    )
    spent_sats = sum(
        tx_input.get("prevout", {}).get("value", 0)
        for tx_input in tx.get("vin", [])
        if (tx_input.get("prevout") or {}).get("scriptpubkey_address", "").lower() == wallet_address.lower()
    )

    status_label = "PENDING (in mempool, not yet confirmed)" if is_pending else "CONFIRMED"

    if OUTPUT_STYLE == "simple":
        amount_bits = []
        if received_sats > 0:
            amount_bits.append(f"received {received_sats / 100_000_000:.4f} BTC")
        if spent_sats > 0:
            amount_bits.append(f"sent {spent_sats / 100_000_000:.4f} BTC")
        print(f"\n⚠️  This wallet has moved money recently.")
        print(f"  Wallet : {wallet_address}")
        print(f"  What happened: {' and '.join(amount_bits) or 'a transaction was seen'} "
              f"({'not yet confirmed' if is_pending else 'confirmed'})")
        print(f"  When: {_friendly_datetime(tx_time)}")
        print("  (Full technical detail - the transaction reference and a verify link - "
              "is available in Technical View.)")
        return

    print("\n" + "🚨" * 20)
    print("🚨  ALERT: FLAGGED BITCOIN WALLET HAS MOVED FUNDS  🚨")
    print("🚨" * 20)
    print(f"  Wallet Address : {wallet_address}")
    print(f"  Status         : {status_label}")
    print(f"  Transaction Time (UTC): {tx_time.strftime('%Y-%m-%d %H:%M:%S')}")
    if received_sats > 0:
        print(f"  Amount Received: {received_sats / 100_000_000:.8f} BTC")
    if spent_sats > 0:
        print(f"  Amount Spent   : {spent_sats / 100_000_000:.8f} BTC")
    print(f"  Tx Hash        : {tx.get('txid')}")
    print(f"  View on mempool.space: https://mempool.space/tx/{tx.get('txid')}")
    print("🚨" * 20 + "\n")


def check_bitcoin_wallet(wallet_address):
    """
    PLAIN ENGLISH: Runs the full recent-activity check for one
    Bitcoin wallet. Returns True if an alert was raised.
    """
    transactions = get_recent_bitcoin_transactions(wallet_address)

    if not transactions:
        print("  No transaction history found for this wallet.")
        return False

    recent_tx, tx_time, is_pending = bitcoin_moved_recently(transactions, LOOKBACK_HOURS)

    if recent_tx:
        print_bitcoin_alert(wallet_address, recent_tx, tx_time, is_pending)
        return True
    else:
        print("  ✅ No activity in the lookback window. Nothing to report.")
        return False


# ====================================================================
# SECTION 4B: XRP LEDGER LOGIC (via Ripple's public XRPL node)
# ====================================================================

RIPPLE_EPOCH_OFFSET_SECONDS = 946684800  # seconds between 1970-01-01 and 2000-01-01


def get_recent_xrp_transactions(address):
    """
    PLAIN ENGLISH: Asks a public XRP Ledger node for this address's
    most recent validated transactions, newest first. No API key is
    needed - s1.ripple.com is Ripple's own free public server.
    """
    payload = {
        "method": "account_tx",
        "params": [{
            "account": address,
            "ledger_index_min": -1,
            "ledger_index_max": -1,
            "limit": 20,
            "forward": False,
        }],
    }
    try:
        response = requests.post(XRPL_RPC_URL, json=payload, timeout=15)
        data = response.json()
    except requests.exceptions.RequestException as error:
        print(f"  ⚠️  Could not reach the XRP Ledger node: {error}")
        return []
    except ValueError:
        print("  ⚠️  XRP Ledger node returned an unexpected response.")
        return []

    result = data.get("result", {})
    if result.get("status") != "success":
        error_message = result.get("error_message") or result.get("error") or "unknown error"
        print(f"  ⚠️  XRP Ledger error: {error_message}")
        return []

    return result.get("transactions", [])


def xrp_moved_money_recently(transactions, lookback_hours):
    """
    PLAIN ENGLISH: Checks whether any validated XRP transaction
    touching this address happened within the lookback window.
    Returns (tx_entry, tx_time) or (None, None).
    """
    cutoff_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    for tx_entry in transactions:
        if not tx_entry.get("validated", False):
            continue

        tx = tx_entry.get("tx", {})
        ripple_timestamp = tx.get("date")
        if ripple_timestamp is None:
            continue

        tx_time = datetime.fromtimestamp(
            ripple_timestamp + RIPPLE_EPOCH_OFFSET_SECONDS, tz=timezone.utc
        )
        if tx_time >= cutoff_time:
            return tx_entry, tx_time

    return None, None


def print_xrp_alert(wallet_address, tx_entry, tx_time):
    """
    PLAIN ENGLISH: Prints a big, hard-to-miss warning banner for an
    XRP wallet that has moved money recently.
    """
    tx = tx_entry.get("tx", {})
    meta = tx_entry.get("meta", {})

    # "delivered_amount" is the authoritative figure for how much XRP
    # actually arrived - Amount alone can be misleading for partial
    # payments. Only native XRP (a plain numeric string, in drops) is
    # shown here; issued-currency (token) payments are flagged as such
    # rather than converted, since that needs the token's own decimals.
    delivered = meta.get("delivered_amount", tx.get("Amount"))
    if isinstance(delivered, str):
        amount_label = f"{int(delivered) / 1_000_000:.6f} XRP"
    elif isinstance(delivered, dict):
        amount_label = f"{delivered.get('value')} {delivered.get('currency')} (issued token)"
    else:
        amount_label = "unknown"

    if OUTPUT_STYLE == "simple":
        if tx.get("Account", "").lower() == wallet_address.lower():
            action, counterparty_label = "sent", "to"
        else:
            action, counterparty_label = "received", "from"
        print(f"\n⚠️  This wallet has moved money recently.")
        print(f"  Wallet : {wallet_address}")
        print(f"  What happened: {action} {amount_label} {counterparty_label} another wallet")
        print(f"  When: {_friendly_datetime(tx_time)}")
        print("  (Full technical detail - the transaction reference and a verify link - "
              "is available in Technical View.)")
        return

    print("\n" + "🚨" * 20)
    print("🚨  ALERT: FLAGGED XRP WALLET HAS MOVED FUNDS  🚨")
    print("🚨" * 20)
    print(f"  Wallet Address : {wallet_address}")
    print(f"  Transaction Time (UTC): {tx_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Amount Moved   : {amount_label}")
    print(f"  From           : {tx.get('Account')}")
    print(f"  To             : {tx.get('Destination', '(n/a - not a Payment tx)')}")
    print(f"  Tx Hash        : {tx.get('hash')}")
    print(f"  View on XRPL explorer: https://livenet.xrpl.org/transactions/{tx.get('hash')}")
    print("🚨" * 20 + "\n")


def check_xrp_wallet(wallet_address):
    """
    PLAIN ENGLISH: Runs the full recent-activity check for one XRP
    wallet. Returns True if an alert was raised.
    """
    transactions = get_recent_xrp_transactions(wallet_address)

    if not transactions:
        print("  No transaction history found for this wallet.")
        return False

    recent_tx, tx_time = xrp_moved_money_recently(transactions, LOOKBACK_HOURS)

    if recent_tx:
        print_xrp_alert(wallet_address, recent_tx, tx_time)
        return True
    else:
        print("  ✅ No activity in the lookback window. Nothing to report.")
        return False


# ====================================================================
# SECTION 5: MAIN WATCHLIST LOOP
# ====================================================================

def run_watchlist_check(watchlist_wallets):
    """
    PLAIN ENGLISH: Loops through every wallet on the watchlist,
    detects whether it's Ethereum, Bitcoin, or XRP, checks it with
    the right method, and prints either an alert or a quiet "all
    clear".
    """

    print("=" * 60)
    print(f"Starting wallet check - {len(watchlist_wallets)} wallets on watchlist")
    print(f"Looking back {LOOKBACK_HOURS} hours for activity")
    print("=" * 60)

    alerts_found = 0

    for wallet_address in watchlist_wallets:

        print(f"\nChecking wallet: {wallet_address} ...")

        chain = detect_chain(wallet_address)

        if chain is None:
            print("  ⚠️  Skipping - this doesn't look like a valid Ethereum "
                  "(0x... , 42 chars), Bitcoin (1..., 3..., bc1...), or "
                  "XRP (r..., 25-35 chars) address.")
            continue

        print(f"  Detected chain: {chain.capitalize()}")

        if chain == "ethereum":
            alert_raised = check_ethereum_wallet(wallet_address)
        elif chain == "bitcoin":
            alert_raised = check_bitcoin_wallet(wallet_address)
        else:
            alert_raised = check_xrp_wallet(wallet_address)

        if alert_raised:
            alerts_found += 1

        # Small pause so we don't overwhelm any API's free tier.
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    print("\n" + "=" * 60)
    print("CHECK COMPLETE")
    print(f"Wallets checked : {len(watchlist_wallets)}")
    print(f"Alerts raised   : {alerts_found}")
    print("=" * 60)


# ====================================================================
# SECTION 6: SCRIPT ENTRY POINT
# This is the part that actually runs when you type "python
# wallet_watcher.py" in your terminal (optionally followed by
# wallet addresses to check instead of the built-in list - see
# WATCHLIST_WALLETS above for the exact syntax).
# ====================================================================
if __name__ == "__main__":
    active_watchlist = get_watchlist_from_cli_or_default()

    has_ethereum_wallets = any(is_valid_ethereum_address(w) for w in active_watchlist)

    if has_ethereum_wallets and ETHERSCAN_API_KEY == "":
        print("⚠️  Please add your Etherscan API key before running this script -")
        print("    your watchlist includes Ethereum wallets. See STEP 3 above.")
        print("    (Bitcoin/XRP-only watchlists don't need an API key.)")
    else:
        run_watchlist_check(active_watchlist)