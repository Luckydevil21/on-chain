"""
====================================================================
 EMAIL - sends password-reset emails via SMTP (any provider)
====================================================================

WHAT THIS IS: a thin wrapper around Python's built-in smtplib, so
"forgot password" emails can go out through whatever SMTP provider
you already have - Gmail (with an app password), SendGrid, Mailgun,
Amazon SES, Resend, Postmark, a self-hosted mail server, anything
that speaks standard SMTP. No extra library, no vendor lock-in.

====================================================================
 SETUP - environment variables
====================================================================
    SMTP_HOST=smtp.your-provider.com
    SMTP_PORT=587
    SMTP_USERNAME=your-smtp-username
    SMTP_PASSWORD=your-smtp-password-or-app-password
    SMTP_FROM_ADDRESS=noreply@yourdomain.com
    TOOLKIT_BASE_URL=https://your-app.onrender.com   (used to build the reset link)

If these aren't set, password-reset emails simply won't send - the
forgot-password endpoint still responds normally (so it doesn't leak
whether an account exists), but nothing arrives in anyone's inbox.
Check the server logs for a warning if this happens to you.

A quick, free option for testing: a Gmail account with an "app
password" (Google Account -> Security -> 2-Step Verification -> App
passwords) works fine as SMTP_HOST=smtp.gmail.com, SMTP_PORT=587.
For anything beyond testing, a real transactional email provider
(SendGrid, Mailgun, Resend, etc.) is more reliable and won't get
rate-limited or flagged the way a personal Gmail account can be.
====================================================================
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM_ADDRESS = os.environ.get("SMTP_FROM_ADDRESS", SMTP_USERNAME)
TOOLKIT_BASE_URL = os.environ.get("TOOLKIT_BASE_URL", "").rstrip("/")

_smtp_configured = bool(SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD)
if not _smtp_configured:
    print("=" * 70)
    print("⚠️  SMTP is not configured (SMTP_HOST/USERNAME/PASSWORD not all")
    print("    set) - 'forgot password' requests will be accepted but no")
    print("    email will actually be sent. See email_sender.py for setup.")
    print("=" * 70)


def send_email(to_address, subject, body_text):
    """
    PLAIN ENGLISH: Sends a plain-text email via SMTP. Returns True on
    success, False on any failure (never raises - a broken email
    provider shouldn't crash the request that triggered it). Logs the
    specific error to the server console either way, so it's
    diagnosable even though the caller just gets True/False.
    """
    if not _smtp_configured:
        print(f"⚠️  Skipped sending email to {to_address} - SMTP not configured.")
        return False

    message = MIMEMultipart()
    message["From"] = SMTP_FROM_ADDRESS
    message["To"] = to_address
    message["Subject"] = subject
    message.attach(MIMEText(body_text, "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM_ADDRESS, [to_address], message.as_string())
        return True
    except (smtplib.SMTPException, OSError, TimeoutError) as error:
        print(f"⚠️  Failed to send email to {to_address}: {error}")
        return False


def send_password_reset_email(to_address, username, reset_token):
    """Builds and sends the actual password-reset email."""
    base_url = TOOLKIT_BASE_URL or "http://localhost:8000"
    reset_link = f"{base_url}/?reset_token={reset_token}"

    subject = "Password reset - On-Chain Investigations"
    body = (
        f"Hi {username},\n\n"
        f"Someone (hopefully you) requested a password reset for your "
        f"On-Chain Investigations account.\n\n"
        f"To set a new password, open this link:\n{reset_link}\n\n"
        f"This link expires in 1 hour and can only be used once. If you "
        f"didn't request this, you can safely ignore this email - your "
        f"password hasn't been changed.\n"
    )
    return send_email(to_address, subject, body)
