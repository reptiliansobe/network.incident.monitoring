"""
monitor.check.availability.py

Step 2 of the ongoing network monitoring and automated response
system: verify each in-scope device's availability and automatically
send a "Device Unavailable Notification" email (from Task 2 Email
Templates.docx) for every device that doesn't respond.

Re-uses check.network.py entirely for the actual availability logic
rather than re-implementing it, so this always matches whatever
check.network.py currently considers "up":

    - Static-IP devices (SVR1, SVR2, API, DB, DNS1, DNS2) are pinged
      via ICMP at their real Device Address.
    - DHCP devices (PC1-PC4) have no fixed address, so they're
      checked via a TCP connection to localhost:<Access Port> instead
      -- same purpose, adapted to how GNS3 exposes them.
    - SW1-4, SMTP, and ROUTER1 are excluded entirely per
      check.network.py's IN_SCOPE_DEVICES list.

Email template used (verbatim from Task 2 Email Templates.docx,
"Device Unavailable Notification"). One email is sent PER unavailable
device, since the subject line itself is device-specific:

    Subject: Network Device Unavailable: [Device Name] ([IP Address])

    Dear Network Administrator,

    This is an automated notification that the following network
    device is currently unavailable:

    Device Name: [Device Name]
    IP Address: [IP Address]
    Last Checked: [Time stamp]

    Please investigate this issue at your earliest convenience.

    Best regards,
    Network Monitoring System

SMTP configuration
-------------------
Same lab SMTP endpoint used throughout this project:

    HOST: smtp.d522.wgu.internal
    PORT: 1025

No TLS/auth by default. Overridable via environment variables:

    SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_USE_TLS
    ALERT_SENDER       "From" address (default: network-monitor@d522.wgu.internal)
    ALERT_RECIPIENTS   comma-separated stakeholder emails (required to actually send)

Usage
-----
    export ALERT_RECIPIENTS="netadmin@d522.wgu.internal"
    python monitor.check.availability.py network_devices.csv
    python monitor.check.availability.py network_devices.csv --dry-run
"""

import argparse
import importlib.util
import os
import smtplib
import sys
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

# --------------------------------------------------------------------------
# Load check.network.py (dot in filename -> load by path, not `import`)
# Re-uses read_devices, get_in_scope_devices, and check_availability, so
# "unavailable" always means exactly what check.network.py says it means.
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent
_check_network_path = _here / "check.network.py"

_spec = importlib.util.spec_from_file_location("check_network", _check_network_path)
if _spec is None or _spec.loader is None:
    raise ImportError(
        f"Could not find check.network.py next to this script (looked in: {_here}). "
        "Make sure check.network.py is in the same folder as monitor.check.availability.py."
    )
check_network = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_network)

read_devices = check_network.read_devices
get_in_scope_devices = check_network.get_in_scope_devices
check_availability = check_network.check_availability

SUBJECT_TEMPLATE = "Network Device Unavailable: {name} ({address})"

BODY_TEMPLATE = (
    "Dear Network Administrator,\n\n"
    "This is an automated notification that the following network device "
    "is currently unavailable:\n\n"
    "Device Name: {name}\n"
    "IP Address: {address}\n"
    "Last Checked: {timestamp}\n\n"
    "Please investigate this issue at your earliest convenience.\n\n"
    "Best regards,\n"
    "Network Monitoring System\n"
)

DEFAULT_SMTP_SERVER = "smtp.d522.wgu.internal"
DEFAULT_SMTP_PORT = 1025
DEFAULT_SENDER = "network-monitor@d522.wgu.internal"


# --------------------------------------------------------------------------
# Availability check (thin wrapper around check.network.py's result shape)
# --------------------------------------------------------------------------

def get_unavailable_devices(csv_path: str) -> list[dict]:
    """
    Run check.network.py's availability check on all in-scope devices and
    return only the ones that are down, in the shape the email template
    needs (name / address / timestamp). Exposed as a function so other
    scripts (e.g. monitor.create.tickets.py) can reuse it directly.
    """
    devices = get_in_scope_devices(read_devices(csv_path))
    results = check_availability(devices)
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return [
        {"name": r["name"], "address": r["address"], "method": r["method"], "timestamp": checked_at}
        for r in results
        if not r["up"]
    ]


# --------------------------------------------------------------------------
# Email
# --------------------------------------------------------------------------

def build_email(device: dict) -> tuple[str, str]:
    subject = SUBJECT_TEMPLATE.format(name=device["name"], address=device["address"])
    body = BODY_TEMPLATE.format(name=device["name"], address=device["address"], timestamp=device["timestamp"])
    return subject, body


def send_email(subject: str, body: str, recipients: list[str]) -> None:
    smtp_server = os.environ.get("SMTP_SERVER", DEFAULT_SMTP_SERVER)
    smtp_port = int(os.environ.get("SMTP_PORT", str(DEFAULT_SMTP_PORT)))
    smtp_username = os.environ.get("SMTP_USERNAME")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    use_tls = os.environ.get("SMTP_USE_TLS", "").lower() in ("1", "true", "yes")
    sender = os.environ.get("ALERT_SENDER", DEFAULT_SENDER)

    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)

    with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
        server.ehlo()
        if use_tls:
            server.starttls()
            server.ehlo()
        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)
        server.sendmail(sender, recipients, msg.as_string())


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Check device availability and email a notification for each device that's down.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--dry-run", action="store_true", help="Print emails instead of sending them")
    args = parser.parse_args()

    unavailable = get_unavailable_devices(args.csv_path)

    if not unavailable:
        print("All in-scope devices are available. No notifications sent.")
        return

    print(f"{len(unavailable)} device(s) unavailable:\n")

    recipients = []
    if not args.dry_run:
        recipients_env = os.environ.get("ALERT_RECIPIENTS", "")
        recipients = [r.strip() for r in recipients_env.split(",") if r.strip()]
        if not recipients:
            print(
                "ERROR: No recipients configured. Set ALERT_RECIPIENTS to a "
                "comma-separated list of admin emails.",
                file=sys.stderr,
            )
            sys.exit(1)

    for device in unavailable:
        subject, body = build_email(device)
        print(f"Subject: {subject}")
        print(body)

        if args.dry_run:
            print("[Dry run] Email not sent.\n")
            continue

        send_email(subject, body, recipients)
        print(f"Notification sent to: {', '.join(recipients)}\n")

    return unavailable


if __name__ == "__main__":
    main()