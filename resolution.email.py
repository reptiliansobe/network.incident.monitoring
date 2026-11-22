"""
resolution.email.py

Sends the "Resolution Notification Email" (from Task 1 Email
Templates.docx) to stakeholders, confirming the DNS issue has been
resolved, and listing every device that was ACTUALLY affected by
hostname and IP address.

Which devices are listed
--------------------------
Reads corrected_devices.json, the record correct.dns.settings.py
writes at the end of its run listing exactly which devices it found
misconfigured and fixed. This is NOT a live re-check against the CSV
or a blanket "every in-scope device" list -- by the time a resolution
email goes out, everything has already been fixed, so a live check
would just show every device as OK and the email would (wrongly)
report nobody was ever affected. The corrected-devices file is the
actual record of what happened.

If DNS1/DNS2 themselves were restarted this run (a full service
outage, not just a downstream misconfiguration), pass
--dns-devices-file pointing at a similar JSON list to include them
too; there's no restart.dns.service.py equivalent record by default,
since that's a separate incident type from device-level DNS
misconfiguration.

Email template used (verbatim subject/body from Task 1 Email
Templates.docx, "Resolution Notification Email"), with {device_list}
filled in as one "Device Name / IP Address" block per device:

    Subject: RESOLVED: DNS Service Issue and Device Compromise—All Issues Remediated

    Dear Stakeholders,

    This is an automated notification to inform you that the DNS
    service issue and all related device compromises have been
    successfully resolved. The following devices were affected and
    have now been remediated:

    {device_list}

    No further action is required at this time. ...

SMTP configuration
------------------
Same lab SMTP endpoint used by incident.email.py:

    HOST: smtp.d522.wgu.internal
    PORT: 1025

No TLS/auth by default (overridable via SMTP_USE_TLS / SMTP_USERNAME /
SMTP_PASSWORD env vars, same as incident.email.py).

    ALERT_RECIPIENTS  comma-separated stakeholder emails (required)

Usage
-----
    export ALERT_RECIPIENTS="stakeholders@d522.wgu.internal"
    python correct.dns.settings.py network_devices.csv   # writes corrected_devices.json
    python resolution.email.py
    python resolution.email.py --dry-run
    python resolution.email.py --devices-file corrected_devices.json
"""

import argparse
import json
import os
import smtplib
import sys
from email.mime.text import MIMEText
from pathlib import Path


SUBJECT = "RESOLVED: DNS Service Issue and Device Compromise\u2014All Issues Remediated"

DEVICE_BLOCK_TEMPLATE = "Device Name: {name}\nIP Address: {address}\n"

BODY_TEMPLATE = (
    "Dear Stakeholders,\n\n"
    "This is an automated notification to inform you that the DNS service "
    "issue and all related device compromises have been successfully "
    "resolved. The following devices were affected and have now been "
    "remediated:\n\n"
    "{device_list}\n"
    "No further action is required at this time. If you have any questions "
    "or concerns, please contact the IT support team.\n\n"
    "Thank you for your attention.\n\n"
    "Best regards,\n"
    "Network Monitoring System\n"
)

DEFAULT_SMTP_SERVER = "smtp.d522.wgu.internal"
DEFAULT_SMTP_PORT = 1025
DEFAULT_SENDER = "network-monitor@d522.wgu.internal"


# --------------------------------------------------------------------------
# Affected device list
# --------------------------------------------------------------------------

def load_device_list(json_path: str) -> list[dict]:
    """Load a [{"name": ..., "address": ...}, ...] list from a JSON file."""
    path = Path(json_path)
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    return [{"name": d.get("name", ""), "address": d.get("address", "")} for d in raw]


def get_affected_devices(devices_file: str, dns_devices_file: str | None) -> list[dict]:
    """
    Build the actually-affected device list from correct.dns.settings.py's
    corrected-devices record, optionally combined with a DNS-server record
    (--dns-devices-file) if DNS1/DNS2 themselves were also part of this
    incident (a service outage, not just downstream misconfiguration).
    """
    devices = load_device_list(devices_file)

    if not devices:
        print(
            f"WARNING: no devices found in {devices_file!r}. Make sure "
            "correct.dns.settings.py has been run and actually corrected "
            "something, or pass --devices-file pointing at the right file.",
            file=sys.stderr,
        )

    if dns_devices_file:
        devices = load_device_list(dns_devices_file) + devices

    # De-duplicate while preserving order, in case a device shows up in
    # both files.
    seen = set()
    unique = []
    for d in devices:
        key = d["name"].lower()
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


# --------------------------------------------------------------------------
# Email construction
# --------------------------------------------------------------------------

def build_email_body(devices: list[dict]) -> str:
    blocks = "\n".join(
        DEVICE_BLOCK_TEMPLATE.format(name=d["name"], address=d["address"])
        for d in devices
    )
    return BODY_TEMPLATE.format(device_list=blocks)


def send_email(body: str, recipients: list[str]) -> None:
    smtp_server = os.environ.get("SMTP_SERVER", DEFAULT_SMTP_SERVER)
    smtp_port = int(os.environ.get("SMTP_PORT", str(DEFAULT_SMTP_PORT)))
    smtp_username = os.environ.get("SMTP_USERNAME")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    use_tls = os.environ.get("SMTP_USE_TLS", "").lower() in ("1", "true", "yes")
    sender = os.environ.get("ALERT_SENDER", DEFAULT_SENDER)

    msg = MIMEText(body, "plain")
    msg["Subject"] = SUBJECT
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
    parser = argparse.ArgumentParser(description="Send the Resolution Notification Email listing the devices actually affected and corrected.")
    parser.add_argument("--devices-file", default="corrected_devices.json", help="JSON list of corrected devices, written by correct.dns.settings.py (default: corrected_devices.json)")
    parser.add_argument("--dns-devices-file", default=None, help="Optional JSON list of DNS servers to also include, if DNS1/DNS2 were part of this incident")
    parser.add_argument("--dry-run", action="store_true", help="Print the email instead of sending it")
    args = parser.parse_args()

    devices = get_affected_devices(args.devices_file, args.dns_devices_file)

    if not devices:
        print("No affected devices found. No resolution email sent.")
        return

    body = build_email_body(devices)

    print(f"Subject: {SUBJECT}\n")
    print(body)

    if args.dry_run:
        print("[Dry run] Email not sent.")
        return

    recipients_env = os.environ.get("ALERT_RECIPIENTS", "")
    recipients = [r.strip() for r in recipients_env.split(",") if r.strip()]
    if not recipients:
        print(
            "ERROR: No recipients configured. Set ALERT_RECIPIENTS to a "
            "comma-separated list of stakeholder emails.",
            file=sys.stderr,
        )
        sys.exit(1)

    send_email(body, recipients)
    print(f"Resolution email sent to: {', '.join(recipients)}")


if __name__ == "__main__":
    main()