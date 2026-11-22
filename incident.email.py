"""
send_incident_alert.py

Sends the "Incident Alert Email" (from Task 1 Email Templates.docx) to
stakeholders, listing every device that has been identified as
compromised by hostname, IP address, and affected service.

Where the device list comes from
---------------------------------
This script can get its list of compromised devices two ways:

1. AUTOMATIC (recommended): re-uses check.network.py's availability
   and DNS-configuration checks across every in-scope device. A
   device is flagged "compromised" when it's reachable (up) but its
   DNS configuration is misconfigured to a non-internal DNS server --
   a host that's up but pointed at the wrong DNS is a classic
   compromise / tampering indicator, so it gets included in the alert
   even though a plain availability check would call it "healthy".

2. MANUAL: pass a JSON file of devices with --devices-file if you want
   to alert on a specific, pre-determined list instead of running a
   live scan.

Email template used (verbatim subject/body structure from
Task 1 Email Templates.docx, "Incident Alert Email"), extended with a
Service line per device since the alert needs to indicate hostname,
IP address, AND service:

    Subject: URGENT: Device Compromise Detected-Immediate Attention Required

    Dear Stakeholders,

    This is an automated alert to inform you that the following
    device(s) have been identified as compromised during the recent
    network scan:

    Device Name: [Device Name]
    IP Address: [IP Address]
    Service: [Service]
    Last Checked: [Time stamp]

    Immediate investigation and remediation are recommended to
    prevent further impact.
    ...

SMTP configuration
------------------
This environment provides a plain SMTP endpoint for sending mail
(GNS3 lab network):

    HOST: smtp.d522.wgu.internal
    PORT: 1025

That's a lightweight lab/dev SMTP service (no TLS, no login required),
so this script defaults to those values and connects without STARTTLS
or authentication. Everything is still overridable via environment
variables in case you point this at a different server later:

    SMTP_SERVER     defaults to smtp.d522.wgu.internal
    SMTP_PORT       defaults to 1025
    SMTP_USERNAME   optional - only used if SMTP_PASSWORD is also set
    SMTP_PASSWORD   optional - only used if SMTP_USERNAME is also set
    SMTP_USE_TLS    optional - set to "1"/"true" to force STARTTLS
    ALERT_SENDER    "From" address (default: network-monitor@d522.wgu.internal)
    ALERT_RECIPIENTS  comma-separated stakeholder emails,
                       e.g. "ops@company.com,security@company.com"

Note: per lab instructions, this script only sends TO the SMTP
endpoint - it does not attempt to configure, manage, or otherwise
connect to the SMTP server itself (e.g. no SSH).

Usage
-----
    # Set who receives the alert (required)
    export ALERT_RECIPIENTS="stakeholders@d522.wgu.internal"

    # Live scan of network_devices.csv, auto-detect compromised devices
    python send_incident_alert.py network_devices.csv

    # Alert on a specific manual list instead
    python send_incident_alert.py --devices-file compromised.json

    # Dry run - print the email instead of sending it
    python send_incident_alert.py network_devices.csv --dry-run
"""

import argparse
import importlib.util
import json
import os
import smtplib
import sys
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

# --------------------------------------------------------------------------
# Load check.network.py
# --------------------------------------------------------------------------
# This module re-uses the ping / DNS logic from the network-scan script.
# That file is named "check.network.py" (dot in the filename), so it can't
# be loaded with a normal "import check.network" statement -- Python would
# read the dot as a package separator and look for a "check" package with
# a "network" submodule, not a single file. Instead, load it directly from
# disk by path, using the file's location relative to this script so it
# works no matter what directory you run this from.

_here = Path(__file__).resolve().parent
_check_network_path = _here / "check.network.py"

_spec = importlib.util.spec_from_file_location("check_network", _check_network_path)
if _spec is None or _spec.loader is None:
    raise ImportError(
        f"Could not find check.network.py next to this script (looked in: {_here}). "
        "Make sure check.network.py is in the same folder as incident.email.py."
    )
check_network = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_network)

read_devices = check_network.read_devices
get_in_scope_devices = check_network.get_in_scope_devices
check_availability = check_network.check_availability
check_dns_configurations = check_network.check_dns_configurations

SUBJECT = "URGENT: Device Compromise Detected\u2014Immediate Attention Required"

DEVICE_BLOCK_TEMPLATE = (
    "Device Name: {name}\n"
    "IP Address: {address}\n"
    "Service: {service}\n"
    "Last Checked: {timestamp}\n"
)

BODY_TEMPLATE = (
    "Dear Stakeholders,\n\n"
    "This is an automated alert to inform you that the following device(s) "
    "have been identified as compromised during the recent network scan:\n\n"
    "{device_blocks}\n"
    "Immediate investigation and remediation are recommended to prevent "
    "further impact.\n\n"
    "If you have any questions or require additional information, please "
    "contact the IT support team.\n\n"
    "Best regards,\n"
    "Network Monitoring System\n"
)


# --------------------------------------------------------------------------
# Finding compromised devices
# --------------------------------------------------------------------------

def find_compromised_devices(csv_path: str, port_override=None) -> list[dict]:
    """
    Run a live availability + DNS-configuration check against every
    in-scope device and return the ones that look compromised: reachable
    on the network but pointed at a non-internal (misconfigured) DNS
    server -- up, but not configured the way it should be.
    """
    devices = get_in_scope_devices(read_devices(csv_path))
    compromised = []
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    availability_results = check_availability(devices)
    down_names = {r["name"] for r in availability_results if not r["up"]}

    # Only check DNS configuration on devices that are actually up --
    # a device that's simply down is an outage, not this alert's target.
    reachable_devices = [d for d in devices if d.get("Device Name", "") not in down_names]
    dns_results = check_dns_configurations(reachable_devices, port_override)

    for r in dns_results:
        if r["connected"] and r.get("status") == "MISCONFIGURED":
            compromised.append(
                {
                    "name": r["name"],
                    "address": r["address"],
                    "service": "DNS",
                    "timestamp": checked_at,
                    "detail": r["detail"],
                }
            )

    return compromised


def load_manual_devices(devices_file: str) -> list[dict]:
    """Load a manually curated list of compromised devices from JSON.

    Expected format:
    [
        {"name": "DNS1", "address": "10.10.10.10", "service": "DNS"},
        {"name": "SMTP", "address": "10.10.10.100", "service": "SMTP"}
    ]
    "timestamp" is optional; if omitted, the current time is used.
    """
    path = Path(devices_file)
    if not path.exists():
        raise FileNotFoundError(f"Could not find devices file: {devices_file}")

    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    devices = []
    for item in raw:
        devices.append(
            {
                "name": item.get("name", "UNKNOWN"),
                "address": item.get("address", "UNKNOWN"),
                "service": item.get("service", "UNKNOWN"),
                "timestamp": item.get("timestamp", now),
            }
        )
    return devices


# --------------------------------------------------------------------------
# Email construction
# --------------------------------------------------------------------------

def build_email_body(devices: list[dict]) -> str:
    blocks = "\n".join(
        DEVICE_BLOCK_TEMPLATE.format(
            name=d["name"],
            address=d["address"],
            service=d["service"],
            timestamp=d["timestamp"],
        )
        for d in devices
    )
    return BODY_TEMPLATE.format(device_blocks=blocks)


DEFAULT_SMTP_SERVER = "smtp.d522.wgu.internal"
DEFAULT_SMTP_PORT = 1025
DEFAULT_SENDER = "network-monitor@d522.wgu.internal"


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
    parser = argparse.ArgumentParser(description="Send the Incident Alert Email for compromised devices.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Network devices CSV to scan (ignored if --devices-file is given)")
    parser.add_argument("--devices-file", help="JSON file with a manual list of compromised devices, instead of running a live scan")
    parser.add_argument("--port-override", type=int, default=None, help="Force a single SSH port for all devices instead of using each device's Access Port from the CSV")
    parser.add_argument("--dry-run", action="store_true", help="Print the email instead of sending it")
    args = parser.parse_args()

    if args.devices_file:
        compromised = load_manual_devices(args.devices_file)
    else:
        compromised = find_compromised_devices(args.csv_path, args.port_override)

    if not compromised:
        print("No compromised devices detected. No alert sent.")
        return

    body = build_email_body(compromised)

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
    print(f"Alert sent to: {', '.join(recipients)}")


if __name__ == "__main__":
    main()