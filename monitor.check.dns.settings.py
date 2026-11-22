"""
monitor.check.dns.settings.py

Ongoing monitoring: connect to each affected device -- over SSH for
static-IP devices, over the GNS3 Telnet console for DHCP devices --
read its current DNS resolver configuration, and compare it against
the expected DNS servers (DNS1 10.10.10.10, DNS2 10.10.10.20). When a
device's DNS setting has been altered from what's expected, send the
"DNS Setting Altered Notification" email (from Task 2 Email
Templates.docx) to stakeholders.

Which devices are checked
---------------------------
Re-uses correct.dns.settings.py's is_affected_device() filter, so the
same device set is checked here as gets corrected: PC1-4, SVR1-2,
API, DB. SMTP, ROUTER1, and switches are never in scope (excluded by
check.network.py itself); DNS1/DNS2 are the DNS servers themselves,
not consumers of DNS, so they're excluded too.

How each device is reached
-----------------------------
    SVR1, SVR2, API, DB   -- SSH to the device's own IP, port 22
    PC1, PC2, PC3, PC4    -- Telnet to localhost:<Access Port> (the
                             GNS3 console), since they're DHCP devices
                             with no SSH target. Uses the same
                             resolvectl-status-with-resolv.conf-fallback
                             logic already proven in check.network.py
                             and correct.dns.settings.py.

Email template used (verbatim from Task 2 Email Templates.docx,
"DNS Setting Altered Notification"). One email is sent PER altered
device, since the subject and detected/expected values are
device-specific:

    Subject: DNS Configuration Alert: [Device Name] ([IP Address])

    Dear Network Administrator,

    This is an automated alert that the DNS configuration for the
    following device has been altered from the expected settings:

    Device Name: [Device Name]
    IP Address: [IP Address]
    Detected DNS Setting: [Current DNS Setting]
    Expected DNS Setting: [Expected DNS Setting]
    Time Detected: [Time stamp]

    The system will attempt to automatically correct this
    configuration.

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
    python monitor.check.dns.settings.py network_devices.csv
    python monitor.check.dns.settings.py network_devices.csv --dry-run
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
# Load correct.dns.settings.py (re-uses read_devices, get_in_scope_devices,
# is_affected_device, connect_ssh, run_command -- all chained through to
# check.network.py, so this script always connects and evaluates DNS the
# same way check.network.py does).
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent


def _load(module_name: str, filename: str):
    path = _here / filename
    if not path.exists():
        raise ImportError(
            f"Could not find {filename} next to this script (looked in: {_here}). "
            f"Make sure {filename} is in the same folder as monitor.check.dns.settings.py."
        )
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {filename}.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


correct_dns_settings = _load("correct_dns_settings", "correct.dns.settings.py")

read_devices = correct_dns_settings.read_devices
get_in_scope_devices = correct_dns_settings.get_in_scope_devices
is_affected_device = correct_dns_settings.is_affected_device
is_static_address = correct_dns_settings.is_static_address
connect_ssh = correct_dns_settings.connect_ssh
run_command = correct_dns_settings.run_command
get_dns_configuration = correct_dns_settings.verify_dns_service.check_network.get_dns_configuration
get_dns_configuration_via_telnet = correct_dns_settings.verify_dns_service.check_network.get_dns_configuration_via_telnet_confirmed
classify_dns = correct_dns_settings.verify_dns_service.check_network.classify_dns
SSH_HOST = correct_dns_settings.SSH_HOST

EXPECTED_DNS_SERVERS = ["10.10.10.10", "10.10.10.20"]

SUBJECT_TEMPLATE = "DNS Configuration Alert: {name} ({address})"

BODY_TEMPLATE = (
    "Dear Network Administrator,\n\n"
    "This is an automated alert that the DNS configuration for the "
    "following device has been altered from the expected settings:\n\n"
    "Device Name: {name}\n"
    "IP Address: {address}\n"
    "Detected DNS Setting: {detected}\n"
    "Expected DNS Setting: {expected}\n"
    "Time Detected: {timestamp}\n\n"
    "The system will attempt to automatically correct this configuration.\n\n"
    "Best regards,\n"
    "Network Monitoring System\n"
)

DEFAULT_SMTP_SERVER = "smtp.d522.wgu.internal"
DEFAULT_SMTP_PORT = 1025
DEFAULT_SENDER = "network-monitor@d522.wgu.internal"


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------

def check_dns_device(device: dict, port_override) -> dict:
    name = device.get("Device Name", "")
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")

    result = {
        "device_name": name,
        "address": address,
        "connected": False,
        "altered": False,
        "detected": None,
        "error": None,
        "raw_output": None,
        "stub_detected": None,
    }

    if not is_static_address(address):
        # DHCP device (PC1-4): no SSH target, check over the GNS3
        # Telnet console on its own Access Port instead.
        try:
            telnet_port = int(device.get("Access Port"))
        except (TypeError, ValueError):
            result["error"] = "No valid Access Port in CSV for Telnet console check."
            return result

        try:
            dns_info = get_dns_configuration_via_telnet(SSH_HOST, telnet_port, username, password)
            result["connected"] = True
            current_dns = dns_info["effective"]
            result["detected"] = current_dns
            result["altered"] = set(current_dns) != set(EXPECTED_DNS_SERVERS)
            result["raw_output"] = dns_info.get("raw_output")
            result["stub_detected"] = dns_info.get("stub_detected")
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"Telnet console check failed: {exc}"

        return result

    port = port_override if port_override else 22

    try:
        client = connect_ssh(address, port, username, password)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"SSH connection failed: {exc}"
        return result

    try:
        result["connected"] = True
        dns_info = get_dns_configuration(client)
        current_dns = dns_info["effective"]
        result["detected"] = current_dns
        result["altered"] = set(current_dns) != set(EXPECTED_DNS_SERVERS)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"DNS check failed: {exc}"
    finally:
        client.close()

    return result


def find_altered_devices(csv_path: str, port_override=None) -> tuple[list[dict], list[dict]]:
    devices = get_in_scope_devices(read_devices(csv_path))
    affected = [d for d in devices if is_affected_device(d)]

    altered = []
    unreachable = []
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for device in affected:
        result = check_dns_device(device, port_override)

        if not result["connected"]:
            unreachable.append({"device_name": result["device_name"], "address": result["address"], "error": result["error"]})
            continue

        if result["altered"]:
            detected = ", ".join(result["detected"]) if result["detected"] else "None configured"
            altered.append(
                {
                    "name": result["device_name"],
                    "address": result["address"],
                    "detected": detected,
                    "expected": ", ".join(EXPECTED_DNS_SERVERS),
                    "timestamp": checked_at,
                    "raw_output": result.get("raw_output"),
                    "stub_detected": result.get("stub_detected"),
                }
            )

    return altered, unreachable


# --------------------------------------------------------------------------
# Email
# --------------------------------------------------------------------------

def build_email(device: dict) -> tuple[str, str]:
    subject = SUBJECT_TEMPLATE.format(name=device["name"], address=device["address"])
    body = BODY_TEMPLATE.format(**device)
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
    parser = argparse.ArgumentParser(description="Detect altered DNS settings and email a notification for each affected device.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--port-override", type=int, default=None, help="Force a single SSH port for all devices instead of using each device's Access Port from the CSV")
    parser.add_argument("--dry-run", action="store_true", help="Print emails instead of sending them")
    args = parser.parse_args()

    altered, unreachable = find_altered_devices(args.csv_path, args.port_override)

    for u in unreachable:
        print(f"[UNREACHABLE] {u['device_name']} ({u['address']}) - {u['error']}")

    if not altered:
        print("\nNo altered DNS settings detected. No notifications sent.")
        return

    print(f"\n{len(altered)} device(s) with altered DNS settings:\n")

    for device in altered:
        if device.get("raw_output"):
            print(f"--- {device['name']} raw console output (for verification) ---")
            for line in device["raw_output"].splitlines():
                print(f"    {line}")
            if device.get("stub_detected"):
                print("    (stub resolver 127.0.0.53 detected in this output)")
            print("    ---------------------------------------------------------\n")

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

    for device in altered:
        subject, body = build_email(device)
        print(f"Subject: {subject}")
        print(body)

        if args.dry_run:
            print("[Dry run] Email not sent.\n")
            continue

        send_email(subject, body, recipients)
        print(f"Notification sent to: {', '.join(recipients)}\n")

    return altered


if __name__ == "__main__":
    main()