"""
monitor.py

Consolidated, continuously-running network monitoring and automated
response system. Combines everything the separate monitor.*.py
scripts did into one script that runs forever (until stopped with
Ctrl+C), polling repeatedly rather than being invoked once per check.

What it does, every poll cycle
---------------------------------
1. Device availability
   -----------------------
   Checks every in-scope device (ping for static-IP devices, TCP to
   localhost:<Access Port> for DHCP devices) via check.network.py.
   For each device that's unavailable:
     - Sends the "Device Unavailable Notification" email (Task 2
       Email Templates.docx).
     - Files a Helpdesk ticket ("Device Unavailable" issue type).
   Only fires once per outage (see "State tracking" below), not every
   single poll cycle for a device that's still down.

2. DNS setting monitoring, alerting, and auto-correction
   ---------------------------------------------------------
   Checks every DNS-consumer device's (PC1-4, SVR1-2, API, DB)
   current DNS configuration -- SSH for static-IP devices, the GNS3
   Telnet console for DHCP devices -- and compares it against the
   expected internal DNS servers.

   For a device found ALTERED:
     a. Sends the "DNS Setting Altered Notification" email (Task 2
        Email Templates.docx).
     b. Files a NEW Helpdesk ticket for the issue BEFORE attempting
        any fix.
     c. Corrects the DNS setting (SSH or Telnet, whichever applies)
        and confirms the fix with a live name-resolution test.
     d. If the correction succeeds, updates that same ticket's status
        to "resolved".
   If correction fails, the ticket stays open and is retried on the
   next cycle -- no duplicate ticket gets filed for the same
   still-unresolved issue (tracked in memory for this run).

   DNS servers themselves (DNS1, DNS2) are checked for service health
   (bind9/named active) as part of step 3 below, not for "altered"
   config, since they don't have an upstream DNS server to be altered
   from.

3. Healthy DNS logging
   ----------------------
   For every device confirmed to have correct, unaltered DNS (or, for
   DNS1/DNS2, a running DNS service), appends a log entry -- device
   name, date, and time -- to a log file. This is a running health
   record, so it logs every cycle a device is confirmed healthy, not
   just once.

State tracking (why polling forever doesn't spam alerts)
------------------------------------------------------------
Kept in memory for the life of this process:
    - unavailable_alerted: device names currently alerted as down.
      Cleared when a device comes back up, so a FUTURE outage alerts
      again, but a single ongoing outage doesn't re-alert every cycle.
    - dns_open_tickets: device name -> ticket ID for a DNS issue
      that's been ticketed but not yet confirmed resolved. Prevents
      filing a new ticket every cycle while a correction keeps failing
      or is still being retried.

Foundational pieces re-used (not duplicated)
-----------------------------------------------
    - check.network.py       -> read_devices, get_in_scope_devices,
      is_static_address, check_availability, connect_ssh, run_command,
      get_dns_configuration, get_dns_configuration_via_telnet_confirmed,
      correct_dns_via_telnet, classify_dns, detect_and_check_service
      (via verify.dns.service.py), SSH_HOST, INTERNAL_DNS_SERVERS
    - correct.dns.settings.py -> is_affected_device, correct_dns_ubuntu
    - Helpdesk API details (host, token, schema discovery, ticket
      create/update) are embedded directly below -- small and stable
      enough not to need a separate file, and this keeps monitor.py's
      dependency list to just the two files above.

SMTP and Helpdesk configuration
----------------------------------
Same lab endpoints used throughout this project:

    SMTP:     smtp.d522.wgu.internal:1025 (no auth/TLS by default)
    Helpdesk: http://helpdesk.d522.wgu.internal:5000/api/tickets

Overridable via environment variables:
    SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_USE_TLS
    ALERT_SENDER       "From" address (default: network-monitor@d522.wgu.internal)
    ALERT_RECIPIENTS   comma-separated stakeholder emails (required to actually send)

Usage
-----
    export ALERT_RECIPIENTS="netadmin@d522.wgu.internal"
    python monitor.py network_devices.csv
    python monitor.py network_devices.csv --poll-interval 5
    python monitor.py network_devices.csv --log-file dns_status.log
    python monitor.py network_devices.csv --dry-run   # no emails/tickets/corrections sent, just prints

Stop with Ctrl+C at any time -- it's caught cleanly.

Requires
--------
    pip install paramiko requests
"""

import argparse
import importlib.util
import json
import os
import re
import smtplib
import sys
import time
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path

import requests

# --------------------------------------------------------------------------
# Load check.network.py and correct.dns.settings.py (dot-named -> load by
# path, not `import`). These are the only two files monitor.py depends on;
# everything else (email templates, ticket API, poll loop) lives here.
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent


def _load(module_name: str, filename: str):
    path = _here / filename
    if not path.exists():
        raise ImportError(
            f"Could not find {filename} next to this script (looked in: {_here}). "
            f"Make sure {filename} is in the same folder as monitor.py."
        )
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {filename}.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


correct_dns_settings = _load("correct_dns_settings", "correct.dns.settings.py")
check_network = correct_dns_settings.verify_dns_service.check_network

read_devices = check_network.read_devices
get_in_scope_devices = check_network.get_in_scope_devices
is_static_address = check_network.is_static_address
check_availability = check_network.check_availability
connect_ssh = check_network.connect_ssh
run_command = check_network.run_command
get_dns_configuration = check_network.get_dns_configuration
get_dns_configuration_via_telnet = check_network.get_dns_configuration_via_telnet_confirmed
correct_dns_via_telnet = check_network.correct_dns_via_telnet
classify_dns = check_network.classify_dns
detect_and_check_service = correct_dns_settings.verify_dns_service.detect_and_check_service
SSH_HOST = check_network.SSH_HOST
EXPECTED_DNS_SERVERS = sorted(check_network.INTERNAL_DNS_SERVERS)

is_affected_device = correct_dns_settings.is_affected_device
correct_dns_ubuntu = correct_dns_settings.correct_dns_ubuntu


# --------------------------------------------------------------------------
# Helpdesk API
# --------------------------------------------------------------------------

HELPDESK_HOST = "helpdesk.d522.wgu.internal"
HELPDESK_PORT = 5000
HELPDESK_BASE_URL = f"http://{HELPDESK_HOST}:{HELPDESK_PORT}"
HELPDESK_TOKEN = "vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE"

HEADERS = {
    "Authorization": f"Bearer {HELPDESK_TOKEN}",
    "Content-Type": "application/json",
}

REQUEST_TIMEOUT = 10


def discover_ticket_field_names() -> dict:
    """
    Learn the Helpdesk API's real ticket field names from an existing
    ticket. This API's actual schema (confirmed from real responses) is
    just {title, description, priority, status} plus server-generated
    fields -- no dedicated device_name/issue_type field, so device
    identity and issue type live in the title/description text.
    """
    default_fields = {"title": "title", "description": "description", "priority": "priority", "status": "status", "id": "id"}

    try:
        resp = requests.get(f"{HELPDESK_BASE_URL}/api/tickets", headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        sample = None
        if isinstance(data, list) and data:
            sample = data[0]
        elif isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list) and value:
                    sample = value[0]
                    break

        if isinstance(sample, dict):
            for key in sample:
                lower = key.lower()
                if lower in ("title", "subject", "summary"):
                    default_fields["title"] = key
                elif lower in ("description", "details", "body"):
                    default_fields["description"] = key
                elif lower in ("priority", "severity"):
                    default_fields["priority"] = key
                elif lower in ("status",):
                    default_fields["status"] = key
                elif lower in ("id", "ticket_id", "ticketid", "_id"):
                    default_fields["id"] = key
    except (requests.RequestException, ValueError):
        pass

    return default_fields


def build_ticket_payload(title: str, description: str, priority: str, status: str, field_names: dict) -> dict:
    return {
        field_names["title"]: title,
        field_names["description"]: description,
        field_names["priority"]: priority,
        field_names["status"]: status,
    }


def create_ticket(payload: dict) -> tuple[bool, int, str, int | None]:
    """POST a ticket. Returns (success, status_code, raw_response_text, ticket_id_or_None)."""
    try:
        resp = requests.post(f"{HELPDESK_BASE_URL}/api/tickets", headers=HEADERS, data=json.dumps(payload), timeout=REQUEST_TIMEOUT)
        success = resp.status_code in (200, 201)
        ticket_id = None
        if success:
            try:
                ticket_id = resp.json().get("id")
            except ValueError:
                pass
        return success, resp.status_code, resp.text, ticket_id
    except requests.RequestException as exc:
        return False, 0, str(exc), None


def update_ticket_status(ticket_id: int, new_status: str, field_names: dict) -> tuple[bool, str]:
    url = f"{HELPDESK_BASE_URL}/api/tickets/{ticket_id}"
    body = {field_names["status"]: new_status}
    try:
        resp = requests.patch(url, headers=HEADERS, data=json.dumps(body), timeout=REQUEST_TIMEOUT)
        if resp.status_code in (200, 201, 204):
            return True, resp.text
        if resp.status_code == 405:
            resp = requests.put(url, headers=HEADERS, data=json.dumps(body), timeout=REQUEST_TIMEOUT)
            if resp.status_code in (200, 201, 204):
                return True, resp.text
        return False, f"HTTP {resp.status_code}: {resp.text}"
    except requests.RequestException as exc:
        return False, str(exc)


# --------------------------------------------------------------------------
# SMTP / email templates
# --------------------------------------------------------------------------

DEFAULT_SMTP_SERVER = "smtp.d522.wgu.internal"
DEFAULT_SMTP_PORT = 1025
DEFAULT_SENDER = "network-monitor@d522.wgu.internal"

DEVICE_UNAVAILABLE_SUBJECT = "Network Device Unavailable: {name} ({address})"
DEVICE_UNAVAILABLE_BODY = (
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

DNS_ALTERED_SUBJECT = "DNS Configuration Alert: {name} ({address})"
DNS_ALTERED_BODY = (
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


def get_recipients() -> list[str]:
    return [r.strip() for r in os.environ.get("ALERT_RECIPIENTS", "").split(",") if r.strip()]


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

def log_healthy_device(log_path: Path, device_name: str) -> None:
    now = datetime.now()
    line = f"{now.strftime('%Y-%m-%d')} | {now.strftime('%H:%M:%S')} | {device_name} | DNS service functioning correctly, not altered\n"
    with log_path.open("a", encoding="utf-8") as f:
        f.write(line)


# --------------------------------------------------------------------------
# Per-device DNS check / correction (SSH or Telnet, whichever applies)
# --------------------------------------------------------------------------

def check_device_dns(device: dict, port_override) -> tuple[bool, list[str], str | None]:
    """Returns (connected, current_dns_ips, error)."""
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")

    if not is_static_address(address):
        try:
            telnet_port = int(device.get("Access Port"))
        except (TypeError, ValueError):
            return False, [], "No valid Access Port in CSV for Telnet console check."
        try:
            dns_info = get_dns_configuration_via_telnet(SSH_HOST, telnet_port, username, password)
            return True, dns_info["effective"], None
        except Exception as exc:  # noqa: BLE001
            return False, [], f"Telnet console check failed: {exc}"

    port = port_override if port_override else 22
    try:
        client = connect_ssh(address, port, username, password)
    except Exception as exc:  # noqa: BLE001
        return False, [], f"SSH connection failed: {exc}"
    try:
        dns_info = get_dns_configuration(client)
        return True, dns_info["effective"], None
    except Exception as exc:  # noqa: BLE001
        return False, [], f"DNS check failed: {exc}"
    finally:
        client.close()


def correct_device_dns(device: dict, port_override) -> dict:
    """Returns the correction result dict (method/before/after/resolved/error)."""
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")

    if not is_static_address(address):
        telnet_port = int(device.get("Access Port"))
        return correct_dns_via_telnet(SSH_HOST, telnet_port, username, password)

    port = port_override if port_override else 22
    client = connect_ssh(address, port, username, password)
    try:
        return correct_dns_ubuntu(client, password)
    finally:
        client.close()


def check_dns_server_healthy(device: dict, port_override) -> tuple[bool, str]:
    """DNS1/DNS2: healthy means the bind9/named service is active."""
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")
    port = port_override if port_override else 22

    try:
        client = connect_ssh(address, port, username, password)
    except Exception as exc:  # noqa: BLE001
        return False, f"SSH connection failed: {exc}"
    try:
        status = detect_and_check_service(client)
        if not status["found"]:
            return False, "DNS service not found on host."
        return status["state"] == "active", f"service state: {status['state']}"
    except Exception as exc:  # noqa: BLE001
        return False, f"Status check failed: {exc}"
    finally:
        client.close()


# --------------------------------------------------------------------------
# One poll cycle
# --------------------------------------------------------------------------

def run_availability_check(devices: list[dict], state: dict, recipients: list[str], field_names: dict, dry_run: bool) -> None:
    results = check_availability(devices)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for r in results:
        name = r["name"]

        if r["up"]:
            state["unavailable_alerted"].discard(name)
            continue

        if name in state["unavailable_alerted"]:
            continue  # already alerted for this ongoing outage

        print(f"[UNAVAILABLE] {name} ({r['address']}) - {r['method']}")

        subject = DEVICE_UNAVAILABLE_SUBJECT.format(name=name, address=r["address"])
        body = DEVICE_UNAVAILABLE_BODY.format(name=name, address=r["address"], timestamp=timestamp)

        if dry_run:
            print(f"  [DRY RUN] Would email: {subject}")
        elif recipients:
            try:
                send_email(subject, body, recipients)
                print(f"  Notification sent to: {', '.join(recipients)}")
            except Exception as exc:  # noqa: BLE001
                print(f"  WARNING: could not send email: {exc}")
        else:
            print("  WARNING: ALERT_RECIPIENTS not set, skipping email.")

        if dry_run:
            print("  [DRY RUN] Would file a 'Device Unavailable' ticket.")
        else:
            title = f"Device Unavailable: {name} ({r['address']})"
            description = f"Device {name} ({r['address']}) did not respond as of {timestamp} ({r['method']})."
            payload = build_ticket_payload(title, description, "high", "open", field_names)
            success, status_code, raw, _ = create_ticket(payload)
            if success:
                print(f"  Ticket filed (HTTP {status_code}).")
            else:
                print(f"  WARNING: ticket creation failed (HTTP {status_code}): {raw}")

        state["unavailable_alerted"].add(name)


def run_dns_check(devices: list[dict], state: dict, recipients: list[str], field_names: dict,
                   port_override, log_path: Path, dry_run: bool) -> None:
    def timestamp_str():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- DNS servers themselves: service health -> healthy log only ---
    for device in devices:
        name = (device.get("Device Name") or "")
        if name.lower() not in ("dns1", "dns2"):
            continue

        healthy, detail = check_dns_server_healthy(device, port_override)
        if healthy:
            log_healthy_device(log_path, name)
            print(f"[DNS OK] {name} - {detail}")
        else:
            print(f"[DNS SERVICE ISSUE] {name} - {detail}")

    # --- Consumer devices: altered-config detection, alert, ticket, fix ---
    consumers = [d for d in devices if is_affected_device(d)]

    for device in consumers:
        name = device.get("Device Name", "")
        address = device.get("Device Address", "")

        connected, current_dns, error = check_device_dns(device, port_override)

        if not connected:
            print(f"[DNS UNREACHABLE] {name} ({address}) - {error}")
            continue

        altered = set(current_dns) != set(EXPECTED_DNS_SERVERS)

        if not altered:
            log_healthy_device(log_path, name)
            print(f"[DNS OK] {name} ({address}) - configured DNS: {', '.join(current_dns) if current_dns else 'none'}")

            # If we had an open ticket tracked for this device (e.g. it
            # was fixed by something other than this script), close it out.
            if name in state["dns_open_tickets"] and not dry_run:
                ticket_id = state["dns_open_tickets"].pop(name)
                update_ticket_status(ticket_id, "resolved", field_names)
                print(f"  (Existing open ticket for {name} marked resolved.)")
            continue

        detected_str = ", ".join(current_dns) if current_dns else "None configured"
        expected_str = ", ".join(EXPECTED_DNS_SERVERS)
        print(f"[DNS ALTERED] {name} ({address}) - detected: {detected_str}")

        ticket_id = state["dns_open_tickets"].get(name)

        if ticket_id is None:
            # New alteration -- alert, then file the ticket BEFORE fixing.
            subject = DNS_ALTERED_SUBJECT.format(name=name, address=address)
            body = DNS_ALTERED_BODY.format(
                name=name, address=address, detected=detected_str,
                expected=expected_str, timestamp=timestamp_str(),
            )

            if dry_run:
                print(f"  [DRY RUN] Would email: {subject}")
            elif recipients:
                try:
                    send_email(subject, body, recipients)
                    print(f"  Notification sent to: {', '.join(recipients)}")
                except Exception as exc:  # noqa: BLE001
                    print(f"  WARNING: could not send email: {exc}")
            else:
                print("  WARNING: ALERT_RECIPIENTS not set, skipping email.")

            if dry_run:
                print("  [DRY RUN] Would file a 'DNS Setting Altered' ticket before correcting.")
            else:
                title = f"DNS Setting Altered: {name} ({address})"
                description = (
                    f"DNS configuration on {name} ({address}) was detected as altered from the "
                    f"expected settings. Detected: {detected_str}. Expected: {expected_str}."
                )
                payload = build_ticket_payload(title, description, "urgent", "open", field_names)
                success, status_code, raw, new_ticket_id = create_ticket(payload)
                if success:
                    print(f"  Ticket filed (HTTP {status_code}, id={new_ticket_id}).")
                    ticket_id = new_ticket_id
                    state["dns_open_tickets"][name] = ticket_id
                else:
                    print(f"  WARNING: ticket creation failed (HTTP {status_code}): {raw}")

        # --- Attempt the correction (every cycle it's still altered) ---
        if dry_run:
            print("  [DRY RUN] Would correct DNS settings now.")
            continue

        try:
            correction = correct_device_dns(device, port_override)
        except Exception as exc:  # noqa: BLE001
            print(f"  Correction failed: {exc}")
            continue

        if correction.get("error"):
            print(f"  Correction failed: {correction['error']}")
            continue

        print(f"  Corrected via {correction['method']}, live resolution confirmed working.")

        if ticket_id is not None:
            success, detail = update_ticket_status(ticket_id, "resolved", field_names)
            if success:
                print(f"  Ticket id={ticket_id} updated to 'resolved'.")
                state["dns_open_tickets"].pop(name, None)
            else:
                print(f"  WARNING: could not update ticket id={ticket_id}: {detail}")


def run_one_cycle(csv_path: str, state: dict, recipients: list[str], field_names: dict,
                   port_override, log_path: Path, dry_run: bool) -> None:
    devices = get_in_scope_devices(read_devices(csv_path))

    print(f"\n=== Poll cycle at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")

    print("\n-- Availability --")
    run_availability_check(devices, state, recipients, field_names, dry_run)

    print("\n-- DNS --")
    run_dns_check(devices, state, recipients, field_names, port_override, log_path, dry_run)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Continuously monitor device availability and DNS configuration.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--poll-interval", type=float, default=3.0, help="Seconds to sleep between poll cycles (default: 3)")
    parser.add_argument("--log-file", default="dns_status.log", help="Path to the healthy-DNS log file (default: dns_status.log)")
    parser.add_argument("--port-override", type=int, default=None, help="Force a single SSH port for all static-IP devices instead of port 22")
    parser.add_argument("--dry-run", action="store_true", help="Print what would happen without sending emails, filing tickets, or correcting DNS")
    args = parser.parse_args()

    if not (1.0 <= args.poll_interval <= 5.0):
        print("WARNING: --poll-interval is recommended to stay between 1 and 5 seconds to avoid pegging the CPU with tight loops when checks complete quickly.")

    recipients = get_recipients()
    if not args.dry_run and not recipients:
        print("WARNING: ALERT_RECIPIENTS is not set -- no notification emails will be sent this run.", file=sys.stderr)

    field_names = {"title": "title", "description": "description", "priority": "priority", "status": "status", "id": "id"}
    if not args.dry_run:
        field_names = discover_ticket_field_names()
        print(f"Discovered ticket field names: {field_names}")

    log_path = Path(args.log_file)

    state = {
        "unavailable_alerted": set(),
        "dns_open_tickets": {},
    }

    print(f"Starting continuous monitoring (poll interval: {args.poll_interval}s). Press Ctrl+C to stop.")

    try:
        while True:
            try:
                run_one_cycle(args.csv_path, state, recipients, field_names, args.port_override, log_path, args.dry_run)
            except Exception as exc:  # noqa: BLE001
                # Never let one bad cycle kill the whole monitor -- log it
                # and keep going, since this is meant to run forever.
                print(f"ERROR during poll cycle: {exc}", file=sys.stderr)

            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")


if __name__ == "__main__":
    main()