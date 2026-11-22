"""
monitor.resolve.dns.settings.py

Ongoing monitoring - remediation step: for every device with an
altered DNS setting, automatically correct the configuration back to
the expected DNS servers, then update the corresponding Helpdesk
ticket to show the issue has been resolved.

Re-uses the existing pieces rather than duplicating them:
    - monitor.check.dns.settings.py -> find_altered_devices() (same
      detection logic that already sent the "DNS Setting Altered"
      emails -- SSH for static-IP devices, Telnet console for DHCP
      devices -- so this script only acts on devices that logic
      agrees are actually altered)
    - correct.dns.settings.py       -> read_devices(), connect_ssh(),
      correct_dns_ubuntu() (SSH correction), correct_dns_via_telnet()
      (Telnet console correction for PC1-4), is_static_address() to
      pick the right one per device -- all the same routines already
      proven in correct.dns.settings.py, including the live resolution
      test that proves the fix actually works, not just that the
      config file looks right
    - create.tickets.py             -> Helpdesk API host/auth and the
      ticket-field schema discovery, so the API handling lives in one
      place

Which devices are corrected
------------------------------
Whichever devices find_altered_devices() reports as altered this run
-- could be any subset of PC1-4, SVR1, SVR2, API, DB. Static-IP
devices are corrected over SSH; DHCP devices (PC1-4) are corrected
over the GNS3 Telnet console on their own Access Port, since they
have no SSH target.

Ticket handling
-----------------
For each corrected device, this script:
    1. Searches existing tickets (GET /api/tickets) for an open ticket
       matching that device -- matched by device name AND issue type
       appearing in the ticket's title, since the API's schema has no
       dedicated device_name/issue_type field (device identity lives
       in the title text). Recognizes "DNS Misconfiguration" (what
       create.tickets.py actually titles these), plus a couple of
       other DNS-issue phrasings for compatibility.
    2. If found, updates its status to "resolved" (tries PATCH first,
       falls back to PUT if the API doesn't support PATCH).
    3. If no matching open ticket exists yet, files a new ticket
       that's already marked resolved, so there's still a record of
       the detect-and-fix event in the helpdesk history even if no
       prior alert ticket was created for it.

Usage
-----
    python monitor.resolve.dns.settings.py network_devices.csv
    python monitor.resolve.dns.settings.py network_devices.csv --port-override 22
    python monitor.resolve.dns.settings.py network_devices.csv --dry-run

Requires
--------
    pip install paramiko requests
"""

import argparse
import importlib.util
import json
from pathlib import Path

import requests

# --------------------------------------------------------------------------
# Load monitor.check.dns.settings.py, correct.dns.settings.py, and
# create.tickets.py (all dot-named -> load by path, not `import`)
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent


def _load(module_name: str, filename: str):
    path = _here / filename
    if not path.exists():
        raise ImportError(
            f"Could not find {filename} next to this script (looked in: {_here}). "
            f"Make sure {filename} is in the same folder as monitor.resolve.dns.settings.py."
        )
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {filename}.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


monitor_check_dns = _load("monitor_check_dns_settings", "monitor.check.dns.settings.py")
correct_dns_settings = _load("correct_dns_settings", "correct.dns.settings.py")
create_tickets = _load("create_tickets", "create.tickets.py")

find_altered_devices = monitor_check_dns.find_altered_devices
read_devices = correct_dns_settings.read_devices
connect_ssh = correct_dns_settings.connect_ssh
correct_dns_ubuntu = correct_dns_settings.correct_dns_ubuntu
correct_dns_via_telnet = correct_dns_settings.correct_dns_via_telnet
is_static_address = correct_dns_settings.is_static_address
SSH_HOST = correct_dns_settings.SSH_HOST

HELPDESK_BASE_URL = create_tickets.HELPDESK_BASE_URL
HEADERS = create_tickets.HEADERS
REQUEST_TIMEOUT = create_tickets.REQUEST_TIMEOUT
discover_ticket_field_names = create_tickets.discover_ticket_field_names
build_payload = create_tickets.build_payload
create_ticket = create_tickets.create_ticket

RESOLVED_ISSUE_TYPES = {
    "dns misconfiguration",  # what create.tickets.py actually titles these
    "dns setting altered",
    "dns service failure",
    "dns configuration alert",
}


# --------------------------------------------------------------------------
# Ticket lookup / update
# --------------------------------------------------------------------------

def discover_id_field(sample: dict) -> str:
    for key in sample:
        if key.lower() in ("id", "ticket_id", "ticketid", "_id"):
            return key
    return "id"  # reasonable fallback


def get_all_tickets() -> list[dict]:
    resp = requests.get(f"{HELPDESK_BASE_URL}/api/tickets", headers=HEADERS, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                return value
    return []


def find_open_ticket(tickets: list[dict], field_names: dict, device_name: str) -> dict | None:
    """
    Find an open ticket for this device. The API's schema has no
    dedicated device_name/issue_type fields (confirmed from real POST
    responses) -- device identity and issue type are embedded in the
    title text instead (e.g. "DNS Setting Altered: SVR1 (192.168.20.210)"),
    so matching has to search the title rather than a structured field.
    """
    title_key = field_names["title"]
    status_key = field_names["status"]
    name_lower = device_name.strip().lower()

    matches = [
        t for t in tickets
        if name_lower in str(t.get(title_key, "")).lower()
        and any(issue_type in str(t.get(title_key, "")).lower() for issue_type in RESOLVED_ISSUE_TYPES)
        and str(t.get(status_key, "")).strip().lower() not in ("resolved", "closed")
    ]
    return matches[0] if matches else None


def update_ticket_status(ticket: dict, field_names: dict, id_field: str, new_status: str) -> tuple[bool, str]:
    ticket_id = ticket.get(id_field)
    if ticket_id is None:
        return False, f"Could not determine ticket ID field (looked for '{id_field}')."

    url = f"{HELPDESK_BASE_URL}/api/tickets/{ticket_id}"
    patch_body = {field_names["status"]: new_status}

    try:
        resp = requests.patch(url, headers=HEADERS, data=json.dumps(patch_body), timeout=REQUEST_TIMEOUT)
        if resp.status_code in (200, 201, 204):
            return True, resp.text
        if resp.status_code == 405:  # method not allowed -- try PUT instead
            merged = {**ticket, field_names["status"]: new_status}
            resp = requests.put(url, headers=HEADERS, data=json.dumps(merged), timeout=REQUEST_TIMEOUT)
            if resp.status_code in (200, 201, 204):
                return True, resp.text
        return False, f"HTTP {resp.status_code}: {resp.text}"
    except requests.RequestException as exc:
        return False, str(exc)


def file_resolved_ticket(device_name: str, address: str, field_names: dict) -> tuple[bool, str]:
    """Fallback: no open ticket existed for this device -- file one that's
    already resolved, so the fix is still recorded in the helpdesk."""
    issue = {
        "device_name": device_name,
        "device_ip": address,
        "issue_type": "DNS Setting Altered",
        "description": (
            f"DNS setting on {device_name} ({address}) was detected as altered and has "
            f"been automatically corrected back to the expected DNS servers."
        ),
        "priority": "low",
    }
    payload = build_payload(issue, field_names)
    payload[field_names["status"]] = "resolved"

    print(f"           Request payload: {json.dumps(payload)}")
    success, status_code, raw_response = create_ticket(payload)
    print(f"           Response status: {status_code}")
    print(f"           Response body:   {raw_response}")

    return success, raw_response


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Correct altered DNS settings and update the matching Helpdesk ticket as resolved.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--port-override", type=int, default=None, help="Force a single SSH port for all devices instead of using each device's Access Port from the CSV")
    parser.add_argument("--dry-run", action="store_true", help="Detect and report only -- don't correct DNS or touch tickets")
    args = parser.parse_args()

    altered, unreachable = find_altered_devices(args.csv_path, args.port_override)

    for u in unreachable:
        print(f"[UNREACHABLE] {u['device_name']} ({u['address']}) - {u['error']}")

    if not altered:
        print("\nNo altered DNS settings detected. Nothing to correct.")
        return

    print(f"\n{len(altered)} device(s) need DNS correction: "
          f"{', '.join(d['name'] for d in altered)}\n")

    if args.dry_run:
        for d in altered:
            print(f"[WOULD CORRECT] {d['name']} ({d['address']}) - "
                  f"detected '{d['detected']}', would set to '{d['expected']}'")
        print("\n[Dry run] No changes made, no tickets touched.")
        return

    devices_by_name = {d.get("Device Name", "").lower(): d for d in read_devices(args.csv_path)}
    field_names = discover_ticket_field_names()
    id_field = None

    try:
        tickets = get_all_tickets()
        if tickets:
            id_field = discover_id_field(tickets[0])
    except requests.RequestException as exc:
        print(f"WARNING: could not fetch existing tickets ({exc}); will file new resolved tickets instead.\n")
        tickets = []

    for d in altered:
        name = d["name"]
        address = d["address"]
        device = devices_by_name.get(name.lower())

        if not device:
            print(f"[SKIPPED] {name} ({address}) - device not found in CSV for correction.")
            continue

        username = device.get("Username", "")
        password = device.get("Password", "")

        # --- Correct the DNS setting ---
        if not is_static_address(address):
            # DHCP device (PC1-4): no SSH target, correct over the
            # GNS3 Telnet console on its own Access Port instead.
            try:
                telnet_port = int(device.get("Access Port"))
            except (TypeError, ValueError):
                print(f"[FAILED] {name} ({address}) - No valid Access Port in CSV for Telnet console correction.")
                continue

            try:
                correction = correct_dns_via_telnet(SSH_HOST, telnet_port, username, password)
            except Exception as exc:  # noqa: BLE001
                print(f"[FAILED] {name} ({address}) - Telnet console correction failed: {exc}")
                continue
        else:
            port = args.port_override if args.port_override else 22

            try:
                client = connect_ssh(address, port, username, password)
            except Exception as exc:  # noqa: BLE001
                print(f"[FAILED] {name} ({address}) - SSH connection failed: {exc}")
                continue

            try:
                correction = correct_dns_ubuntu(client, password)
            finally:
                client.close()

        if correction["error"]:
            print(f"[FAILED] {name} ({address}) - DNS correction failed: {correction['error']}")
            continue

        print(f"[CORRECTED] {name} ({address}) - DNS set via {correction['method']}, "
              f"live resolution confirmed working")

        # --- Update (or file) the ticket ---
        open_ticket = find_open_ticket(tickets, field_names, name) if tickets and id_field else None

        if open_ticket:
            success, detail = update_ticket_status(open_ticket, field_names, id_field, "resolved")
            if success:
                print(f"           Ticket for {name} updated to 'resolved'.")
            else:
                print(f"           WARNING: could not update ticket for {name}: {detail}")
        else:
            success, detail = file_resolved_ticket(name, address, field_names)
            if success:
                print(f"           No open ticket found; filed a new resolved ticket for {name}.")
            else:
                print(f"           WARNING: could not file resolved ticket for {name}: {detail}")


if __name__ == "__main__":
    main()