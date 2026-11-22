"""
create.tickets.py

Reads network_devices.csv, checks each in-scope device's status
(reusing the availability + DNS configuration logic from
check.network.py), and automatically files a ticket with the Helpdesk
API for every device that has an issue -- indicating both the issue
type and the targeted device.

Which devices are checked
---------------------------
Only the in-scope devices from check.network.py: PC1-4, SVR1-2, API,
DB, DNS1-2. Switches, SMTP, and ROUTER1 are excluded entirely.

Issue types detected
---------------------
    "Device Unreachable"    - device did not respond to its availability check
                               (ICMP ping for static-IP devices, TCP check
                               to localhost:<Access Port> for DHCP devices)
    "DNS Misconfiguration"  - device is reachable, but its configured DNS
                               server(s) point to something other than the
                               internal DNS servers (10.10.10.10 / .20)

Use --all-devices to instead file an informational ticket for every
in-scope device regardless of status (useful for an audit trail).

Helpdesk API
------------
    HOST: helpdesk.d522.wgu.internal
    PORT: 5000
    Auth: Bearer token (see HELPDESK_TOKEN below)

    GET  http://helpdesk.d522.wgu.internal:5000/api/health   (unauthenticated)
    GET  http://helpdesk.d522.wgu.internal:5000/api/tickets
    POST http://helpdesk.d522.wgu.internal:5000/api/tickets

One ticket is filed PER DEVICE (a separate POST request for each one),
not a single combined ticket -- and the full raw JSON response from
the API is printed for every single request, success or failure, as
direct proof of what the server actually returned. After filing,
the script also re-fetches the ticket list and prints the entries
that match the devices just filed, so you can see them confirmed
present in the API's own data, not just trust the POST response.

The exact JSON schema the API expects for ticket creation wasn't
documented beyond the GET example, so this script:
  1. First tries GET /api/tickets to see if any existing tickets are
     returned, and if so, borrows their field names so the payload
     matches what the API already uses.
  2. Falls back to a reasonable default schema (title, description,
     device_name, device_ip, issue_type, priority, status) if no
     existing tickets are found or the GET fails.

If your Helpdesk API rejects the payload, run with --dry-run to see
exactly what would be sent, compare it against the API's actual
requirements (check the Swagger/Flasgger UI's schema for POST
/api/tickets), and adjust build_payload() below to match.

Usage
-----
    python create.tickets.py network_devices.csv
    python create.tickets.py network_devices.csv --dry-run
    python create.tickets.py network_devices.csv --all-devices
"""

import argparse
import importlib.util
import json
from pathlib import Path

import requests

# --------------------------------------------------------------------------
# Load check.network.py (dot in the filename, so it can't be a normal import)
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent
_check_network_path = _here / "check.network.py"

_spec = importlib.util.spec_from_file_location("check_network", _check_network_path)
if _spec is None or _spec.loader is None:
    raise ImportError(
        f"Could not find check.network.py next to this script (looked in: {_here}). "
        "Make sure check.network.py is in the same folder as create.tickets.py."
    )
check_network = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_network)

read_devices = check_network.read_devices
get_in_scope_devices = check_network.get_in_scope_devices
check_availability = check_network.check_availability
check_dns_configurations = check_network.check_dns_configurations


# --------------------------------------------------------------------------
# Helpdesk API config
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


# --------------------------------------------------------------------------
# Issue detection
# --------------------------------------------------------------------------

def find_device_issues(devices: list[dict], port_override=None) -> list[dict]:
    """Availability + DNS-configuration check on every in-scope device."""
    issues = []

    availability_results = check_availability(devices)
    down_names = {r["name"] for r in availability_results if not r["up"]}

    for r in availability_results:
        if not r["up"]:
            issues.append(
                {
                    "device_name": r["name"],
                    "device_ip": r["address"],
                    "issue_type": "Device Unreachable",
                    "description": f"Device {r['name']} ({r['address']}) failed its availability check ({r['method']}).",
                    "priority": "high",
                }
            )

    # Only check DNS configuration on devices that are actually up --
    # an unreachable device will fail SSH too, which is the same issue
    # already captured above, not a separate one.
    reachable_devices = [d for d in devices if d.get("Device Name", "") not in down_names]
    dns_results = check_dns_configurations(reachable_devices, port_override)

    for r in dns_results:
        if r["connected"] and r.get("status") == "MISCONFIGURED":
            issues.append(
                {
                    "device_name": r["name"],
                    "device_ip": r["address"],
                    "issue_type": "DNS Misconfiguration",
                    "description": f"Device {r['name']} ({r['address']}) - {r['detail']}",
                    "priority": "urgent",
                }
            )

    return issues


def build_all_device_entries(devices: list[dict]) -> list[dict]:
    """Build one informational entry per device, regardless of status."""
    entries = []
    for d in devices:
        name = d.get("Device Name", "")
        address = d.get("Device Address", "")
        location = d.get("Location", "")
        entries.append(
            {
                "device_name": name,
                "device_ip": address,
                "location": location,
                "issue_type": "Inventory Check",
                "description": f"Routine inventory ticket for device {name} ({address}).",
                "priority": "low",
            }
        )
    return entries


# --------------------------------------------------------------------------
# Ticket schema discovery + payload construction
# --------------------------------------------------------------------------

def discover_ticket_field_names() -> dict:
    """
    Try to learn the Helpdesk API's ticket field names by inspecting an
    existing ticket via GET /api/tickets. Falls back to a default schema
    if none are found or the request fails.

    Note: this API's actual ticket schema (confirmed from real POST
    responses) is just {title, description, priority, status} plus
    server-generated fields (id, created_at, updated_at, assigned_to,
    requester_email) -- there's no dedicated device_name/device_ip/
    issue_type field. Device identity and issue type are embedded
    directly in the title and description text instead, which the API
    happily stores as free text.
    """
    default_fields = {
        "title": "title",
        "description": "description",
        "priority": "priority",
        "status": "status",
        "id": "id",
    }

    try:
        resp = requests.get(f"{HELPDESK_BASE_URL}/api/tickets", headers=HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        # Handle either a bare list or a {"tickets": [...]} style wrapper.
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
        # GET failed or returned non-JSON: just use the defaults.
        pass

    return default_fields


def build_payload(issue: dict, field_names: dict) -> dict:
    """
    Build the POST body using only fields the API's schema actually
    supports (title, description, priority, status). Device name, IP,
    and issue type are embedded directly into the title/description
    text instead of separate fields, since the API has nowhere else to
    put them -- this is exactly how the device is still identifiable
    in the ticket even though there's no structured device_name column.
    """
    title = f"{issue['issue_type']}: {issue['device_name']} ({issue['device_ip']})"
    return {
        field_names["title"]: title,
        field_names["description"]: issue["description"],
        field_names["priority"]: issue["priority"],
        field_names["status"]: "open",
    }


# --------------------------------------------------------------------------
# Ticket creation
# --------------------------------------------------------------------------

def check_api_health() -> tuple[bool, str]:
    """GET /api/health -- unauthenticated, confirms the API is even reachable
    before doing anything else."""
    try:
        resp = requests.get(f"{HELPDESK_BASE_URL}/api/health", timeout=REQUEST_TIMEOUT)
        return resp.status_code == 200, resp.text
    except requests.RequestException as exc:
        return False, str(exc)


def create_ticket(payload: dict) -> tuple[bool, int, str]:
    """
    POST a single ticket. Returns (success, status_code, raw_response_text)
    -- the raw text is always returned, not just on failure, so the caller
    can print the actual API response as proof regardless of outcome.
    """
    try:
        resp = requests.post(
            f"{HELPDESK_BASE_URL}/api/tickets",
            headers=HEADERS,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
        )
        return resp.status_code in (200, 201), resp.status_code, resp.text
    except requests.RequestException as exc:
        return False, 0, str(exc)


def fetch_all_tickets() -> list[dict]:
    """GET /api/tickets and return the list of tickets, however the API
    wraps them (bare list, or {"tickets": [...]} style)."""
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


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Create Helpdesk tickets for devices with detected issues.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--port-override", type=int, default=None, help="Force a single SSH port for all devices instead of using each device's Access Port from the CSV")
    parser.add_argument("--all-devices", action="store_true", help="Create an informational ticket for every in-scope device, not just ones with issues")
    parser.add_argument("--dry-run", action="store_true", help="Print ticket payloads instead of sending them")
    args = parser.parse_args()

    if not args.dry_run:
        healthy, health_detail = check_api_health()
        print(f"API health check: {'OK' if healthy else 'FAILED'} - {health_detail}\n")
        if not healthy:
            print("WARNING: Helpdesk API health check failed. Ticket creation will likely fail too.\n")

    devices = get_in_scope_devices(read_devices(args.csv_path))

    if args.all_devices:
        entries = build_all_device_entries(devices)
    else:
        entries = find_device_issues(devices, args.port_override)

    if not entries:
        print("No issues detected. No tickets created.")
        return

    field_names = discover_ticket_field_names() if not args.dry_run else {
        "title": "title", "description": "description", "priority": "priority", "status": "status", "id": "id",
    }
    if not args.dry_run:
        print(f"Discovered ticket field names: {field_names}\n")

    print(f"Filing {len(entries)} ticket(s) -- one POST request per device -- to {HELPDESK_BASE_URL}/api/tickets\n")

    created, failed = 0, 0
    created_tickets = []  # list of (device_name, ticket_id)
    for entry in entries:
        payload = build_payload(entry, field_names)

        if args.dry_run:
            print(json.dumps(payload, indent=2))
            print("[Dry run] Ticket not sent.\n")
            continue

        print(f"--- {entry['device_name']} ({entry['device_ip']}) - {entry['issue_type']} ---")
        print(f"Request payload: {json.dumps(payload)}")

        success, status_code, raw_response = create_ticket(payload)

        print(f"Response status: {status_code}")
        print(f"Response body:   {raw_response}")
        print(f"[{'CREATED' if success else 'FAILED'}]\n")

        created += success
        failed += not success
        if success:
            ticket_id = None
            try:
                parsed = json.loads(raw_response)
                ticket_id = parsed.get(field_names["id"])
            except (ValueError, AttributeError):
                pass
            created_tickets.append((entry["device_name"], ticket_id))

    if args.dry_run:
        return

    print(f"Done. Created: {created}  Failed: {failed}  Total: {len(entries)}")

    if created_tickets:
        print("\nVerifying against GET /api/tickets (matching by ticket id)...")
        try:
            all_tickets = fetch_all_tickets()
            id_key = field_names["id"]
            all_ids = {t.get(id_key) for t in all_tickets}
            print(f"Total tickets currently in the system: {len(all_tickets)}")
            for name, ticket_id in created_tickets:
                if ticket_id is not None and ticket_id in all_ids:
                    match = next(t for t in all_tickets if t.get(id_key) == ticket_id)
                    print(f"  [CONFIRMED] {name} (id={ticket_id}): {match}")
                else:
                    print(f"  [NOT FOUND] {name} (id={ticket_id}): POST reported success, but this id isn't in GET /api/tickets.")
        except requests.RequestException as exc:
            print(f"  Could not verify via GET /api/tickets: {exc}")


if __name__ == "__main__":
    main()