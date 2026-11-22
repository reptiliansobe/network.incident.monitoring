"""
monitor.create_tickets.py

Step 3 of the ongoing network monitoring and automated response
system: check device availability and automatically file a Helpdesk
ticket for every device that's unavailable, indicating the issue type
and the specific device affected.

Re-uses the existing pieces rather than duplicating them:
    - monitor.read_devices.py       -> read_devices()
    - monitor.check.availability.py -> get_unavailable_devices() (the
                                        same in-scope availability logic
                                        used for the email notifications,
                                        so "unavailable" means the same
                                        thing in both places)
    - create.tickets.py             -> Helpdesk API config, schema
                                        discovery, and ticket creation,
                                        so the API auth/host/enum
                                        handling lives in one place.

Helpdesk API
------------
    HOST: helpdesk.d522.wgu.internal
    PORT: 5000
    Auth: Bearer token (defined in create.tickets.py)

    POST http://helpdesk.d522.wgu.internal:5000/api/tickets

Usage
-----
    python monitor.create_tickets.py network_devices.csv
    python monitor.create_tickets.py network_devices.csv --dry-run
"""

import argparse
import importlib.util
import json
from pathlib import Path

# --------------------------------------------------------------------------
# Load monitor.read_devices.py, monitor.check_availability.py, and
# create.tickets.py (all dot-named -> load by path, not `import`)
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent


def _load(module_name: str, filename: str):
    path = _here / filename
    if not path.exists():
        raise ImportError(
            f"Could not find {filename} next to this script (looked in: {_here}). "
            f"Make sure {filename} is in the same folder as monitor.create_tickets.py."
        )
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {filename}.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


monitor_read_devices = _load("monitor_read_devices", "monitor.read.devices.py")
monitor_check_availability = _load("monitor_check_availability", "monitor.check.availability.py")
create_tickets = _load("create_tickets", "create.tickets.py")

get_unavailable_devices = monitor_check_availability.get_unavailable_devices

discover_ticket_field_names = create_tickets.discover_ticket_field_names
build_payload = create_tickets.build_payload
create_ticket = create_tickets.create_ticket


# --------------------------------------------------------------------------
# Convert unavailable devices into ticket issues
# --------------------------------------------------------------------------

def build_issue(device: dict) -> dict:
    return {
        "device_name": device["name"],
        "device_ip": device["address"],
        "issue_type": "Device Unavailable",
        "description": (
            f"Device {device['name']} ({device['address']}) did not respond to ping "
            f"as of {device['timestamp']}."
        ),
        "priority": "high",
    }


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Create a Helpdesk ticket for every currently unavailable device.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--dry-run", action="store_true", help="Print ticket payloads instead of sending them")
    args = parser.parse_args()

    unavailable = get_unavailable_devices(args.csv_path)

    if not unavailable:
        print("All devices are available. No tickets created.")
        return

    issues = [build_issue(d) for d in unavailable]

    print(f"Filing {len(issues)} ticket(s) for unavailable device(s)...\n")

    field_names = discover_ticket_field_names() if not args.dry_run else {
        "title": "title", "description": "description", "priority": "priority", "status": "status", "id": "id",
    }

    created, failed = 0, 0
    for issue in issues:
        payload = build_payload(issue, field_names)

        if args.dry_run:
            print(json.dumps(payload, indent=2))
            print("[Dry run] Ticket not sent.\n")
            continue

        print(f"--- {issue['device_name']} ({issue['device_ip']}) - {issue['issue_type']} ---")
        print(f"Request payload: {json.dumps(payload)}")

        success, status_code, raw_response = create_ticket(payload)

        print(f"Response status: {status_code}")
        print(f"Response body:   {raw_response}")
        print(f"[{'CREATED' if success else 'FAILED'}]\n")

        created += success
        failed += not success

    if not args.dry_run:
        print(f"\nDone. Created: {created}  Failed: {failed}  Total: {len(issues)}")


if __name__ == "__main__":
    main()