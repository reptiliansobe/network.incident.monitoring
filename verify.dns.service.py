"""
verify.dns.service.py

Step 1 of DNS remediation: connect to the internal DNS server(s) over
SSH and verify the current status of the DNS service (bind9/named)
BEFORE any restart is attempted. This script only checks and reports
status -- it does not restart anything. That's handled by a separate
remediation script once this confirms the service is actually down.

SSH connection
--------------
Re-uses check.network.py's connection helper: every in-scope device
is reached via localhost, using that device's own "Access Port" from
the CSV as the port (GNS3 exposes each device's SSH through the same
host machine, gatewayed by its Access Port -- not through the
device's own Device Address).

Detecting the DNS service
--------------------------
Ubuntu DNS servers typically run either "bind9" or "named" under
systemd, depending on how the package was installed. This script
checks both and reports whichever one is actually present.

Usage
-----
    python verify.dns.service.py network_devices.csv
    python verify.dns.service.py network_devices.csv --port-override 22

Requires
--------
    pip install paramiko
"""

import argparse
import importlib.util
from pathlib import Path

import paramiko

# --------------------------------------------------------------------------
# Load check.network.py (dot in the filename -> load by path, not `import`)
# Re-uses its device reading/scope filtering and SSH connection helpers so
# this script always connects the same way check.network.py does.
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent
_check_network_path = _here / "check.network.py"

_spec = importlib.util.spec_from_file_location("check_network", _check_network_path)
if _spec is None or _spec.loader is None:
    raise ImportError(
        f"Could not find check.network.py next to this script (looked in: {_here}). "
        "Make sure check.network.py is in the same folder as verify.dns.service.py."
    )
check_network = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_network)

read_devices = check_network.read_devices
get_in_scope_devices = check_network.get_in_scope_devices
connect_ssh = check_network.connect_ssh
run_command = check_network.run_command

CANDIDATE_SERVICE_NAMES = ["bind9", "named"]


# --------------------------------------------------------------------------
# DNS service status check
# --------------------------------------------------------------------------

def detect_and_check_service(client: paramiko.SSHClient) -> dict:
    """
    Find which DNS service (bind9 or named) is actually installed on the
    host and return its current systemd status.

    Checking "systemctl is-active <name>" alone is NOT enough to detect
    whether a service exists: systemd reports "inactive" both for a
    stopped-but-installed unit and for a unit that doesn't exist at all.
    So we first check LoadState via "systemctl show", which reports
    "not-found" for a nonexistent unit and "loaded" for a real one, and
    only trust the active/inactive state once we know the unit is real.
    """
    for service_name in CANDIDATE_SERVICE_NAMES:
        load_out, _, _ = run_command(
            client, f"systemctl show {service_name} --property=LoadState --value"
        )
        load_state = load_out.strip().lower()

        if load_state != "loaded":
            continue  # unit doesn't exist on this host, try the next candidate

        active_out, _, _ = run_command(client, f"systemctl is-active {service_name}")
        state = active_out.strip().lower()

        enabled_out, _, _ = run_command(client, f"systemctl is-enabled {service_name} 2>/dev/null")
        return {
            "service_name": service_name,
            "state": state,
            "enabled": enabled_out.strip() or "unknown",
            "found": True,
        }

    return {"service_name": None, "state": "unknown", "enabled": "unknown", "found": False}


def verify_dns_device(device: dict, port_override) -> dict:
    name = device.get("Device Name", "")
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")

    try:
        port = port_override if port_override else 22
    except (TypeError, ValueError):
        return {
            "device_name": name, "address": address, "port": None, "connected": False,
            "service_name": None, "state": "unknown", "enabled": "unknown",
            "error": "No valid Access Port in CSV.",
        }

    result = {
        "device_name": name,
        "address": address,
        "port": port,
        "connected": False,
        "service_name": None,
        "state": "unknown",
        "enabled": "unknown",
        "error": None,
    }

    try:
        client = connect_ssh(address, port, username, password)
    except Exception as exc:  # noqa: BLE001 - report any connection failure
        result["error"] = f"SSH connection failed: {exc}"
        return result

    try:
        result["connected"] = True
        status = detect_and_check_service(client)
        result.update(status)
        if not status["found"]:
            result["error"] = "Neither 'bind9' nor 'named' service found on this host."
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Status check failed: {exc}"
    finally:
        client.close()

    return result


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Verify DNS service status on internal DNS server(s) over SSH.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--port-override", type=int, default=None, help="Force a single SSH port for all devices instead of using each device's Access Port from the CSV")
    args = parser.parse_args()

    devices = get_in_scope_devices(read_devices(args.csv_path))
    dns_devices = [d for d in devices if (d.get("Device Name") or "").lower() in ("dns1", "dns2")]

    if not dns_devices:
        print("No DNS devices found in the inventory.")
        return

    print(f"Checking {len(dns_devices)} DNS device(s) via localhost:<Access Port>...\n")

    results = []
    for device in dns_devices:
        result = verify_dns_device(device, args.port_override)
        results.append(result)

        label = f"{result['device_name']} ({result['address']}:{result['port']})"

        if result["error"] and not result["connected"]:
            print(f"[UNREACHABLE] {label} - {result['error']}")
            continue

        if result["error"]:
            print(f"[WARNING] {label} - {result['error']}")
            continue

        status_word = result["state"].upper()
        needs_restart = result["state"] != "active"
        flag = "NEEDS RESTART" if needs_restart else "OK"
        print(
            f"[{flag}] {label} - service '{result['service_name']}' is {status_word} "
            f"(enabled: {result['enabled']})"
        )

    print("\nSummary:")
    for r in results:
        if r["connected"] and not r["error"]:
            verdict = "DOWN - restart needed" if r["state"] != "active" else "running normally"
        else:
            verdict = "could not be checked"
        print(f"  {r['device_name']}: {verdict}")

    return results


if __name__ == "__main__":
    main()