"""
restart.dns.service.py

Step 2 of DNS remediation: connect to the internal DNS server(s) over
SSH, restart the DNS service (bind9/named), and confirm it comes back
up as "active". Meant to be run after verify.dns.service.py has
confirmed the service is actually down -- this script re-checks status
itself too, so it won't restart a service that's already healthy
unless told to.

Which devices it targets
-------------------------
DNS1 and DNS2 (the in-scope DNS devices from check.network.py).
Connection details come from the CSV (Access Port, Username,
Password); SSH connects via localhost:<Access Port>, same as
verify.dns.service.py and check.network.py -- override the port for
all devices at once with --port-override if needed.

Restart process per device
---------------------------
    1. Detect which service is installed (bind9 or named) and check
       its current state.
    2. If it's already active, skip the restart (use --force to
       restart anyway).
    3. Otherwise, restart it with sudo systemctl restart <service>.
    4. Re-check status and confirm it's now "active".

Sudo
----
The lab's "ubuntu" user needs privilege escalation to restart a
system service. This script pipes the same password used for SSH
into `sudo -S`, which works for the common case where the SSH user's
sudo password matches their login password (true for the default
ubuntu/ubuntu lab credentials). If your sudoers config uses NOPASSWD
or a different password, this still works, since `sudo -S` simply
ignores stdin when no password prompt appears.

Usage
-----
    python restart.dns.service.py network_devices.csv
    python restart.dns.service.py network_devices.csv --force
    python restart.dns.service.py network_devices.csv --port-override 22

Requires
--------
    pip install paramiko
"""

import argparse
import importlib.util
import time
from pathlib import Path

import paramiko

# --------------------------------------------------------------------------
# Load verify.dns.service.py (dot in filename -> load by path, not `import`)
# Re-uses its SSH connection + service-detection helpers so the restart
# logic and status-check logic never drift out of sync with each other.
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent
_verify_path = _here / "verify.dns.service.py"

_spec = importlib.util.spec_from_file_location("verify_dns_service", _verify_path)
if _spec is None or _spec.loader is None:
    raise ImportError(
        f"Could not find verify.dns.service.py next to this script (looked in: {_here}). "
        "Make sure verify.dns.service.py is in the same folder as restart.dns.service.py."
    )
verify_dns_service = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_dns_service)

read_devices = verify_dns_service.check_network.read_devices
get_in_scope_devices = verify_dns_service.check_network.get_in_scope_devices
connect_ssh = verify_dns_service.connect_ssh
run_command = verify_dns_service.run_command
detect_and_check_service = verify_dns_service.detect_and_check_service

POST_RESTART_WAIT_SEC = 3
STATUS_RECHECK_ATTEMPTS = 3
STATUS_RECHECK_DELAY_SEC = 2


# --------------------------------------------------------------------------
# Restart logic
# --------------------------------------------------------------------------

def restart_service(client: paramiko.SSHClient, service_name: str, password: str) -> tuple[bool, str]:
    """Restart a systemd service with sudo, using the SSH password for sudo -S."""
    command = f"echo {password!r} | sudo -S systemctl restart {service_name} 2>&1"
    out, err, exit_code = run_command(client, command)

    if exit_code != 0:
        return False, out or err or f"exit code {exit_code}"
    return True, out


def wait_for_active(client: paramiko.SSHClient, service_name: str) -> tuple[bool, str]:
    """Poll systemctl a few times to confirm the service becomes active."""
    for attempt in range(1, STATUS_RECHECK_ATTEMPTS + 1):
        out, _, _ = run_command(client, f"systemctl is-active {service_name}")
        state = out.strip().lower()
        if state == "active":
            return True, state
        time.sleep(STATUS_RECHECK_DELAY_SEC)
    return False, state


def remediate_dns_device(device: dict, port_override, force: bool) -> dict:
    name = device.get("Device Name", "")
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")

    port = port_override if port_override else 22

    result = {
        "device_name": name,
        "address": address,
        "port": port,
        "connected": False,
        "action": None,
        "before_state": "unknown",
        "after_state": "unknown",
        "success": False,
        "error": None,
    }

    try:
        client = connect_ssh(address, port, username, password)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"SSH connection failed: {exc}"
        return result

    try:
        result["connected"] = True

        status = detect_and_check_service(client)
        if not status["found"]:
            result["error"] = "Neither 'bind9' nor 'named' service found on this host."
            return result

        service_name = status["service_name"]
        result["before_state"] = status["state"]

        if status["state"] == "active" and not force:
            result["action"] = "skipped (already active)"
            result["after_state"] = status["state"]
            result["success"] = True
            return result

        restarted, restart_output = restart_service(client, service_name, password)
        result["action"] = f"restart {service_name}"

        if not restarted:
            result["error"] = f"Restart command failed: {restart_output}"
            return result

        time.sleep(POST_RESTART_WAIT_SEC)
        confirmed, final_state = wait_for_active(client, service_name)
        result["after_state"] = final_state
        result["success"] = confirmed

        if not confirmed:
            result["error"] = f"Service did not reach 'active' state after restart (last seen: {final_state})."

    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Remediation failed: {exc}"
    finally:
        client.close()

    return result


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Restart the DNS service on internal DNS server(s) and confirm it's running.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--port-override", type=int, default=None, help="Force a single SSH port for all devices instead of using each device's Access Port from the CSV")
    parser.add_argument("--force", action="store_true", help="Restart the service even if it's already active")
    args = parser.parse_args()

    devices = get_in_scope_devices(read_devices(args.csv_path))
    dns_devices = [d for d in devices if (d.get("Device Name") or "").lower() in ("dns1", "dns2")]

    if not dns_devices:
        print("No DNS devices found in the inventory.")
        return

    print(f"Remediating {len(dns_devices)} DNS device(s) via localhost:<Access Port>...\n")

    results = []
    for device in dns_devices:
        result = remediate_dns_device(device, args.port_override, args.force)
        results.append(result)

        label = f"{result['device_name']} ({result['address']}:{result['port']})"

        if result["error"] and not result["connected"]:
            print(f"[UNREACHABLE] {label} - {result['error']}")
            continue

        if result["action"] == "skipped (already active)":
            print(f"[SKIPPED] {label} - service already active, no restart needed")
            continue

        if result["success"]:
            print(
                f"[RESTARTED] {label} - was '{result['before_state']}', "
                f"now '{result['after_state']}' (UP)"
            )
        else:
            print(
                f"[FAILED] {label} - was '{result['before_state']}' - {result['error']}"
            )

    print("\nSummary:")
    for r in results:
        if not r["connected"]:
            verdict = "could not be reached"
        elif r["success"]:
            verdict = "running normally" if r["action"] == "skipped (already active)" else "restarted successfully, now UP"
        else:
            verdict = "restart failed - manual intervention needed"
        print(f"  {r['device_name']}: {verdict}")

    return results


if __name__ == "__main__":
    main()