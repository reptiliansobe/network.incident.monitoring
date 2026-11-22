"""
monitor.log.dns.status.py

Ongoing monitoring: check DNS health across the network and append a
log entry -- device name, date, and time -- for every device
confirmed to be functioning correctly with unaltered DNS settings.
Meant to be run on a schedule (e.g. cron) alongside the alert/correct
scripts, so there's a running record of healthy checks, not just a
record of problems.

What counts as "functioning correctly"
-----------------------------------------
    - DNS servers (DNS1, DNS2): the bind9/named service is active.
    - Consumer devices (PC1-4, SVR1-2, API, DB): their configured DNS
      servers match the expected DNS1/DNS2 addresses exactly (i.e.
      NOT altered) -- the same check used by
      monitor.check.dns.settings.py, just logging the "all good" case
      instead of emailing the "altered" case. Static-IP devices
      (SVR1-2, API, DB) are checked over SSH; DHCP devices (PC1-4) are
      checked over the GNS3 Telnet console on their own Access Port,
      since they have no SSH target -- and use the retry-confirming
      read (get_dns_configuration_via_telnet_confirmed) so a single
      flaky console read doesn't wrongly mark a healthy device as not
      logged.

Switches, SMTP, and ROUTER1 are never in scope, same as the rest of
this project (check.network.py excludes them entirely).

Re-uses the existing pieces rather than duplicating them:
    - correct.dns.settings.py -> read_devices, get_in_scope_devices,
      is_affected_device, is_static_address, connect_ssh, run_command
      (chained through to check.network.py, so this connects and
      evaluates DNS the same way check.network.py does)
    - check.network.py (via that chain) -> get_dns_configuration,
      get_dns_configuration_via_telnet_confirmed, classify_dns;
      detect_and_check_service is defined in verify.dns.service.py,
      reached the same way

Log format
----------
One line per healthy device, appended (not overwritten) each run:

    2026-08-18 | 07:15:42 | DNS1 | DNS service functioning correctly, not altered
    2026-08-18 | 07:15:44 | API  | DNS service functioning correctly, not altered

Usage
-----
    python monitor.log.dns.status.py network_devices.csv
    python monitor.log.dns.status.py network_devices.csv --log-file dns_status.log
    python monitor.log.dns.status.py network_devices.csv --port-override 22
"""

import argparse
import importlib.util
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Load correct.dns.settings.py and verify.dns.service.py (dot-named -> load
# by path). Re-uses their device reading/filtering and SSH connection
# helpers, plus check.network.py's DNS-configuration logic chained through.
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent


def _load(module_name: str, filename: str):
    path = _here / filename
    if not path.exists():
        raise ImportError(
            f"Could not find {filename} next to this script (looked in: {_here}). "
            f"Make sure {filename} is in the same folder as monitor.log.dns.status.py."
        )
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {filename}.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


correct_dns_settings = _load("correct_dns_settings", "correct.dns.settings.py")
verify_dns_service = correct_dns_settings.verify_dns_service

read_devices = correct_dns_settings.read_devices
get_in_scope_devices = correct_dns_settings.get_in_scope_devices
is_affected_device = correct_dns_settings.is_affected_device
is_static_address = correct_dns_settings.is_static_address
connect_ssh = correct_dns_settings.connect_ssh
run_command = correct_dns_settings.run_command
SSH_HOST = correct_dns_settings.SSH_HOST
detect_and_check_service = verify_dns_service.detect_and_check_service
get_dns_configuration = verify_dns_service.check_network.get_dns_configuration
get_dns_configuration_via_telnet = verify_dns_service.check_network.get_dns_configuration_via_telnet_confirmed
classify_dns = verify_dns_service.check_network.classify_dns
EXPECTED_DNS_SERVERS = list(verify_dns_service.check_network.INTERNAL_DNS_SERVERS)

DEFAULT_LOG_FILE = "dns_status.log"


# --------------------------------------------------------------------------
# Health checks
# --------------------------------------------------------------------------

def check_dns_server_healthy(device: dict, port_override) -> tuple[bool, str]:
    """DNS1/DNS2: healthy means the DNS service is active."""
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


def check_consumer_healthy(device: dict, port_override) -> tuple[bool, str]:
    """PC1-4/SVR1-2/API/DB: healthy means DNS settings match expected exactly."""
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")

    if not is_static_address(address):
        # DHCP device (PC1-4): no SSH target, check over the GNS3
        # Telnet console on its own Access Port instead.
        try:
            telnet_port = int(device.get("Access Port"))
        except (TypeError, ValueError):
            return False, "No valid Access Port in CSV for Telnet console check."

        try:
            dns_info = get_dns_configuration_via_telnet(SSH_HOST, telnet_port, username, password)
            current_dns = dns_info["effective"]
            healthy = set(current_dns) == set(EXPECTED_DNS_SERVERS)
            return healthy, f"configured DNS: {', '.join(current_dns) if current_dns else 'none'}"
        except Exception as exc:  # noqa: BLE001
            return False, f"Telnet console check failed: {exc}"

    port = port_override if port_override else 22

    try:
        client = connect_ssh(address, port, username, password)
    except Exception as exc:  # noqa: BLE001
        return False, f"SSH connection failed: {exc}"

    try:
        dns_info = get_dns_configuration(client)
        current_dns = dns_info["effective"]
        healthy = set(current_dns) == set(EXPECTED_DNS_SERVERS)
        return healthy, f"configured DNS: {', '.join(current_dns) if current_dns else 'none'}"
    except Exception as exc:  # noqa: BLE001
        return False, f"DNS check failed: {exc}"
    finally:
        client.close()


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

def log_healthy_device(log_path: Path, device_name: str) -> None:
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")
    line = f"{date_str} | {time_str} | {device_name} | DNS service functioning correctly, not altered\n"

    with log_path.open("a", encoding="utf-8") as f:
        f.write(line)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Log a status entry for every device with healthy, unaltered DNS.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--log-file", default=DEFAULT_LOG_FILE, help=f"Path to the log file (default: {DEFAULT_LOG_FILE})")
    parser.add_argument("--port-override", type=int, default=None, help="Force a single SSH port for all devices instead of using each device's Access Port from the CSV")
    args = parser.parse_args()

    log_path = Path(args.log_file)

    devices = get_in_scope_devices(read_devices(args.csv_path))
    dns_servers = [d for d in devices if (d.get("Device Name") or "").lower() in ("dns1", "dns2")]
    consumers = [d for d in devices if is_affected_device(d)]

    logged, skipped = 0, 0

    print("Checking DNS servers...")
    for device in dns_servers:
        name = device.get("Device Name", "")
        address = device.get("Device Address", "")
        healthy, detail = check_dns_server_healthy(device, args.port_override)

        if healthy:
            log_healthy_device(log_path, name)
            print(f"  [LOGGED] {name} ({address}) - {detail}")
            logged += 1
        else:
            print(f"  [SKIPPED] {name} ({address}) - not healthy ({detail}), no log entry")
            skipped += 1

    print("\nChecking consumer devices...")
    for device in consumers:
        name = device.get("Device Name", "")
        address = device.get("Device Address", "")
        healthy, detail = check_consumer_healthy(device, args.port_override)

        if healthy:
            log_healthy_device(log_path, name)
            print(f"  [LOGGED] {name} ({address}) - {detail}")
            logged += 1
        else:
            print(f"  [SKIPPED] {name} ({address}) - not healthy ({detail}), no log entry")
            skipped += 1

    print(f"\nDone. Logged: {logged}  Skipped: {skipped}  Log file: {log_path.resolve()}")


if __name__ == "__main__":
    main()