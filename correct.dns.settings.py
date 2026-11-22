"""
correct.dns.settings.py

Step 3 of DNS remediation: connect to each affected device and correct
its DNS resolver configuration so it points at the internal DNS
servers (DNS1 10.10.10.10, DNS2 10.10.10.20), then confirm the change
actually took effect and the device can resolve names again.

Which devices count as "affected"
----------------------------------
All in-scope devices from check.network.py except the DNS servers
themselves (they ARE the DNS servers, not consumers of DNS):

    SVR1, SVR2, API, DB   -- corrected over SSH (Device Address : 22)
    PC1, PC2, PC3, PC4    -- corrected over the GNS3 Telnet console
                             (localhost : Access Port), since they're
                             DHCP devices with no SSH target

Switches, SMTP, and ROUTER1 are never in scope (check.network.py
excludes them entirely).

What "correcting DNS settings" does
-------------------------------------
For static-IP devices (SSH):
    1. Detect whether systemd-resolved is managing DNS.
    2. If so, set the DNS servers for the default interface with
       `resolvectl dns <iface> 10.10.10.10 10.10.10.20`.
    3. If not, write nameserver entries directly to /etc/resolv.conf.
    4. Re-read the config back to confirm both DNS servers are now
       present.
    5. Run a live name resolution test (`getent hosts`) on the device
       itself to prove DNS actually works end-to-end, not just that
       the config file looks right.

For DHCP devices (Telnet console), the same five steps happen over
the console session instead of SSH, with one addition: if resolvectl
is already known to be broken (e.g. PC2/PC3, where systemd-resolved's
D-Bus service isn't registered), it skips straight to the
/etc/resolv.conf fallback rather than retrying a command that just
failed on the read side too.

Connection
----------
Static-IP devices: connects directly to the device's own IP (Device
Address) on port 22.
DHCP devices: connects to localhost on the device's own Access Port
from the CSV (a GNS3 Telnet console, not SSH).

Usage
-----
    python correct.dns.settings.py network_devices.csv
    python correct.dns.settings.py network_devices.csv --port-override 22

Requires
--------
    pip install paramiko
"""

import argparse
import importlib.util
import json
from pathlib import Path

import paramiko

# --------------------------------------------------------------------------
# Load verify.dns.service.py (dot in filename -> load by path, not `import`)
# Re-uses its SSH connection helpers + the check.network.py device reader
# and scope filtering, chained through verify.dns.service.py.
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent
_verify_path = _here / "verify.dns.service.py"

_spec = importlib.util.spec_from_file_location("verify_dns_service", _verify_path)
if _spec is None or _spec.loader is None:
    raise ImportError(
        f"Could not find verify.dns.service.py next to this script (looked in: {_here}). "
        "Make sure verify.dns.service.py is in the same folder as correct.dns.settings.py."
    )
verify_dns_service = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_dns_service)

read_devices = verify_dns_service.check_network.read_devices
get_in_scope_devices = verify_dns_service.check_network.get_in_scope_devices
connect_ssh = verify_dns_service.connect_ssh
run_command = verify_dns_service.run_command

is_static_address = verify_dns_service.check_network.is_static_address
correct_dns_via_telnet = verify_dns_service.check_network.correct_dns_via_telnet
SSH_HOST = verify_dns_service.check_network.SSH_HOST
get_dns_configuration = verify_dns_service.check_network.get_dns_configuration
get_dns_configuration_via_telnet = verify_dns_service.check_network.get_dns_configuration_via_telnet_confirmed
classify_dns = verify_dns_service.check_network.classify_dns

DNS_SERVERS = ["10.10.10.10", "10.10.10.20"]
TEST_DOMAIN = "example.com"


# --------------------------------------------------------------------------
# Pre-check: is this device actually misconfigured?
# --------------------------------------------------------------------------

def check_dns_status(device: dict, port_override) -> tuple[str, str]:
    """
    Check a device's CURRENT DNS status before touching anything, using
    the same classification create.tickets.py uses to decide what counts
    as an issue. Returns one of:
        ("OK", detail)             - already correct, leave it alone
        ("MISCONFIGURED", detail)  - needs correcting
        ("UNREACHABLE", detail)    - couldn't even check -- NOT the same
                                      as "already fine", so this must not
                                      be silently skipped
    """
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")

    try:
        if is_static_address(address):
            port = port_override if port_override else 22
            client = connect_ssh(address, port, username, password)
            try:
                dns_info = get_dns_configuration(client)
            finally:
                client.close()
        else:
            telnet_port = int(device.get("Access Port"))
            dns_info = get_dns_configuration_via_telnet(SSH_HOST, telnet_port, username, password)
    except Exception as exc:  # noqa: BLE001
        return "UNREACHABLE", str(exc)

    status, detail = classify_dns(dns_info)
    return status, detail


# --------------------------------------------------------------------------
# Device filtering
# --------------------------------------------------------------------------

def is_affected_device(device: dict) -> bool:
    """
    In-scope device that isn't a DNS server itself. Includes both
    static-IP devices (SVR1, SVR2, API, DB -- corrected over SSH) and
    DHCP devices (PC1-4 -- corrected over the GNS3 Telnet console,
    since they have no SSH target).
    """
    name = (device.get("Device Name") or "").strip().lower()
    return name not in ("dns1", "dns2")


# --------------------------------------------------------------------------
# Ubuntu / systemd-resolved DNS correction
# --------------------------------------------------------------------------

def get_default_interface(client: paramiko.SSHClient) -> str:
    out, _, _ = run_command(client, "ip route show default")
    # e.g. "default via 10.10.10.1 dev eth0 proto dhcp ..."
    parts = out.split()
    if "dev" in parts:
        return parts[parts.index("dev") + 1]
    return "eth0"  # reasonable fallback for these lab devices


def correct_dns_ubuntu(client: paramiko.SSHClient, password: str) -> dict:
    result = {"method": None, "before": None, "after": None, "resolved": None, "error": None}

    resolved_state, _, _ = run_command(client, "systemctl is-active systemd-resolved")
    using_systemd_resolved = resolved_state.strip().lower() == "active"

    if using_systemd_resolved:
        iface = get_default_interface(client)
        result["method"] = f"resolvectl (interface {iface})"

        before, _, _ = run_command(client, f"resolvectl dns {iface}")
        result["before"] = before

        dns_args = " ".join(DNS_SERVERS)
        cmd = f"echo {password!r} | sudo -S resolvectl dns {iface} {dns_args} 2>&1"
        _, _, exit_code = run_command(client, cmd)
        if exit_code != 0:
            result["error"] = f"resolvectl dns command exited {exit_code}"
            return result

        after, _, _ = run_command(client, f"resolvectl dns {iface}")
        result["after"] = after

    else:
        result["method"] = "/etc/resolv.conf"

        before, _, _ = run_command(client, "cat /etc/resolv.conf")
        result["before"] = before

        resolv_contents = "\\n".join(f"nameserver {ip}" for ip in DNS_SERVERS)
        cmd = f"echo {password!r} | sudo -S bash -c \"printf '{resolv_contents}\\n' > /etc/resolv.conf\" 2>&1"
        _, _, exit_code = run_command(client, cmd)
        if exit_code != 0:
            result["error"] = f"Writing /etc/resolv.conf exited {exit_code}"
            return result

        after, _, _ = run_command(client, "cat /etc/resolv.conf")
        result["after"] = after

    all_present = all(ip in (result["after"] or "") for ip in DNS_SERVERS)
    if not all_present:
        result["error"] = "DNS servers not present in config after update."
        return result

    # Prove it actually works, not just that the config file looks right.
    lookup_out, lookup_err, lookup_code = run_command(client, f"getent hosts {TEST_DOMAIN}")
    result["resolved"] = lookup_code == 0 and bool(lookup_out.strip())
    if not result["resolved"]:
        result["error"] = f"Config updated but live lookup of {TEST_DOMAIN} failed: {lookup_err or lookup_out}"

    return result


# --------------------------------------------------------------------------
# Per-device orchestration
# --------------------------------------------------------------------------

def correct_dns_for_device(device: dict, port_override, force: bool = False) -> dict:
    name = device.get("Device Name", "")
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")

    result = {
        "device_name": name,
        "address": address,
        "os": device.get("OS", ""),
        "connected": False,
        "success": False,
        "skipped": False,
        "error": None,
        "detail": None,
        "port_used": None,
    }

    if not force:
        status, status_detail = check_dns_status(device, port_override)

        if status == "UNREACHABLE":
            result["error"] = f"Could not check current status: {status_detail}"
            return result

        if status != "MISCONFIGURED":
            # OK or UNKNOWN -- already fine, or not confirmed broken.
            # Either way, leave it alone rather than rewriting it.
            result["skipped"] = True
            result["success"] = True
            result["error"] = status_detail
            return result

    if not is_static_address(address):
        # DHCP device (PC1-4): no SSH target, correct over the GNS3
        # Telnet console on its own Access Port instead.
        try:
            telnet_port = int(device.get("Access Port"))
        except (TypeError, ValueError):
            result["error"] = "No valid Access Port in CSV for Telnet console correction."
            return result

        result["port_used"] = telnet_port

        try:
            detail = correct_dns_via_telnet(SSH_HOST, telnet_port, username, password)
            result["connected"] = True
            result["detail"] = detail
            result["success"] = detail["error"] is None and bool(detail.get("resolved"))
            if detail["error"]:
                result["error"] = detail["error"]
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"Telnet console correction failed: {exc}"

        return result

    port = port_override if port_override else 22

    try:
        client = connect_ssh(address, port, username, password)
        result["port_used"] = port
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"SSH connection failed: {exc}"
        return result

    try:
        result["connected"] = True

        detail = correct_dns_ubuntu(client, password)

        result["detail"] = detail
        result["success"] = detail["error"] is None and bool(detail.get("resolved"))
        if detail["error"]:
            result["error"] = detail["error"]

    except Exception as exc:  # noqa: BLE001
        result["error"] = f"DNS correction failed: {exc}"
    finally:
        client.close()

    return result


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Correct DNS settings on affected devices and confirm the fix.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--port-override", type=int, default=None, help="Force a single SSH port for all devices instead of using each device's Access Port from the CSV")
    parser.add_argument("--force", action="store_true", help="Correct every affected device regardless of current status, skipping the pre-check")
    parser.add_argument("--corrected-devices-file", default="corrected_devices.json", help="Where to write the list of actually-corrected devices (default: corrected_devices.json)")
    args = parser.parse_args()

    devices = get_in_scope_devices(read_devices(args.csv_path))
    affected = [d for d in devices if is_affected_device(d)]

    if not affected:
        print("No affected devices found to correct.")
        return

    print(f"Checking {len(affected)} in-scope device(s) for DNS misconfiguration: "
          f"{', '.join(d['Device Name'] for d in affected)}\n")

    results = []
    for device in affected:
        result = correct_dns_for_device(device, args.port_override, args.force)
        results.append(result)

        label = f"{result['device_name']} ({result['address']})"

        if result["skipped"]:
            print(f"[SKIPPED] {label} - already correct, no action needed ({result['error']})")
            continue

        if not result["connected"]:
            print(f"[UNREACHABLE] {label} - {result['error']}")
            continue

        if result["success"]:
            method = result["detail"]["method"]
            print(
                f"[UPDATED] {label} (port {result['port_used']}) - DNS set via {method}, "
                f"live resolution of '{TEST_DOMAIN}' confirmed working"
            )
        else:
            print(f"[FAILED] {label} - {result['error']}")

    corrected_count = sum(1 for r in results if r["success"] and not r["skipped"])
    skipped_count = sum(1 for r in results if r["skipped"])
    print(f"\nDone. Corrected: {corrected_count}  Skipped (already OK): {skipped_count}  "
          f"Failed: {sum(1 for r in results if not r['success'])}  Total: {len(results)}")

    # Record exactly which devices were actually corrected this run, so
    # resolution.email.py can report the real affected list instead of
    # guessing from a blanket in-scope filter. A live re-check at email
    # time would be useless here -- everything would already show OK
    # since it was just fixed.
    corrected_devices = [
        {"name": r["device_name"], "address": r["address"]}
        for r in results if r["success"] and not r["skipped"]
    ]
    if corrected_devices:
        output_path = Path(args.corrected_devices_file)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(corrected_devices, f, indent=2)
        print(f"Corrected device list written to {output_path.resolve()} "
              f"(used by resolution.email.py)")

    print("\nSummary:")
    for r in results:
        if r["skipped"]:
            verdict = "already correct, left alone"
        elif not r["connected"]:
            verdict = "could not be reached"
        elif r["success"]:
            verdict = "DNS settings corrected and confirmed working"
        else:
            verdict = "correction failed - manual intervention needed"
        print(f"  {r['device_name']}: {verdict}")

    return results


if __name__ == "__main__":
    main()