"""
backup.dns.config.py

Connects to both DNS servers over SSH and backs up their DNS record
configuration into a local directory structure:

    DNS-Backup/
        Server-1/
            record-config.txt
        Server-2/
            record-config.txt

DNS1 is backed up to Server-1, DNS2 to Server-2 (devices sorted by
name so the mapping is deterministic).

What gets backed up
---------------------
The DNS config layout can differ depending on how the service was
installed (bind9 on Ubuntu typically uses /etc/bind, while a "named"
install can use /etc/named.conf + /var/named). Rather than guessing
one location, this script searches all the common locations and
backs up whatever actually exists on that host:

    /etc/bind
    /etc/named.conf
    /etc/named
    /var/named

Every file found gets dumped into record-config.txt with a header
showing its original path, so the single backup file is a complete,
readable snapshot of that server's DNS record configuration
(named.conf, named.conf.local, zone files / db.* records, etc.).

Usage
-----
    python backup.dns.config.py network_devices.csv
    python backup.dns.config.py network_devices.csv --output-dir DNS-Backup
    python backup.dns.config.py network_devices.csv --port-override 22

Requires
--------
    pip install paramiko
"""

import argparse
import importlib.util
from datetime import datetime
from pathlib import Path

import paramiko

# --------------------------------------------------------------------------
# Load verify.dns.service.py (dot in filename -> load by path, not `import`)
# Re-uses its SSH connection helpers + the check.network.py device reader.
# --------------------------------------------------------------------------

_here = Path(__file__).resolve().parent
_verify_path = _here / "verify.dns.service.py"

_spec = importlib.util.spec_from_file_location("verify_dns_service", _verify_path)
if _spec is None or _spec.loader is None:
    raise ImportError(
        f"Could not find verify.dns.service.py next to this script (looked in: {_here}). "
        "Make sure verify.dns.service.py is in the same folder as backup.dns.config.py."
    )
verify_dns_service = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_dns_service)

read_devices = verify_dns_service.check_network.read_devices
get_in_scope_devices = verify_dns_service.check_network.get_in_scope_devices
connect_ssh = verify_dns_service.connect_ssh
run_command = verify_dns_service.run_command

CANDIDATE_CONFIG_PATHS = ["/etc/bind", "/etc/named.conf", "/etc/named", "/var/named"]


# --------------------------------------------------------------------------
# Config discovery + retrieval
# --------------------------------------------------------------------------

def find_config_files(client: paramiko.SSHClient, password: str) -> list[str]:
    """Find every DNS config file present on the host, across common locations."""
    paths = " ".join(CANDIDATE_CONFIG_PATHS)
    cmd = (
        f"echo {password!r} | sudo -S bash -c "
        f"\"find {paths} -maxdepth 3 -type f 2>/dev/null\""
    )
    out, _, _ = run_command(client, cmd)
    return [line.strip() for line in out.splitlines() if line.strip()]


def fetch_file_contents(client: paramiko.SSHClient, password: str, remote_path: str) -> str:
    cmd = f"echo {password!r} | sudo -S cat {remote_path!r} 2>&1"
    out, _, _ = run_command(client, cmd)
    return out


def build_record_config_text(device_name: str, address: str, files: dict[str, str]) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"DNS Record Configuration Backup",
        f"Device: {device_name} ({address})",
        f"Backed up: {timestamp}",
        "=" * 60,
        "",
    ]
    if not files:
        lines.append("No DNS configuration files were found on this host.")
    else:
        for path, content in files.items():
            lines.append(f"----- {path} -----")
            lines.append(content.rstrip("\n"))
            lines.append("")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Per-device backup
# --------------------------------------------------------------------------

def backup_dns_device(device: dict, port_override, output_dir: Path, server_label: str) -> dict:
    name = device.get("Device Name", "")
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")

    result = {
        "device_name": name,
        "address": address,
        "server_label": server_label,
        "connected": False,
        "success": False,
        "error": None,
        "file_count": 0,
        "output_path": None,
    }

    port = port_override if port_override else 22

    try:
        client = connect_ssh(address, port, username, password)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"SSH connection failed: {exc}"
        return result

    try:
        result["connected"] = True

        remote_paths = find_config_files(client, password)
        files = {}
        for path in remote_paths:
            files[path] = fetch_file_contents(client, password, path)

        record_config_text = build_record_config_text(name, address, files)

        server_dir = output_dir / server_label
        server_dir.mkdir(parents=True, exist_ok=True)
        out_path = server_dir / "record-config.txt"
        out_path.write_text(record_config_text, encoding="utf-8")

        result["file_count"] = len(files)
        result["output_path"] = str(out_path)
        result["success"] = True

        if not files:
            result["error"] = "Connected, but no DNS config files were found to back up."

    except Exception as exc:  # noqa: BLE001
        result["error"] = f"Backup failed: {exc}"
    finally:
        client.close()

    return result


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Back up DNS record configuration from both DNS servers.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--output-dir", default="DNS-Backup", help="Local backup directory name (default: DNS-Backup)")
    parser.add_argument("--port-override", type=int, default=None, help="Force a single SSH port for all devices instead of using each device's Access Port from the CSV")
    args = parser.parse_args()

    devices = get_in_scope_devices(read_devices(args.csv_path))
    dns_devices = sorted(
        (d for d in devices if (d.get("Device Name") or "").lower() in ("dns1", "dns2")),
        key=lambda d: d.get("Device Name", ""),
    )

    if not dns_devices:
        print("No DNS devices found in the inventory.")
        return

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Backing up {len(dns_devices)} DNS server(s) into '{output_dir}/'...\n")

    results = []
    for i, device in enumerate(dns_devices, start=1):
        server_label = f"Server-{i}"
        result = backup_dns_device(device, args.port_override, output_dir, server_label)
        results.append(result)

        label = f"{result['device_name']} ({result['address']}) -> {server_label}"

        if not result["connected"]:
            print(f"[UNREACHABLE] {label} - {result['error']}")
        elif result["success"] and result["file_count"] > 0:
            print(f"[BACKED UP] {label} - {result['file_count']} file(s) saved to {result['output_path']}")
        else:
            print(f"[WARNING] {label} - {result['error']}")

    print("\nSummary:")
    for r in results:
        if not r["connected"]:
            verdict = "could not be reached"
        elif r["success"] and r["file_count"] > 0:
            verdict = f"backed up ({r['file_count']} file(s)) -> {r['output_path']}"
        else:
            verdict = r["error"] or "backup incomplete"
        print(f"  {r['device_name']} ({r['server_label']}): {verdict}")

    return results


if __name__ == "__main__":
    main()