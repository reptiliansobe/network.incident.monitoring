"""
monitor.read_devices.py

Step 1 of the ongoing network monitoring and automated response system:
read network device information from a CSV file.

This is the foundation the later monitoring steps (availability
checks, DNS configuration checks, automated alerting/remediation)
will build on, so it's kept intentionally simple and dependency-free:
just a clean, validated read of the device inventory.

Expected CSV columns:
    Device ID, Device Name, Device Address, Subnet Mask, Location,
    Access Port, OS, Username, Password

Usage
-----
    python monitor.read_devices.py [path_to_csv]

If no path is given, it defaults to "network_devices.csv" in the
current directory.
"""

import csv
import sys
from pathlib import Path

REQUIRED_COLUMNS = {
    "Device ID",
    "Device Name",
    "Device Address",
    "Subnet Mask",
    "Location",
    "Access Port",
    "OS",
    "Username",
    "Password",
}


def read_devices(csv_path: str) -> list[dict]:
    """Read the network devices CSV and return a list of device dicts."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Could not find CSV file: {csv_path}")

    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"CSV is missing required column(s): {', '.join(sorted(missing))}"
            )

        devices = []
        for row in reader:
            cleaned = {k: (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
            devices.append(cleaned)

    return devices


def print_device_summary(devices: list[dict]) -> None:
    print(f"{'ID':<6}{'Name':<10}{'Address':<16}{'Location':<10}{'OS':<10}")
    print("-" * 55)
    for d in devices:
        print(
            f"{d.get('Device ID', ''):<6}"
            f"{d.get('Device Name', ''):<10}"
            f"{d.get('Device Address', ''):<16}"
            f"{d.get('Location', ''):<10}"
            f"{d.get('OS', ''):<10}"
        )
    print("-" * 55)
    print(f"Total devices loaded: {len(devices)}")


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "network_devices.csv"
    devices = read_devices(csv_path)
    print_device_summary(devices)
    return devices


if __name__ == "__main__":
    main()