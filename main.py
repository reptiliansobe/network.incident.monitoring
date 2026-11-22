"""
list_network_devices.py

Reads a network devices CSV file and produces a list of network devices.

Expected CSV columns:
    Device ID, Device Name, Device Address, Subnet Mask, Location,
    Access Port, OS, Username, Password

Usage:
    python list_network_devices.py [path_to_csv]

If no path is given, it defaults to "network_devices.csv" in the
current directory.
"""

import csv
import sys
from pathlib import Path


def read_devices(csv_path: str) -> list[dict]:
    """Read the network devices CSV and return a list of device dicts."""
    devices = []
    path = Path(csv_path)

    if not path.exists():
        raise FileNotFoundError(f"Could not find CSV file: {csv_path}")

    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Strip whitespace from all values (e.g. "Services " -> "Services")
            cleaned = {k: v.strip() if isinstance(v, str) else v for k, v in row.items()}
            devices.append(cleaned)

    return devices


def print_device_list(devices: list[dict]) -> None:
    """Print a readable summary list of devices."""
    print(f"{'ID':<6}{'Name':<10}{'Address':<16}{'Location':<10}{'Port':<7}{'OS':<14}")
    print("-" * 65)
    for d in devices:
        print(
            f"{d['Device ID']:<6}"
            f"{d['Device Name']:<10}"
            f"{d['Device Address']:<16}"
            f"{d['Location']:<10}"
            f"{d['Access Port']:<7}"
            f"{d['OS']:<14}"
        )
    print("-" * 65)
    print(f"Total devices: {len(devices)}")


def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "network_devices.csv"
    devices = read_devices(csv_path)
    print_device_list(devices)
    return devices


if __name__ == "__main__":
    main()