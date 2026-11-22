# Network Incident Monitoring & Ticketing Automation

A Python tool that watches a simulated 10 device network, detects outages, opens a helpdesk ticket through a REST API, notifies stakeholders by email, and closes the ticket once the issue is fixed and verified. Built and tested in a GNS3 lab with Ubuntu Linux.

**Tools:** Python, GNS3, Ubuntu Linux, SSH, Telnet, REST API, SMTP email

---

## What it does

This project covers the full incident lifecycle the way a help desk or NOC team handles it:

1. **Detect:** checks every device on a schedule with ping and TCP port checks.
2. **Ticket:** opens a helpdesk ticket through a REST API when a device goes down.
3. **Notify:** sends a templated email with the device name, IP address, and time of the last successful check.
4. **Fix:** connects to the affected machine, diagnoses the problem, and applies the fix.
5. **Verify and close:** confirms the fix with a live test, then closes the ticket as resolved.

## Features

- **Availability monitoring:** ping and TCP checks run around the clock across all 10 devices.
- **Ticket automation:** incidents are opened and closed through a helpdesk REST API.
- **Templated email alerts:** every outage notification includes the device name, IP address, and last check time.
- **Duplicate suppression:** a long outage produces one alert and one ticket, not one per check.
- **Remote access:** SSH for workstations, and Telnet console sessions for PCs that use DHCP addressing and have no SSH access.
- **Health log:** a timestamped record of devices confirmed healthy, useful for checking against when users report problems.

## Lab environment

| Item | Details |
|---|---|
| Simulator | GNS3 |
| Devices | 10 (Ubuntu workstations and servers, plus [routers / switches / DHCP PCs, fill in]) |
| Internal DNS servers | 10.10.10.10 and 10.10.10.20 |
| Monitoring host | Ubuntu Linux running the Python scripts |



## Example incident: DNS misconfiguration

**Problem:** Ubuntu workstations could reach devices by IP address but could not resolve names.

**Diagnosis:** connected over SSH and found the machines pointing at the wrong DNS server.

**Fix:** restored the internal DNS servers (10.10.10.10 / 10.10.10.20).

**Verification:** ran a live name resolution test and confirmed it succeeded before closing the ticket.


## Project structure


├── monitor.py          # availability checks
├── tickets.py          # REST API ticket open and close
├── notify.py           # email templates and sending
├── config.example.py   # sample settings, no real credentials
└── README.md


## Setup and usage

```bash
# 1. Clone the repo
git clone https://github.com/reptiliansobe/network.incident.monitoring.git
cd network.incident.monitoring

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy the example config and add your own values
cp config.example.py config.py

# 4. Run the monitor
python3 [your main script name].py
```

Settings such as device IPs, the ticketing API address, and email server details are kept in a config file. **No credentials are stored in this repository.**

## What I learned

- How an incident moves from detection to resolution, and why each stage needs a clear record.
- Troubleshooting DNS and DHCP problems on Linux from the command line.
- Automating repetitive help desk work with Python and a REST API.
- Reducing alert noise so one real problem produces one clear notification.

## About

Built by Bryan Rascon as a hands on IT automation project
[LinkedIn](https://linkedin.com/in/bryanrascon)
