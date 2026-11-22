"""
check.network.py

Foundation script for the network monitoring project. Does two
things, printing results to the terminal for each:

    1. Ping / availability check on every required device.
    2. DNS configuration check on every required device -- retrieves
       each device's configured DNS server(s) over SSH and flags any
       device pointed at a non-internal (external) DNS server.

Which devices are checked
---------------------------
Only these devices are in scope for this project:

    PC1, PC2, PC3, PC4, SVR1, SVR2, API, DB, DNS1, DNS2

Excluded entirely (not checked, not connected to, not analyzed):

    SW1, SW2, SW3, SW4   - switches
    SMTP                 - SMTP endpoint only, no SSH, excluded per lab instructions
    ROUTER1              - out of scope for this project

How devices are reached
--------------------------
Ping / ICMP targets a device's actual network address where one
exists (the static IP devices: SVR1, SVR2, API, DB, DNS1, DNS2). For
the DHCP devices (PC1-PC4), there's no fixed address to send ICMP to,
so a TCP reachability check against localhost:<Access Port> is used
instead as the availability check -- confirming the GNS3 node process
itself is up and responding, even though what's listening there is a
telnet console, not SSH (see note below).

SSH-based checks (used for the DNS configuration check on static-IP
devices) connect directly to a device's own static IP on port 22 --
NOT through localhost/Access Port. Testing confirmed the CSV's
"Access Port" column is a GNS3 telnet console port (its banner starts
with the Telnet IAC byte 0xFF, not an SSH banner), so it cannot be
used as an SSH target.

For DHCP devices (PC1-PC4), which have no static IP for SSH, the DNS
configuration check instead connects to that same GNS3 console over
Telnet (localhost:<Access Port>), logs in if a login prompt appears,
and runs `resolvectl status` to read the device's actual DNS
configuration directly from its console.

    SSH target (static-IP DNS check)  = <Device Address> : 22
    Telnet target (DHCP DNS check)    = localhost : <Access Port>
    Availability check                = ICMP to Device Address (static),
                                         or TCP to localhost:<Access Port> (DHCP)

About the DNS stub resolver (127.0.0.53)
-------------------------------------------
Seeing "nameserver 127.0.0.53" in /etc/resolv.conf does NOT by itself
mean the DNS configuration is good or bad. It just means the device
is using systemd-resolved as a stub resolver -- a fixed local address
that always exists, which then looks up the REAL upstream DNS servers
at request time rather than using a static IP directly. So whenever
127.0.0.53 is detected, this script looks past it and asks
systemd-resolved (`resolvectl dns`) what the actual upstream DNS
server(s) are, and verifies THOSE against the internal DNS servers --
the stub address itself is never treated as a pass or fail signal.

Usage
-----
    python check.network.py network_devices.csv
    python check.network.py network_devices.csv --port-override 22

Requires
--------
    pip install paramiko
"""

import argparse
import csv
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import paramiko

# --------------------------------------------------------------------------
# Device scope
# --------------------------------------------------------------------------

IN_SCOPE_DEVICES = {"pc1", "pc2", "pc3", "pc4", "svr1", "svr2", "api", "db", "dns1", "dns2"}
INTERNAL_DNS_SERVERS = {"10.10.10.10", "10.10.10.20"}
STUB_RESOLVER_ADDRESS = "127.0.0.53"

PING_TIMEOUT_SEC = 2
PING_COUNT = 1
TCP_CHECK_TIMEOUT_SEC = 3
SSH_HOST = "localhost"
SSH_TIMEOUT = 10
TELNET_READ_TIMEOUT = 0.5
TELNET_IDLE_SEC = 1.5
TELNET_MAX_WAIT_SEC = 10


# --------------------------------------------------------------------------
# CSV loading
# --------------------------------------------------------------------------

def read_devices(csv_path: str) -> list[dict]:
    """Read the network devices CSV and return a list of device dicts."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Could not find CSV file: {csv_path}")

    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        devices = []
        for row in reader:
            cleaned = {k: (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
            devices.append(cleaned)
    return devices


def get_in_scope_devices(devices: list[dict]) -> list[dict]:
    return [d for d in devices if (d.get("Device Name") or "").strip().lower() in IN_SCOPE_DEVICES]


def is_static_address(address: str) -> bool:
    if not address or address.strip().lower() in ("dhcp", "none", ""):
        return False
    try:
        ipaddress.ip_address(address.strip())
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Requirement 1: Ping / availability check
# --------------------------------------------------------------------------

def ping_host(address: str, count: int = PING_COUNT, timeout: int = PING_TIMEOUT_SEC) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), address]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), address]

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 2
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def tcp_check(host: str, port: int, timeout: int = TCP_CHECK_TIMEOUT_SEC) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_availability(devices: list[dict]) -> list[dict]:
    """
    Check availability of every in-scope device. Static-IP devices are
    pinged via ICMP; DHCP devices (no fixed address) are checked via a
    TCP connection to their Access Port on localhost instead.
    """
    results = []
    for d in devices:
        name = d.get("Device Name", "")
        address = d.get("Device Address", "")

        try:
            access_port = int(d.get("Access Port"))
        except (TypeError, ValueError):
            access_port = None

        if is_static_address(address):
            method = f"ICMP ping to {address}"
            up = ping_host(address)
        elif access_port:
            method = f"TCP check to {SSH_HOST}:{access_port} (DHCP device, no static IP)"
            up = tcp_check(SSH_HOST, access_port)
        else:
            method = "no address or access port available"
            up = False

        results.append({"name": name, "address": address, "method": method, "up": up})

    return results


def print_availability_results(results: list[dict]) -> None:
    print("=" * 70)
    print("DEVICE AVAILABILITY CHECK")
    print("=" * 70)
    for r in results:
        status = "UP" if r["up"] else "DOWN"
        print(f"[{status}] {r['name']} ({r['address']}) - {r['method']}")

    up_count = sum(1 for r in results if r["up"])
    print("-" * 70)
    print(f"Up: {up_count}  Down: {len(results) - up_count}  Total: {len(results)}")


# --------------------------------------------------------------------------
# Requirement 2: DNS configuration check
# --------------------------------------------------------------------------

def connect_ssh(host: str, port: int, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username=username,
        password=password,
        timeout=SSH_TIMEOUT,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run_command(client: paramiko.SSHClient, command: str) -> tuple[str, str, int]:
    stdin, stdout, stderr = client.exec_command(command, timeout=SSH_TIMEOUT)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()
    return out, err, exit_code


def get_default_interface(client: paramiko.SSHClient) -> str:
    out, _, _ = run_command(client, "ip route show default")
    parts = out.split()
    if "dev" in parts:
        return parts[parts.index("dev") + 1]
    return "eth0"


def get_dns_configuration(client: paramiko.SSHClient) -> dict:
    """
    Read the device's DNS configuration and resolve past the stub
    resolver (127.0.0.53) to the real upstream DNS server(s) when
    present, since the stub address alone doesn't tell us anything
    about whether the DNS setup is correct.
    """
    resolv_out, _, _ = run_command(client, "cat /etc/resolv.conf 2>/dev/null")
    configured = [
        line.split()[1] for line in resolv_out.splitlines()
        if line.strip().startswith("nameserver") and len(line.split()) > 1
    ]

    stub_detected = configured == [STUB_RESOLVER_ADDRESS] or STUB_RESOLVER_ADDRESS in configured

    effective = configured
    if stub_detected:
        iface = get_default_interface(client)
        resolvectl_out, _, code = run_command(client, f"resolvectl dns {iface} 2>/dev/null")
        if code == 0 and resolvectl_out.strip():
            # Output looks like "eth0: 10.10.10.10 10.10.10.20"
            after_colon = resolvectl_out.split(":", 1)[-1]
            effective = after_colon.split()

    return {
        "configured": configured,
        "stub_detected": stub_detected,
        "effective": effective,
    }


# --------------------------------------------------------------------------
# Telnet-based DNS check (for DHCP devices with no SSH target)
# --------------------------------------------------------------------------
# PC1-4 have no static IP, and their CSV "Access Port" is a GNS3 console
# port speaking Telnet, not SSH (confirmed by the 0xFF/IAC byte in the
# banner). Rather than giving up on checking their DNS, this connects to
# that same console over Telnet, logs in, and runs `resolvectl status`
# directly -- getting a real, live answer instead of an N/A.

IAC, DONT, DO, WONT, WILL, SE, SB = 255, 254, 253, 252, 251, 240, 250


def _telnet_strip_negotiation(sock: socket.socket, data: bytes) -> bytes:
    """
    Strip Telnet IAC negotiation sequences out of a chunk of data, replying
    with a blanket refusal (WONT/DONT) to anything the server asks for.
    This keeps the session in plain character mode without needing a full
    telnet option-negotiation implementation.
    """
    clean = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte != IAC:
            clean.append(byte)
            i += 1
            continue

        if i + 1 >= len(data):
            break  # incomplete sequence at the end of this chunk, drop it

        cmd = data[i + 1]
        if cmd in (WILL, WONT, DO, DONT):
            if i + 2 >= len(data):
                break
            option = data[i + 2]
            try:
                if cmd == WILL:
                    sock.sendall(bytes([IAC, DONT, option]))
                elif cmd == DO:
                    sock.sendall(bytes([IAC, WONT, option]))
                # WONT/DONT from the server need no reply
            except OSError:
                pass
            i += 3
        elif cmd == SB:
            # Subnegotiation: skip until IAC SE
            end = data.find(bytes([IAC, SE]), i + 2)
            i = end + 2 if end != -1 else len(data)
        else:
            i += 2  # other 2-byte IAC commands (e.g. NOP)

    return bytes(clean)


def _telnet_read_until_idle(sock: socket.socket, idle: float = TELNET_IDLE_SEC, max_wait: float = TELNET_MAX_WAIT_SEC) -> str:
    """Read from the socket until output goes quiet for `idle` seconds."""
    sock.settimeout(TELNET_READ_TIMEOUT)
    buffer = bytearray()
    elapsed = 0.0
    idle_elapsed = 0.0

    while elapsed < max_wait and idle_elapsed < idle:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            chunk = b""
        except OSError:
            break

        if chunk:
            buffer.extend(_telnet_strip_negotiation(sock, chunk))
            idle_elapsed = 0.0
        else:
            idle_elapsed += TELNET_READ_TIMEOUT

        elapsed += TELNET_READ_TIMEOUT

    return buffer.decode(errors="replace")


SHELL_PROMPT_PATTERNS = ["$ ", "# "]

# A real bash-style prompt looks like "user@host:path$ " or "...# " for
# root. This is what "$ "/"# " in SHELL_PROMPT_PATTERNS actually means --
# checked via regex instead of a bare substring, because a bare "# "
# substring check false-positives on ANY comment line in file output
# (e.g. /etc/resolv.conf's standard header is full of lines starting
# with "# "), which would cut a read off mid-file.
_SHELL_PROMPT_RE = re.compile(r"[\w.\-]{1,64}@[\w.\-]{1,64}:[^\r\n]{0,120}[#$]\s*$")


def _tail_matches(text: str, patterns: list[str]) -> bool:
    """
    Check whether `text` ends with a real prompt/banner cue. Plain
    substrings (e.g. "login:", "password:") are matched literally at the
    tail. The shell-prompt markers ("$ " / "# ") are matched with a
    proper prompt-shaped regex instead, since a literal check is unsafe
    (see SHELL_PROMPT_PATTERNS note above).
    """
    tail = text[-300:]  # only need to look near the end; keeps regex cheap on large buffers
    lower_tail = tail.lower()

    for p in patterns:
        if p in ("$ ", "# "):
            if _SHELL_PROMPT_RE.search(tail):
                return True
        elif lower_tail.endswith(p):
            return True
    return False


def _telnet_wait_for(sock: socket.socket, patterns: list[str] | None, max_wait: float = 25.0, settle: float = 8.0) -> str:
    """
    Read until the buffer's TRAILING bytes look like one of `patterns`,
    then wait a short `settle` period to catch any immediately-trailing
    data, and return. This is far more reliable than a fixed timer for
    things like login prompts and MOTD banners, which vary a lot in
    how long they take to actually appear.

    Matching happens only against the tail of what's been received so
    far (via _tail_matches), never "anywhere in the buffer" -- see
    _tail_matches / SHELL_PROMPT_PATTERNS for why that distinction
    matters.

    If nothing matches, keeps reading (best-effort) until `max_wait` is
    hit and returns whatever was captured, rather than raising -- a
    partial capture still gets surfaced in the raw debug output.
    """
    sock.settimeout(TELNET_READ_TIMEOUT)
    buffer = bytearray()
    elapsed = 0.0
    matched_at = None

    while elapsed < max_wait:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            chunk = b""
        except OSError:
            break

        if chunk:
            buffer.extend(_telnet_strip_negotiation(sock, chunk))
            if patterns:
                text = buffer.decode(errors="replace")
                if _tail_matches(text, patterns):
                    matched_at = elapsed
                else:
                    # New data arrived that ISN'T a trailing prompt --
                    # whatever matched before wasn't actually the end of
                    # output, so keep waiting.
                    matched_at = None
        elif matched_at is not None and (elapsed - matched_at) >= settle:
            break  # matched, and it's been quiet since -- confident we're done

        elapsed += TELNET_READ_TIMEOUT

    return buffer.decode(errors="replace")


def _telnet_send_line(sock: socket.socket, text: str) -> None:
    sock.sendall((text + "\r\n").encode())


def _telnet_clear_line(sock: socket.socket) -> None:
    """Send Ctrl+U to clear any stray leftover input sitting on the
    current line (e.g. a half-typed command from a previous session
    still buffered in the console) before typing a fresh command."""
    sock.sendall(bytes([0x15]))


_ANSI_ESCAPE_RE = re.compile(
    r"\x1b\[[0-9;?]*[a-zA-Z]"      # CSI sequences (cursor moves, colors, etc.)
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences (terminal title, etc.)
    r"|\x1b[=>]"                    # keypad mode switches
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f]"  # stray control chars (not \t \n \r)
)


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE_RE.sub("", text)


_DNS_LINE_RE = re.compile(
    r"(?:current\s+dns\s+server|dns\s+servers?)\s*:\s*([0-9.\s]+)",
    re.IGNORECASE,
)


def _extract_dns_ips(text: str) -> list[str]:
    """Find every DNS-server IP mentioned in `resolvectl status` output,
    tolerant of ANSI noise and line-wrapping since it searches the whole
    cleaned text rather than requiring exact per-line prefixes."""
    cleaned = _strip_ansi(text)
    ips = []
    for match in _DNS_LINE_RE.finditer(cleaned):
        for tok in match.group(1).split():
            if tok.count(".") == 3:
                ips.append(tok)
    seen = set()
    return [ip for ip in ips if not (ip in seen or seen.add(ip))]


def _extract_resolv_conf_ips(text: str) -> list[str]:
    cleaned = _strip_ansi(text)
    ips = []
    for line in cleaned.splitlines():
        stripped = line.strip()
        if stripped.startswith("nameserver"):
            parts = stripped.split()
            if len(parts) > 1 and parts[1].count(".") == 3:
                ips.append(parts[1])
    seen = set()
    return [ip for ip in ips if not (ip in seen or seen.add(ip))]


def _telnet_login(sock: socket.socket, username: str, password: str) -> None:
    """
    Connect-time login handshake: waits for a login prompt if one
    appears and logs in, otherwise assumes the console is already
    sitting at a shell prompt (common for GNS3, since it's the same
    persistent VM console across reconnects).
    """
    banner = _telnet_wait_for(sock, ["login:", "username:"] + SHELL_PROMPT_PATTERNS, max_wait=30)
    if "login:" in banner.lower() or "username:" in banner.lower():
        _telnet_send_line(sock, username)
        after_user = _telnet_wait_for(sock, ["password:"], max_wait=20)
        if "password:" in after_user.lower():
            _telnet_send_line(sock, password)
            # Wait for the actual shell prompt to reappear -- this is
            # what actually finishes, however long the MOTD/update
            # banner takes, instead of guessing a fixed duration.
            _telnet_wait_for(sock, SHELL_PROMPT_PATTERNS, max_wait=40)


def _telnet_run_command(sock: socket.socket, command: str, max_wait: float = 15.0) -> str:
    """
    Run a single command at the shell prompt (clearing any stray input
    and forcing a fresh prompt first) and return its output.
    """
    _telnet_clear_line(sock)
    _telnet_send_line(sock, "")
    _telnet_wait_for(sock, SHELL_PROMPT_PATTERNS, max_wait=15)

    _telnet_send_line(sock, command)
    return _telnet_wait_for(sock, SHELL_PROMPT_PATTERNS, max_wait=max_wait)


def _resolvectl_looks_broken(output: str) -> bool:
    """
    Detect resolvectl actually failing, anchored to the specific error
    shapes we've observed (D-Bus/service errors, "command not found") --
    NOT a bare "failed" or "not found" substring check, which is unsafe:
    normal resolvectl status output can legitimately contain words like
    "unsupported" or per-link notes that a loose substring match could
    misfire on, wrongly treating a working device as broken.
    """
    patterns = [
        r"failed to get (global|link) data",
        r"dbus[-.]org\.freedesktop\.resolve1",
        r"unit .*resolve1.*not found",
        r"resolvectl:\s*command not found",
        r"bash:.*resolvectl.*not found",
    ]
    return any(re.search(p, output, re.IGNORECASE) for p in patterns)


def get_dns_configuration_via_telnet(host: str, port: int, username: str, password: str) -> dict:
    """
    Connect to a device's GNS3 console over Telnet, log in if needed, and
    read its actual DNS configuration -- preferring `resolvectl status`,
    falling back to `/etc/resolv.conf` if resolvectl itself isn't working
    (e.g. systemd-resolved's D-Bus service isn't registered).

    Waits are prompt-driven rather than fixed timers: each step waits
    until it actually sees the prompt/banner it's expecting (login:,
    Password:, or a shell prompt), since these consoles vary a lot in
    how long they take to respond -- a fixed timer either wastes time
    or, worse, cuts off before the real output arrives.
    """
    with socket.create_connection((host, port), timeout=SSH_TIMEOUT) as sock:
        _telnet_login(sock, username, password)

        output = _telnet_run_command(sock, "resolvectl status", max_wait=70)

        effective = _extract_dns_ips(output)
        stub_detected = False
        combined_output = output

        if not effective or _resolvectl_looks_broken(output):
            # resolvectl gave us nothing usable -- fall back to reading
            # /etc/resolv.conf directly over the same session.
            resolv_output = _telnet_run_command(sock, "cat /etc/resolv.conf", max_wait=50)
            combined_output += "\n--- cat /etc/resolv.conf ---\n" + resolv_output

            configured = _extract_resolv_conf_ips(resolv_output)
            stub_detected = configured == [STUB_RESOLVER_ADDRESS] or STUB_RESOLVER_ADDRESS in configured

            if stub_detected and len(configured) == 1:
                # Only the stub resolver is configured and resolvectl (the
                # only way to see past it) isn't working -- we genuinely
                # can't determine the real upstream DNS servers here.
                effective = []
            else:
                effective = configured

    return {
        "configured": effective,
        "stub_detected": stub_detected,
        "effective": effective,
        "raw_output": combined_output,
    }


def get_dns_configuration_via_telnet_confirmed(
    host: str, port: int, username: str, password: str, attempts: int = 3, delay: float = 2.0
) -> dict:
    """
    Like get_dns_configuration_via_telnet, but re-checks up to `attempts`
    times to filter out transient read glitches on a Telnet console (a
    read that happens to land mid-transmission can come back looking
    empty/wrong even though the device's actual DNS config is fine).

    If ANY attempt reports the DNS servers matching the expected
    internal servers, that result is trusted immediately -- a flaky
    read coming back empty on a later attempt shouldn't override a
    good one that already confirmed the config is correct. Only if
    EVERY attempt agrees the config is something else (or empty) is
    that treated as the real, final result.
    """
    last_result = None
    for attempt in range(attempts):
        result = get_dns_configuration_via_telnet(host, port, username, password)
        last_result = result
        status, _ = classify_dns(result)
        if status == "OK":
            return result
        if attempt < attempts - 1:
            time.sleep(delay)
    return last_result


def correct_dns_via_telnet(host: str, port: int, username: str, password: str) -> dict:
    """
    Connect to a DHCP device's GNS3 console over Telnet and correct its
    DNS configuration to point at the internal DNS servers. Mirrors
    correct.dns.settings.py's SSH-based correct_dns_ubuntu(), but over
    Telnet for devices (PC1-4) that have no SSH target.

    Tries `resolvectl dns <iface> ...` first, but skips straight to
    editing /etc/resolv.conf directly if resolvectl is already known to
    be broken (e.g. the PC2/PC3 case where systemd-resolved's D-Bus
    service isn't registered) -- no point retrying a command that just
    failed on the read side too. Finishes with a live `getent hosts`
    lookup to prove DNS actually works end-to-end, not just that the
    config file looks right.
    """
    target_ips = sorted(INTERNAL_DNS_SERVERS)
    result = {"method": None, "before": None, "after": None, "resolved": None, "error": None}

    with socket.create_connection((host, port), timeout=SSH_TIMEOUT) as sock:
        _telnet_login(sock, username, password)

        # --- Capture "before" state ---
        status_before = _telnet_run_command(sock, "resolvectl status", max_wait=70)
        resolvectl_broken = _resolvectl_looks_broken(status_before)
        before_ips = _extract_dns_ips(status_before)

        if not before_ips or resolvectl_broken:
            resolv_before = _telnet_run_command(sock, "cat /etc/resolv.conf", max_wait=50)
            before_ips = _extract_resolv_conf_ips(resolv_before)

        result["before"] = ", ".join(before_ips) if before_ips else "none configured"

        # --- Correct it ---
        if not resolvectl_broken:
            iface_out = _telnet_run_command(sock, "ip route show default", max_wait=15)
            iface_parts = iface_out.split()
            iface = iface_parts[iface_parts.index("dev") + 1] if "dev" in iface_parts else "eth0"

            result["method"] = f"resolvectl (interface {iface})"
            cmd = f"echo {password!r} | sudo -S resolvectl dns {iface} {' '.join(target_ips)} 2>&1"
            correction_out = _telnet_run_command(sock, cmd, max_wait=30)

            if _resolvectl_looks_broken(correction_out):
                resolvectl_broken = True  # the correction command itself failed

        if resolvectl_broken:
            result["method"] = "/etc/resolv.conf"
            resolv_contents = "\\n".join(f"nameserver {ip}" for ip in target_ips)
            cmd = f"echo {password!r} | sudo -S bash -c \"printf '{resolv_contents}\\n' > /etc/resolv.conf\" 2>&1"
            _telnet_run_command(sock, cmd, max_wait=30)

        # --- Verify "after" state ---
        # Retry a few times: a read landing mid-transmission can come
        # back looking like the servers aren't there even though the
        # change actually succeeded, so don't trust a single failed
        # read as proof the correction didn't work.
        after_ips = []
        for attempt in range(3):
            status_after = _telnet_run_command(sock, "resolvectl status", max_wait=70)
            after_ips = _extract_dns_ips(status_after)

            if not after_ips or _resolvectl_looks_broken(status_after):
                resolv_after = _telnet_run_command(sock, "cat /etc/resolv.conf", max_wait=50)
                after_ips = _extract_resolv_conf_ips(resolv_after)

            if all(ip in after_ips for ip in target_ips):
                break
            if attempt < 2:
                time.sleep(2.0)

        result["after"] = ", ".join(after_ips) if after_ips else "none configured"

        all_present = all(ip in after_ips for ip in target_ips)
        if not all_present:
            result["error"] = "DNS servers not present in config after update."
            return result

        # --- Prove it actually works, not just that the config looks right ---
        lookup_out = _telnet_run_command(sock, "getent hosts example.com", max_wait=20)
        # A successful `getent hosts` lookup can return either an IPv4 or
        # IPv6 address depending on what's available -- both count as a
        # working resolution, so check for either rather than IPv4 only.
        has_ipv4 = bool(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", lookup_out))
        has_ipv6 = bool(re.search(r"\b[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,}\b", lookup_out))
        resolved = (has_ipv4 or has_ipv6) and "no such" not in lookup_out.lower()
        result["resolved"] = resolved
        if not resolved:
            snippet = lookup_out.strip().replace("\n", " ")[:200]
            result["error"] = f"Config updated but live lookup of example.com failed. Output: {snippet}"

    return result


def classify_dns(dns_info: dict) -> tuple[str, str]:
    effective = dns_info["effective"]

    if not effective:
        if dns_info.get("stub_detected"):
            return (
                "UNKNOWN",
                "Device uses the systemd-resolved stub (127.0.0.53) but the real "
                "upstream DNS server(s) could not be determined (resolvectl unavailable).",
            )
        return "UNKNOWN", "No DNS server could be determined from this device's configuration."

    external = [ip for ip in effective if ip not in INTERNAL_DNS_SERVERS and ip not in ("127.0.0.1", STUB_RESOLVER_ADDRESS)]

    if external:
        return "MISCONFIGURED", f"Device is using non-internal DNS server(s): {', '.join(external)}"

    return "OK", f"DNS server(s) confirmed internal: {', '.join(effective)}"


def check_dns_device(device: dict, port_override) -> dict:
    name = device.get("Device Name", "")
    address = device.get("Device Address", "")
    username = device.get("Username", "")
    password = device.get("Password", "")

    if not is_static_address(address):
        # DHCP devices (PC1-4) have no static IP, so there's no SSH
        # target -- fall back to the GNS3 console (Telnet) on the
        # device's own Access Port and read DNS via `resolvectl status`.
        try:
            access_port = int(device.get("Access Port"))
        except (TypeError, ValueError):
            return {
                "name": name, "address": address, "connected": False,
                "error": "No valid Access Port in CSV for Telnet console check.",
            }

        result = {"name": name, "address": address, "port": access_port, "connected": False, "error": None}

        try:
            dns_info = get_dns_configuration_via_telnet_confirmed(SSH_HOST, access_port, username, password)
            result["connected"] = True
            status, detail = classify_dns(dns_info)
            result.update({"dns_info": dns_info, "status": status, "detail": detail})
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"Telnet console check failed: {exc}"

        return result

    port = port_override if port_override else 22
    result = {"name": name, "address": address, "port": port, "connected": False, "error": None}

    try:
        client = connect_ssh(address, port, username, password)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"SSH connection failed: {exc}"
        return result

    try:
        result["connected"] = True
        dns_info = get_dns_configuration(client)
        status, detail = classify_dns(dns_info)
        result.update({"dns_info": dns_info, "status": status, "detail": detail})
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"DNS configuration check failed: {exc}"
    finally:
        client.close()

    return result


def check_dns_configurations(devices: list[dict], port_override=None) -> list[dict]:
    return [check_dns_device(d, port_override) for d in devices]


def print_dns_results(results: list[dict]) -> None:
    print("\n" + "=" * 70)
    print("DNS CONFIGURATION CHECK")
    print("=" * 70)

    for r in results:
        label = f"{r['name']} ({r['address']})"

        if not r["connected"]:
            label_tag = "N/A" if r["error"].startswith("N/A") else "UNREACHABLE"
            print(f"[{label_tag}] {label} - {r['error']}")
            continue

        stub_note = ""
        if r["dns_info"]["stub_detected"]:
            stub_note = (
                f" [stub resolver {STUB_RESOLVER_ADDRESS} detected -> "
                f"resolved actual upstream: {', '.join(r['dns_info']['effective']) or 'none found'}]"
            )

        if r["status"] == "MISCONFIGURED":
            print(f"[MISCONFIGURED] {label} - {r['detail']}{stub_note}")
        elif r["status"] == "OK":
            print(f"[OK] {label} - {r['detail']}{stub_note}")
        else:
            print(f"[UNKNOWN] {label} - {r['detail']}{stub_note}")
            raw = r["dns_info"].get("raw_output")
            if raw is not None:
                print("    --- raw console output (for debugging) ---")
                for line in raw.splitlines():
                    print(f"    {line}")
                print("    -------------------------------------------")

    checked = [r for r in results if r["connected"]]
    misconfigured = sum(1 for r in checked if r["status"] == "MISCONFIGURED")
    ok = sum(1 for r in checked if r["status"] == "OK")
    not_applicable = sum(1 for r in results if not r["connected"] and r["error"].startswith("N/A"))
    unreachable = len(results) - len(checked) - not_applicable
    print("-" * 70)
    print(f"OK: {ok}  Misconfigured: {misconfigured}  N/A: {not_applicable}  Unreachable: {unreachable}  Total: {len(results)}")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Check availability and DNS configuration for in-scope network devices.")
    parser.add_argument("csv_path", nargs="?", default="network_devices.csv", help="Path to the network devices CSV file")
    parser.add_argument("--port-override", type=int, default=None, help="Force a specific SSH port for the DNS configuration check instead of the default port 22")
    args = parser.parse_args()

    all_devices = read_devices(args.csv_path)
    devices = get_in_scope_devices(all_devices)

    if not devices:
        print("No in-scope devices found in the CSV.")
        return

    availability_results = check_availability(devices)
    print_availability_results(availability_results)

    dns_results = check_dns_configurations(devices, args.port_override)
    print_dns_results(dns_results)

    return availability_results, dns_results


if __name__ == "__main__":
    main()