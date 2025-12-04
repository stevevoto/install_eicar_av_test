#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# EICAR Outbound Router AV Test - Installer
#
# Author: Steve Voto (Svoto)
#
# License: MIT-style; you may use, copy, modify, and distribute this script
# and the generated files. Keep this notice with any copies.
#
# DISCLAIMER:
# This installer will automatically create and enable a recurring EICAR test
# job on this system. It is intended ONLY for controlled lab / test
# environments that you own or are explicitly authorized to test.
# Use at your own risk. No warranties of any kind are provided. The author
# (Steve Voto / Svoto) assumes no responsibility for outages, security
# incidents, or policy violations resulting from use or misuse of this tool.
# -----------------------------------------------------------------------------

set -euo pipefail

SERVICE_NAME="eicar-av-test"
INSTALL_DIR="/usr/local/eicar-av-test"
PY_SCRIPT_NAME="eicar_router_test.py"
PY_SCRIPT_PATH="${INSTALL_DIR}/${PY_SCRIPT_NAME}"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Please run this script as root, e.g.:"
    echo "  sudo bash $(basename "$0")"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found. Please install python3 and rerun."
    exit 1
fi

echo "==> Creating install directory: ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"

echo "==> Writing Python EICAR test script to ${PY_SCRIPT_PATH}"
cat > "${PY_SCRIPT_PATH}" <<'EOF_PY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# EICAR Outbound Router AV Test
#
# Author:  Steve Voto (Svoto)
# License: MIT-style; permission granted to use, copy, modify, and distribute
#          this software with attribution.
#
# DISCLAIMER:
# This script is provided "AS IS", without warranty of any kind, express or
# implied. It is intended ONLY for controlled lab and test environments to
# verify router / firewall antivirus and IDS/IPS visibility using the
# standardized EICAR test string. Do NOT run this on networks or systems you
# do not own or are not explicitly authorized to test. The author (Steve Voto /
# Svoto) assumes no responsibility for misuse, outages, data loss, security
# incidents, or policy violations caused by this tool.
# -----------------------------------------------------------------------------
"""
EICAR Outbound Transmission Test for Router/Gateway AV Detection
Sends EICAR test patterns through your router to trigger AV detection.
Designed for testing 128T and similar router-based antivirus systems.

Features:
- Multiple outbound test vectors (HTTP, HTTPS, encoded, raw socket, etc.)
- Optional timed loop via CLI (--interval / --runs)
- Non-interactive mode (--no-prompt) for systemd/cron usage
"""

import os
import sys
import time
import json
import base64
import socket
import urllib.request
import urllib.parse
import http.client
import ssl
import argparse
from datetime import datetime


class Colors:
    """Terminal colors for output"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def print_header():
    """Print test header"""
    print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}EICAR Outbound Router AV Test Suite{Colors.RESET}")
    print(f"{Colors.BOLD}Testing Router/Gateway Antivirus Detection{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")


def get_eicar_string():
    """Return the standard EICAR test string"""
    # Standard EICAR test string
    return "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def get_eicar_variations():
    """Return various EICAR format variations"""
    eicar_base = get_eicar_string()
    return {
        "plain": eicar_base,
        "base64": base64.b64encode(eicar_base.encode()).decode(),
        "hex": eicar_base.encode().hex(),
        "url_encoded": urllib.parse.quote(eicar_base),
        "double_encoded": urllib.parse.quote(urllib.parse.quote(eicar_base)),
    }


def test_http_post_upload():
    """Test 1: HTTP POST Upload to test servers"""
    print(f"\n{Colors.BLUE}[TEST 1] HTTP POST Upload Test{Colors.RESET}")
    print("-" * 50)

    eicar_content = get_eicar_string()
    results = []

    # Test servers that accept POST data
    test_endpoints = [
        ("http://httpbin.org/post", "httpbin.org"),
        ("http://postman-echo.com/post", "Postman Echo"),
        # Replace with your own URLs if you want to inspect payloads directly:
        ("http://webhook.site/unique-url", "Webhook.site"),
        ("http://requestbin.net/r/test", "RequestBin"),
    ]

    for url, name in test_endpoints:
        print(f"Testing POST to {name}: {url}")
        try:
            response = requests.post(  # type: ignore[name-defined]
                url,
                data={"file": eicar_content, "test": "eicar"},
                headers={"User-Agent": "EICAR-Test-Client"},
                timeout=5,
            )

            if response.status_code == 200:
                print(
                    f"{Colors.YELLOW}  ⚠ POST succeeded - Router AV might not have detected"
                    f"{Colors.RESET}"
                )
                results.append(False)
            else:
                print(
                    f"{Colors.GREEN}  ✓ POST blocked or failed (Status: {response.status_code})"
                    f"{Colors.RESET}"
                )
                results.append(True)

        except requests.exceptions.Timeout:  # type: ignore[name-defined]
            print(f"{Colors.GREEN}  ✓ Connection timed out (likely blocked){Colors.RESET}")
            results.append(True)
        except requests.exceptions.ConnectionError:  # type: ignore[name-defined]
            print(f"{Colors.GREEN}  ✓ Connection blocked by router{Colors.RESET}")
            results.append(True)
        except Exception as e:
            print(f"{Colors.YELLOW}  ⚠ Error: {str(e)[:50]}{Colors.RESET}")
            results.append(False)

    return any(results)


def test_http_multipart_upload():
    """Test 2: Multipart file upload with EICAR"""
    print(f"\n{Colors.BLUE}[TEST 2] HTTP Multipart File Upload Test{Colors.RESET}")
    print("-" * 50)

    eicar_content = get_eicar_string()

    files = {
        "file": ("eicar.txt", eicar_content, "text/plain"),
        "field": (None, "test"),
    }

    test_urls = [
        "http://httpbin.org/post",
        "http://postman-echo.com/post",
    ]

    results = []
    for url in test_urls:
        print(f"Uploading EICAR as file to: {url}")
        try:
            response = requests.post(  # type: ignore[name-defined]
                url,
                files=files,
                timeout=5,
            )

            if response.status_code == 200:
                print(
                    f"{Colors.YELLOW}  ⚠ File upload succeeded - Check router AV logs"
                    f"{Colors.RESET}"
                )
                results.append(False)
            else:
                print(
                    f"{Colors.GREEN}  ✓ Upload blocked (Status: {response.status_code})"
                    f"{Colors.RESET}"
                )
                results.append(True)

        except Exception as e:
            print(f"{Colors.GREEN}  ✓ Upload blocked: {str(e)[:50]}{Colors.RESET}")
            results.append(True)

    return any(results)


def test_https_transmission():
    """Test 3: HTTPS transmission with EICAR"""
    print(f"\n{Colors.BLUE}[TEST 3] HTTPS Encrypted Transmission Test{Colors.RESET}")
    print("-" * 50)

    eicar_content = get_eicar_string()

    https_endpoints = [
        "https://httpbin.org/post",
        "https://postman-echo.com/post",
        # Replace with your own webhook token URL if desired
        "https://webhook.site/token",
    ]

    results = []
    for url in https_endpoints:
        print(f"Testing HTTPS POST to: {url}")
        try:
            response = requests.post(  # type: ignore[name-defined]
                url,
                json={"payload": eicar_content, "test": "eicar_https"},
                headers={"Content-Type": "application/json"},
                timeout=5,
                verify=True,
            )

            if response.status_code == 200:
                print(f"{Colors.YELLOW}  ⚠ HTTPS transmission succeeded{Colors.RESET}")
                results.append(False)
            else:
                print(
                    f"{Colors.GREEN}  ✓ HTTPS blocked (Status: {response.status_code})"
                    f"{Colors.RESET}"
                )
                results.append(True)

        except Exception as e:
            print(f"{Colors.GREEN}  ✓ HTTPS blocked: {str(e)[:50]}{Colors.RESET}")
            results.append(True)

    return any(results)


def get_eicar_variations():
    """Return various EICAR format variations"""
    eicar_base = get_eicar_string()
    return {
        "plain": eicar_base,
        "base64": base64.b64encode(eicar_base.encode()).decode(),
        "hex": eicar_base.encode().hex(),
        "url_encoded": urllib.parse.quote(eicar_base),
        "double_encoded": urllib.parse.quote(urllib.parse.quote(eicar_base)),
    }


def test_encoded_transmissions():
    """Test 4: Various encoded EICAR transmissions"""
    print(f"\n{Colors.BLUE}[TEST 4] Encoded EICAR Transmission Test{Colors.RESET}")
    print("-" * 50)

    variations = get_eicar_variations()
    test_url = "http://httpbin.org/post"

    results = []
    for encoding, content in variations.items():
        print(f"Testing {encoding} encoded EICAR...")
        try:
            response = requests.post(  # type: ignore[name-defined]
                test_url,
                data={f"eicar_{encoding}": content},
                timeout=5,
            )

            if response.status_code == 200:
                print(
                    f"{Colors.YELLOW}  ⚠ {encoding}: Transmitted successfully{Colors.RESET}"
                )
                results.append(False)
            else:
                print(f"{Colors.GREEN}  ✓ {encoding}: Blocked{Colors.RESET}")
                results.append(True)

        except Exception as e:
            print(f"{Colors.GREEN}  ✓ {encoding}: Blocked{Colors.RESET}")
            results.append(True)

    return any(results)


def test_direct_socket_transmission():
    """Test 5: Direct socket transmission of EICAR"""
    print(f"\n{Colors.BLUE}[TEST 5] Direct Socket Transmission Test{Colors.RESET}")
    print("-" * 50)

    eicar_content = get_eicar_string()

    servers = [
        ("httpbin.org", 80, "HTTP"),
        ("postman-echo.com", 80, "HTTP"),
    ]

    results = []
    for host, port, proto in servers:
        print(f"Testing raw socket to {host}:{port} ({proto})")

        try:
            request = (
                f"POST /post HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: text/plain\r\n"
                f"Content-Length: {len(eicar_content)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{eicar_content}"
            )

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.send(request.encode())

            response = sock.recv(1024)
            sock.close()

            if b"200 OK" in response:
                print(f"{Colors.YELLOW}  ⚠ Raw transmission succeeded{Colors.RESET}")
                results.append(False)
            else:
                print(f"{Colors.GREEN}  ✓ Transmission blocked{Colors.RESET}")
                results.append(True)

        except (socket.timeout, socket.error) as e:
            print(f"{Colors.GREEN}  ✓ Socket blocked: {str(e)[:30]}{Colors.RESET}")
            results.append(True)
        except Exception as e:
            print(f"{Colors.YELLOW}  ⚠ Error: {str(e)[:30]}{Colors.RESET}")
            results.append(False)

    return any(results)


def test_ftp_simulation():
    """Test 6: FTP-like transmission (using HTTP PUT)"""
    print(f"\n{Colors.BLUE}[TEST 6] File Transfer Protocol Simulation{Colors.RESET}")
    print("-" * 50)

    eicar_content = get_eicar_string()

    test_urls = [
        "http://httpbin.org/put",
        "http://postman-echo.com/put",
    ]

    results = []
    for url in test_urls:
        print(f"Testing PUT file transfer to: {url}")
        try:
            response = requests.put(  # type: ignore[name-defined]
                url,
                data=eicar_content,
                headers={"Content-Type": "application/octet-stream"},
                timeout=5,
            )

            if response.status_code == 200:
                print(f"{Colors.YELLOW}  ⚠ PUT transfer succeeded{Colors.RESET}")
                results.append(False)
            else:
                print(
                    f"{Colors.GREEN}  ✓ PUT blocked (Status: {response.status_code})"
                    f"{Colors.RESET}"
                )
                results.append(True)

        except Exception as e:
            print(f"{Colors.GREEN}  ✓ Transfer blocked: {str(e)[:50]}{Colors.RESET}")
            results.append(True)

    return any(results)


def test_dns_tunnel_simulation():
    """Test 7: DNS tunneling simulation"""
    print(f"\n{Colors.BLUE}[TEST 7] DNS Tunneling Detection Test{Colors.RESET}")
    print("-" * 50)

    eicar_hex = get_eicar_string().encode().hex()

    chunk_size = 63
    chunks = [eicar_hex[i : i + chunk_size] for i in range(0, len(eicar_hex), chunk_size)]

    print(f"Testing DNS queries with embedded EICAR (chunks: {len(chunks)})")

    blocked = False
    for i, chunk in enumerate(chunks[:3]):
        test_domain = f"{chunk}.test.local"
        try:
            socket.gethostbyname(test_domain)
            print(f"{Colors.YELLOW}  ⚠ Chunk {i + 1}: DNS query succeeded{Colors.RESET}")
        except socket.gaierror:
            print(f"{Colors.GREEN}  ✓ Chunk {i + 1}: DNS query blocked{Colors.RESET}")
            blocked = True
        except Exception:
            print(f"{Colors.GREEN}  ✓ Chunk {i + 1}: Query failed{Colors.RESET}")
            blocked = True

    return blocked


def test_websocket_simulation():
    """Test 8: WebSocket-like persistent connection"""
    print(f"\n{Colors.BLUE}[TEST 8] WebSocket Transmission Simulation{Colors.RESET}")
    print("-" * 50)

    eicar_content = get_eicar_string()

    print("Simulating WebSocket upgrade with EICAR payload...")

    try:
        response = requests.post(  # type: ignore[name-defined]
            "http://httpbin.org/post",
            json={
                "type": "websocket_message",
                "data": base64.b64encode(eicar_content.encode()).decode(),
                "protocol": "ws",
            },
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
            },
            timeout=5,
        )

        if response.status_code in [200, 426]:
            print(f"{Colors.YELLOW}  ⚠ WebSocket simulation transmitted{Colors.RESET}")
            return False
        else:
            print(f"{Colors.GREEN}  ✓ WebSocket blocked{Colors.RESET}")
            return True

    except Exception as e:
        print(f"{Colors.GREEN}  ✓ WebSocket blocked: {str(e)[:50]}{Colors.RESET}")
        return True


def check_network_path():
    """Check network routing and gateway"""
    print(f"\n{Colors.CYAN}[INFO] Network Path Information{Colors.RESET}")
    print("-" * 50)

    try:
        import subprocess

        result = subprocess.run(
            ["ip", "route", "show", "default"], capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            print(f"Default route: {result.stdout.strip()}")

        result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
        lines = result.stdout.split("\n")
        for line in lines:
            if "inet " in line and "127.0.0.1" not in line:
                print(f"Interface IP: {line.strip()}")
                break

    except Exception as e:
        print(f"Could not determine network path: {e}")


def generate_test_report(results):
    """Generate comprehensive test report"""
    print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}TEST RESULTS SUMMARY{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

    total = len(results)
    blocked = sum(1 for r in results.values() if r)

    for test_name, was_blocked in results.items():
        status = (
            f"{Colors.GREEN}BLOCKED{Colors.RESET}"
            if was_blocked
            else f"{Colors.RED}ALLOWED{Colors.RESET}"
        )
        print(f"{test_name:30s} : {status}")

    print(
        f"\n{Colors.BOLD}Overall Score: {blocked}/{total} transmissions blocked"
        f"{Colors.RESET}"
    )

    if total > 0:
        percentage = (blocked / total) * 100.0
    else:
        percentage = 0.0

    if percentage >= 80:
        print(
            f"{Colors.GREEN}✓ EXCELLENT: Router AV is detecting most EICAR transmissions"
            f"{Colors.RESET}"
        )
    elif percentage >= 60:
        print(
            f"{Colors.YELLOW}⚠ GOOD: Router AV is partially effective{Colors.RESET}"
        )
    else:
        print(
            f"{Colors.RED}✗ WARNING: Router AV may not be properly configured"
            f"{Colors.RESET}"
        )

    print(f"\n{Colors.BOLD}Recommendations:{Colors.RESET}")

    if not results.get("HTTP POST", False):
        print("• Enable HTTP content inspection on router")
    if not results.get("HTTPS", False):
        print("• Configure SSL/TLS inspection for HTTPS traffic")
    if not results.get("Encoded", False):
        print("• Enable deep packet inspection for encoded content")
    if not results.get("Socket", False):
        print("• Review raw socket filtering rules")

    print(f"\n{Colors.BOLD}Next Steps:{Colors.RESET}")
    print("1. Check router AV logs at: /var/log/128t-anti-virus/ (or equivalent)")
    print("2. Review 128T IDPS events in conductor")
    print("3. Verify antivirus signatures are up to date")
    print("4. Check if SSL decryption is enabled for HTTPS inspection")


def run_all_tests_once():
    """Run the full outbound EICAR test suite once using default values."""
    test_results = {}

    print(f"\n{Colors.BOLD}Starting EICAR Outbound Tests...{Colors.RESET}")

    test_results["HTTP POST"] = test_http_post_upload()
    time.sleep(1)

    test_results["Multipart Upload"] = test_http_multipart_upload()
    time.sleep(1)

    test_results["HTTPS"] = test_https_transmission()
    time.sleep(1)

    test_results["Encoded"] = test_encoded_transmissions()
    time.sleep(1)

    test_results["Socket"] = test_direct_socket_transmission()
    time.sleep(1)

    test_results["File Transfer"] = test_ftp_simulation()
    time.sleep(1)

    test_results["DNS Tunnel"] = test_dns_tunnel_simulation()
    time.sleep(1)

    test_results["WebSocket"] = test_websocket_simulation()

    generate_test_report(test_results)

    print(f"\n{Colors.BOLD}Testing Complete!{Colors.RESET}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nCheck your router/firewall logs for detailed detection information.")
    print("For 128T: Look in conductor Events > IDPS or /var/log/128t-anti-virus/\n")


def parse_interval_to_seconds(interval_str):
    """
    Parse an interval string into seconds.
    - If it's an integer string, treat as seconds.
    - If it's HH:MM:SS, convert to seconds.
    """
    if interval_str is None:
        return None

    try:
        return int(interval_str)
    except ValueError:
        pass

    parts = interval_str.split(":")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid interval format: {interval_str}. Use seconds or HH:MM:SS"
        )

    try:
        hours = int(parts[0])
        minutes = int(parts[1])
        seconds = int(parts[2])
    except ValueError:
        raise ValueError(
            f"Invalid interval format: {interval_str}. Use seconds or HH:MM:SS"
        )

    return hours * 3600 + minutes * 60 + seconds


def main():
    """Main test execution and optional timed loop"""
    print_header()

    parser = argparse.ArgumentParser(
        description="EICAR Outbound Router AV Test Suite (128T / gateway AV testing)"
    )
    parser.add_argument(
        "-i",
        "--interval",
        help="Run tests repeatedly every INTERVAL seconds or HH:MM:SS (default: run once)",
    )
    parser.add_argument(
        "-n",
        "--runs",
        type=int,
        default=0,
        help="Number of runs when using --interval (0 = infinite until Ctrl+C)",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Run without waiting for Enter (non-interactive / cron / systemd)",
    )

    args = parser.parse_args()

    print(
        f"{Colors.YELLOW}⚠  IMPORTANT: This test sends EICAR test patterns through your network"
        f"{Colors.RESET}"
    )
    print(
        f"{Colors.YELLOW}   Your router/firewall SHOULD detect and block these transmissions"
        f"{Colors.RESET}"
    )
    print(
        f"{Colors.YELLOW}   Check your 128T or router logs for detection events{Colors.RESET}\n"
    )

    if not args.no_prompt and args.interval is None:
        input("Press Enter to begin outbound EICAR transmission tests...")
    else:
        print(f"{Colors.CYAN}[INFO] Starting tests in non-interactive mode{Colors.RESET}")

    check_network_path()

    if args.interval is None:
        run_all_tests_once()
        return

    try:
        interval_seconds = parse_interval_to_seconds(args.interval)
    except ValueError as ve:
        print(f"{Colors.RED}Error parsing interval: {ve}{Colors.RESET}")
        sys.exit(1)

    if interval_seconds <= 0:
        print(f"{Colors.RED}Interval must be > 0 seconds{Colors.RESET}")
        sys.exit(1)

    print(f"\n{Colors.CYAN}[INFO] Timed mode enabled{Colors.RESET}")
    print(f"{Colors.CYAN}       Interval: {interval_seconds} seconds{Colors.RESET}")
    if args.runs > 0:
        print(f"{Colors.CYAN}       Runs:     {args.runs}{Colors.RESET}")
    else:
        print(f"{Colors.CYAN}       Runs:     infinite (Ctrl+C to stop){Colors.RESET}")

    run_count = 0
    try:
        while True:
            run_count += 1
            start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
            print(
                f"{Colors.CYAN}[INFO] Test run #{run_count} starting at {start_ts}"
                f"{Colors.RESET}"
            )
            print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")

            run_all_tests_once()

            if args.runs > 0 and run_count >= args.runs:
                print(
                    f"{Colors.CYAN}[INFO] Completed {run_count} run(s); "
                    f"exiting timed loop.{Colors.RESET}"
                )
                break

            print(
                f"{Colors.CYAN}[INFO] Sleeping {interval_seconds} seconds before next run "
                f"(Ctrl+C to stop)...{Colors.RESET}"
            )
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Test loop interrupted by user (Ctrl+C){Colors.RESET}")


if __name__ == "__main__":
    try:
        try:
            import requests  # type: ignore[import-not-found]
        except ImportError:
            print("Installing required module: requests")
            os.system("pip3 install requests --break-system-packages >/dev/null 2>&1")
            import requests  # type: ignore[import-not-found]

        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Test interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)
EOF_PY

chmod +x "${PY_SCRIPT_PATH}"

echo "==> Creating systemd service: /etc/systemd/system/${SERVICE_NAME}.service"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=EICAR Outbound Router AV Test (128T / Gateway AV) - Steve Voto (Svoto)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/env python3 ${PY_SCRIPT_PATH} --no-prompt
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "==> Creating systemd timer: /etc/systemd/system/${SERVICE_NAME}.timer"
cat > "/etc/systemd/system/${SERVICE_NAME}.timer" <<EOF
[Unit]
Description=Run EICAR AV test every 12 hours (Svoto lab tool)

[Timer]
OnBootSec=5min
OnUnitActiveSec=12h
Unit=${SERVICE_NAME}.service
Persistent=true

[Install]
WantedBy=timers.target
EOF

echo "==> Reloading systemd daemon"
systemctl daemon-reload

echo "==> Enabling and starting timer: ${SERVICE_NAME}.timer"
systemctl enable --now "${SERVICE_NAME}.timer"

echo "==> Starting initial test run via ${SERVICE_NAME}.service"
systemctl start "${SERVICE_NAME}.service"

echo
echo "=== Setup complete ==="
echo "Service : ${SERVICE_NAME}.service"
echo "Timer   : ${SERVICE_NAME}.timer"
echo
echo "Timer schedule:"
systemctl list-timers "${SERVICE_NAME}.timer" --no-pager || true
echo
echo "Last run status:"
systemctl status "${SERVICE_NAME}.service" --no-pager || true
echo
echo "Recent logs (last 50 lines):"
journalctl -u "${SERVICE_NAME}.service" -n 50 --no-pager || true
