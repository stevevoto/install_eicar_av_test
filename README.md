# Svoto EICAR Router AV Scheduled Testing Guide

## Overview

This project installs a scheduled EICAR outbound antivirus test on a Linux system that sits behind your 128T router or any router/firewall. It uses the standard EICAR test string to verify that your router or firewall antivirus (AV) and IDPS are inspecting and logging outbound traffic correctly, including encrypted and encoded paths.

The setup uses a one-shot installer (install\_eicar\_av\_test.sh), a Python test script (eicar\_router\_test.py), and a systemd service plus timer so the test runs once immediately after install and then automatically every 12 hours by default.

## Safety & Legal Disclaimer

This tool uses the EICAR standard antivirus test string, not real malware. The EICAR string is designed to be harmless, recognized by most AV engines, and intended specifically for testing AV detection.

This tool is provided “AS IS”, without warranty of any kind, express or implied. Use at your own risk. The author (Steve Voto / Svoto) assumes no responsibility for outages or downtime, data loss or corruption, security incidents or misconfigurations, or policy, compliance, or legal violations resulting from use or misuse of this tool.

Do not run this on networks where such testing is prohibited by policy, contract, or law. Only use this on networks you own or are explicitly authorized to test.

## Components

### 1\. install\_eicar\_av\_test.sh – One-Shot Installer

This script:

·       • Creates the install directory:

/usr/local/eicar-av-test/

·       • Writes the main Python script:

/usr/local/eicar-av-test/eicar\_router\_test.py

·       • Creates the systemd unit files:

/etc/systemd/system/eicar-av-test.service

/etc/systemd/system/eicar-av-test.timer

·       • Reloads systemd and enables the timer:

systemctl daemon-reload

systemctl enable --now eicar-av-test.timer

systemctl start eicar-av-test.service

Result: a single immediate test run via eicar-av-test.service and recurring tests every 12 hours via eicar-av-test.timer.

### 2\. eicar\_router\_test.py – Outbound Test Script

This script:

·       • Sends the EICAR string using multiple methods:

·       \- HTTP POST

·       \- HTTP multipart upload

·       \- HTTPS JSON POST

·       \- Encoded payloads (Base64, Hex, URL-encoded, double-encoded)

·       \- Raw socket HTTP

·       \- PUT (FTP-like simulation)

·       \- DNS-like tunneling patterns

·       \- WebSocket-like JSON messages

·       • Prints a detailed summary of:

·       \- Which tests were BLOCKED vs ALLOWED

·       \- Overall detection score

·       \- Recommendations for AV / IDPS configuration

·       • Supports:

·       \- --no-prompt for non-interactive runs (used by systemd)

·       \- --interval and --runs for self-looping test mode (optional)

## Installation & Setup

### 1\. Clone the Repository

Run the following commands on your Linux host:

git clone https://github.com/stevevoto/install_eicar_av_test.git

cd <your-repo>

### 2\. Make the Installer Executable

Make the installer script executable:

chmod +x install\_eicar\_av\_test.sh

### 3\. Run the Installer (One Time, as Root)

Run the installer once using sudo:

sudo ./install\_eicar\_av\_test.sh

The installer will:

·       • Create:

/usr/local/eicar-av-test/

·       • Install the Python test script:

/usr/local/eicar-av-test/eicar\_router\_test.py

·       • Create systemd unit files:

/etc/systemd/system/eicar-av-test.service

/etc/systemd/system/eicar-av-test.timer

·       • Run:

systemctl daemon-reload

systemctl enable --now eicar-av-test.timer

systemctl start eicar-av-test.service

Outcome: one immediate test run happens right after install, and future tests run automatically every 12 hours.

## EICAR Test String

The script uses the standard EICAR test string, which is harmless but designed to trigger antivirus detection:

X5O!P%@AP\[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H\*

This string contains no real malware. It is an industry-standard way to validate that antivirus engines are correctly detecting and handling threats.

## What Gets Tested (Per Run)

Each scheduled run of eicar\_router\_test.py attempts multiple outbound EICAR patterns:

1.     1\. HTTP POST – EICAR in plain HTTP form-data to public HTTP endpoints.

2.     2\. HTTP Multipart Upload – EICAR as an uploaded file (multipart/form-data).

3.     3\. HTTPS POST – EICAR in JSON over TLS to test SSL inspection.

4.     4\. Encoded Payloads – Base64, Hex, URL-encoded, and double URL-encoded EICAR.

5.     5\. Raw Socket HTTP – Manually crafted HTTP POST over TCP sockets.

6.     6\. PUT / FTP-like Simulation – EICAR sent via HTTP PUT.

7.     7\. DNS-like Tunneling Simulation – EICAR encoded into DNS label-sized hex chunks.

8.     8\. WebSocket-like Simulation – JSON with EICAR payload and WebSocket-style headers.

The goal is to reveal which outbound paths your AV/IDPS is inspecting and which may not be covered due to missing SSL decryption, incomplete DPI, or weak DNS/Socket inspection.

## How Often Does It Run?

The installer creates a systemd timer that controls how often the test is run:

\[Timer file: /etc/systemd/system/eicar-av-test.timer\]

\[Unit\]  
Description=Run EICAR AV test every 12 hours (Svoto lab tool)  
  
\[Timer\]  
OnBootSec=5min  
OnUnitActiveSec=12h  
Unit=eicar-av-test.service  
Persistent=true  
  
\[Install\]  
WantedBy=timers.target  
  

This configuration means:

·       • First automatic run: about 5 minutes after boot (OnBootSec=5min).

·       • Subsequent runs: every 12 hours after the last run completes (OnUnitActiveSec=12h).

### Checking Last and Next Run

Use this command to see when the service last ran and when it will run next:

systemctl list-timers eicar-av-test.timer

Example output:

NEXT                        LEFT          LAST                        PASSED       UNIT                 ACTIVATES  
Mon 2025-12-08 04:00:00     11h left      Sun 2025-12-07 16:00:10     1h ago      eicar-av-test.timer  eicar-av-test.service  
  

·       LAST → last test execution time.

·       NEXT → next scheduled test time.

## Viewing Test Results (Linux Host)

All output from eicar\_router\_test.py is captured by systemd journal under the eicar-av-test.service unit.

### Show Latest Run Output

Run:

sudo journalctl -u eicar-av-test.service -n 100 --no-pager

### Follow Logs in Real Time

Run:

sudo journalctl -u eicar-av-test.service -f

You will see individual test results (BLOCKED vs ALLOWED), an overall detection score, and recommendations to tune AV/IDPS configuration.

## Manual Script Usage (Ad-Hoc Testing)

Even with systemd scheduling, you can run the script manually when needed.

### Script Location

The script is installed at:

/usr/local/eicar-av-test/eicar\_router\_test.py

### Run Once (Interactive)

Run:

python3 /usr/local/eicar-av-test/eicar\_router\_test.py

You will be prompted to press Enter before the tests begin, which is useful for lab usage.

### Run Once (Non-Interactive)

Run:

python3 /usr/local/eicar-av-test/eicar\_router\_test.py --no-prompt

## Self-Looping Mode (Without systemd)

If you prefer not to use systemd, the script can loop itself using the --interval and --runs arguments.

Example: Run every 10 minutes, forever:

python3 /usr/local/eicar-av-test/eicar\_router\_test.py --interval 600 --no-prompt

Example: Run every hour, 5 times, then exit:

python3 /usr/local/eicar-av-test/eicar\_router\_test.py --interval 01:00:00 --runs 5 --no-prompt

\--interval accepts either a number of seconds (e.g. 600) or HH:MM:SS format (e.g. 01:00:00).

## Customizing the Systemd Interval

To adjust how often the test is run by systemd, edit the timer file and restart the timer.

9.     1\. Edit the timer file:

sudo nano /etc/systemd/system/eicar-av-test.timer

10.  2\. Change the OnUnitActiveSec line, for example:

OnUnitActiveSec=6h    # every 6 hours

OnUnitActiveSec=1h    # every 1 hour

OnUnitActiveSec=30min # every 30 minutes

11.  3\. Reload systemd and restart the timer:

sudo systemctl daemon-reload

sudo systemctl restart eicar-av-test.timer

12.  4\. Confirm the new schedule:

systemctl list-timers eicar-av-test.timer

## Managing the Service & Timer

Useful systemd commands for managing this test environment:

·       Check service status:

systemctl status eicar-av-test.service

·       Check timer status:

systemctl status eicar-av-test.timer

·       Manually trigger a test run:

sudo systemctl start eicar-av-test.service

·       Stop automatic runs (keep files installed):

sudo systemctl disable --now eicar-av-test.timer

·       Re-enable automatic runs:

sudo systemctl enable --now eicar-av-test.timer

## Checking 128T Router & Security Logs

After each test run, verify that your 128T router or other security device detects the EICAR traffic.

### 1\. Conductor GUI (128T)

In the Conductor web interface:

·       • Go to Monitor → Events → IDPS Events.

·       • Filter for terms like “EICAR” or “Test”.

·       • Cross-check timestamps with the Linux host test times.

### 2\. On the 128T Router (Linux / CLI)

Run these commands on the router:

ssh admin@<router-ip>

systemctl status 128t-anti-virus

sudo journalctl -u 128t-anti-virus -f

sudo ls -la /var/log/128t-anti-virus/

sudo tail -f /var/log/128t-anti-virus/anti-virus.log

### 3\. PCLI on 128T

From PCLI:

pcli

show events type idps

show events category security

show idps signatures

## Expected Behavior

What you should expect to see when running these tests:

### When Protection is Working (Good)

·       • Many or most transmissions are blocked, reset, or error out.

·       • The script shows numerous BLOCKED results.

·       • 128T / firewall logs contain clear EICAR / test entries.

### When Protection Needs Improvement

·       • Many tests succeed with 200 OK responses.

·       • Script shows ALLOWED on key vectors like HTTP, HTTPS, and encoded content.

·       • Logs show little or no detection activity for EICAR-related traffic.

## Uninstall / Cleanup

To completely remove the tool and its scheduled tests, perform the following steps:

13.  1\. Stop and disable the timer:

sudo systemctl disable --now eicar-av-test.timer

14.  2\. Remove the systemd unit files:

sudo rm -f /etc/systemd/system/eicar-av-test.service

sudo rm -f /etc/systemd/system/eicar-av-test.timer

15.  3\. Reload systemd:

sudo systemctl daemon-reload

16.  4\. Remove the install directory and script:

sudo rm -rf /usr/local/eicar-av-test

## Best Practices

Suggested operational practices:

·       • Test regularly, especially after policy changes or system updates.

·       • Always verify logs in addition to observing blocking behavior.

·       • Keep AV/IDPS signatures up to date on your router/firewall.

·       • Test both HTTP and HTTPS paths and any other critical protocols.

·       • Document results for internal reviews, audits, or compliance reports.

## References

This tool uses the standard EICAR antivirus test string to verify antivirus and IDPS operation. For more information about the EICAR test file, see the official EICAR site:

https://www.eicar.org/download-anti-malware-testfile/

Reminder: Only run these tests on networks where you have explicit authorization. These tests will generate security alerts, logs, and may notify security teams.
