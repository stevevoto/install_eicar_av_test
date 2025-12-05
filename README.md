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

cd install_eicar_av_test/

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

show idp application status

==============================================================
 node0.020001fcaecc
==============================================================
 Mode:                                   spoke
 Engine:                                 on
 Pod:                                    active
 Engine Started:                         2025-12-04T19:09:30Z
 Up Time:                                2h 32m 59s
 Last Commit:                            2025-12-04T19:28:28Z
 Last:                                   starting
 Platform Size:                          legacy
 Anti Virus Scan Engine Type:            sophos-engine
 Anti Virus Scan Engine Information:     running
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



## 

**How the Test Traffic Looks on the Wire & How AV Picks It Up**

Your script always sends **the same EICAR test string**, but it wraps it in different **protocols and encodings** to exercise different AV/IDPS paths.

EICAR string (payload):

X5O!P%@AP\[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H\*

Below is what each test is doing and how a network AV/IDPS typically sees and classifies it.

* * *

**1\. HTTP POST (plain form data)**

**What we send**

*   **Protocol:** HTTP over **TCP/80**
*   **Direction:** Client → Internet test site (e.g. httpbin.org, postman-echo.com)
*   **Typical wire example:**

·       POST /post HTTP/1.1

·       Host: httpbin.org

·       User-Agent: EICAR-Test-Client

·       Content-Type: application/x-www-form-urlencoded

·       Content-Length: <len>

·        

·       file=X5O!P%@AP\[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H\*&test=eicar

**How AV/IDPS detects it**

*   Device sits **inline** as your default gateway / router / NGFW.
*   It:

1.  Reassembles the **TCP stream**.
2.  Recognizes **HTTP** using its protocol parser.
3.  Extracts the **body** (file=...) and runs it through the **signature engine**.
4.  Sees the literal EICAR string and hits a signature like EICAR\_Test\_File.

*   Classification usually shows up as:

*   **Type:** Virus / Malware (Test)
*   **Name:** EICAR, EICAR\_TEST\_FILE, etc.
*   **Severity:** Low/Medium (because it’s a test file)

*   Policy then:

*   Blocks the request (drop/reset), or
*   Allows but logs, depending on your AV/IDP policy.

* * *

**2\. HTTP Multipart File Upload**

**What we send**

*   **Protocol:** HTTP over **TCP/80**
*   **Wire shape:** A multipart/form-data **file upload** with the EICAR string as the “file” content.

·       POST /post HTTP/1.1

·       Host: httpbin.org

·       Content-Type: multipart/form-data; boundary=----BOUNDARY

·        

·       \------BOUNDARY

·       Content-Disposition: form-data; name="file"; filename="eicar.txt"

·       Content-Type: text/plain

·        

·       X5O!P%@AP\[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H\*

·       \------BOUNDARY--

**How AV/IDPS detects it**

*   HTTP parser sees **multipart/form-data** and treats this as a **file upload**.
*   It extracts the file payload and scans it as:

*   File type: text/plain
*   Content: the EICAR string

*   Same signature match as above, but some engines explicitly log it as:

*   **Category:** File upload / HTTP file transfer
*   **Action:** “Blocked file”, “Quarantined file”, or similar.

* * *

**3\. HTTPS POST (encrypted)**

**What we send**

*   **Protocol:** HTTPS over **TCP/443**
*   **Shape on the wire:**

*   Full **TLS handshake**, then
*   An **HTTP POST** with JSON body carrying EICAR:

o   POST /post HTTP/1.1

o   Host: httpbin.org

o   Content-Type: application/json

o    

o   {"payload": "X5O!P%@AP\[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H\*", "test":"eicar\_https"}

But from the outside, all of this is **encrypted** inside the TLS session.

**How AV/IDPS detects it**

Two cases:

1.  **SSL/TLS inspection enabled**

*   The device acts as a **TLS proxy / man-in-the-middle**:

*   Terminates TLS from the client.
*   Decrypts the inner HTTP.
*   Runs the same HTTP + payload engine as in the plain HTTP tests.

*   It sees the EICAR string and fires the same EICAR signature.
*   Classification: “Virus detected in HTTPS traffic”, often with an extra tag like ssl-decrypted.

3.  **No SSL inspection**

*   Device only sees:

*   Client IP/port, server IP/port
*   TLS metadata (SNI, cert, ciphers)

*   It **cannot see EICAR** inside the encrypted payload.
*   No EICAR detection from content signatures; it may only do **reputation / domain-based** checks.
*   In your test results, this usually appears as **HTTPS: ALLOWED** unless SSL inspection is turned on.

* * *

**4\. Encoded Payloads (Base64, Hex, URL-encoded)**

**What we send**

Still HTTP POST over TCP/80, but the **body is encoded**:

*   **Base64:** eicar\_base64=WFNPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVN...
*   **Hex:** eicar\_hex=58354f2150254041505b345c505a583534285e29374343...
*   **URL-encoded:** eicar\_url=X5O%21P%25%40AP%5B4%5CPZX54...
*   **Double-URL-encoded:** same but encoded twice.

**How AV/IDPS detects it**

*   Many modern engines have **content decoders**:

*   For HTTP POST/GET params, they will:

*   URL-decode parameters
*   Decode Base64 fields (if they look like data blobs)
*   Sometimes decode hex strings in known contexts

*   So they may:

1.  Decode the payload back to the original EICAR bytes.
2.  Re-run signatures on the decoded content.

*   Classification:

*   Same EICAR signature, often annotated as:

*   “Detected after decoding” or
*   “Encoded malware payload”.

*   If decoders are **not** enabled/advanced, these may slip and show as **ALLOWED** in your test.

* * *

**5\. Raw Socket HTTP**

**What we send**

*   **Protocol:** Still HTTP over **TCP/80**, but we bypass requests and build the HTTP request by hand over a raw socket:

·       POST /post HTTP/1.1

·       Host: httpbin.org

·       Content-Type: text/plain

·       Content-Length: <len>

·       Connection: close

·        

·       X5O!P%@AP\[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H\*

**How AV/IDPS detects it**

*   To the network device, this **still looks like normal HTTP**:

*   IP + TCP handshake
*   HTTP headers + body

*   The AV/IDPS protocol parser doesn’t care that your **client** is low-level; it just sees HTTP semantics.
*   It reassembles and scans body content as before → EICAR signature.

This test is more about **ensuring detection isn’t tied only to “browser-like” traffic**; raw tools and scripts should be covered too.

* * *

**6\. HTTP PUT (FTP-like / file transfer simulation)**

**What we send**

*   **Protocol:** HTTP over **TCP/80**
*   **Method:** PUT
*   **Payload:** The EICAR string as the request body, with Content-Type: application/octet-stream.

·       PUT /put HTTP/1.1

·       Host: httpbin.org

·       Content-Type: application/octet-stream

·       Content-Length: <len>

·        

·       X5O!P%@AP\[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H\*

**How AV/IDPS detects it**

*   HTTP parser recognizes **PUT** (file upload / object update).
*   Treats body as a generic file/stream and scans for signatures.
*   Same EICAR detection, but some engines will tag:

*   **Direction:** Upload
*   **Method:** PUT
*   **Application:** WebDAV / REST API / generic web file upload.

This helps test AV coverage for **API/file-transfer** style traffic, not just browser form posts.

* * *

**7\. DNS “Tunneling” Simulation**

**What we send**

*   **Protocol:** DNS queries, typically over **UDP/53**
*   **Payload shape:**

*   EICAR string is hex-encoded.
*   Split into label-length chunks (up to 63 chars).
*   Used as a **subdomain**:

o   <hex-chunk>.test.local

*   Script uses socket.gethostbyname() → OS resolver → your DNS server → out to upstream (depending on your lab).

**How AV/IDPS detects it**

*   A pure **AV engine** usually doesn’t decode arbitrary hex back to EICAR in DNS labels.
*   But **IDPS / DNS security** may detect:

*   Suspiciously long or random-looking labels.
*   Patterns consistent with **DNS tunneling**.

*   So classification is more like:

*   **Category:** DNS Tunneling / Anomaly / Suspicious DNS
*   Not “Virus: EICAR” specifically.

*   In your test:

*   If DNS queries get blocked / NXDOMAIN by security filters, you’ll see BLOCKED.
*   If they resolve or just fail normally (no security event), you may see ALLOWED but still log anomalies upstream, depending on config.

* * *

**8\. WebSocket-like Simulation**

**What we send**

*   **Protocol:** HTTP over TCP/80 with **WebSocket-style headers**, plus JSON body containing EICAR (Base64-encoded):

·       POST /post HTTP/1.1

·       Host: httpbin.org

·       Upgrade: websocket

·       Connection: Upgrade

·       Content-Type: application/json

·        

·       {"type":"websocket\_message",

·        "data":"WFNPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVN...",

·        "protocol":"ws"}

*   This isn’t a full RFC-perfect WebSocket handshake, but it simulates an application sending EICAR-like content in a WebSocket-ish flow.

**How AV/IDPS detects it**

*   Application decoder sees HTTP with Upgrade: websocket.
*   Many NGFW/IDPS products treat WebSocket as **“HTTP-derived”** and still:

*   Parse initial HTTP headers.
*   Inspect JSON payload (if not fully upgraded or if they can decode frames).

*   It may:

*   Base64-decode data, find EICAR, trigger signature.
*   Or only see it as generic JSON if decoders are limited.

This checks that **WebSocket-style traffic isn’t a blind spot**.

* * *

**How AV/IDPS Classifies What We Send**

Across all these tests, a modern AV/IDPS typically does:

1.  **Flow & Session Handling**

*   Tracks TCP/UDP flows, source/destination IPs/ports, session state.
*   Applies security policies (service policies, zones, etc.) to decide which flows to inspect.

3.  **Protocol Decoding**

*   Identifies application protocol: HTTP, HTTPS, DNS, WebSocket-ish, etc.
*   Extracts relevant fields:

*   HTTP headers & body
*   Multipart file sections
*   JSON keys/values
*   DNS query names

*   Classifies “application” (e.g., web-browsing, web services, DNS) for logging.

5.  **Content Normalization & Decoding**

*   Reassembles fragmented packets and TCP streams.
*   Decodes:

*   URL-encoding
*   Base64 blobs
*   Sometimes hex encodings, compression, or chunked encoding.

*   Feeds the **normalized payload** into the signature engine.

7.  **Signature Matching**

*   Contains a known signature for **EICAR test string**.
*   As soon as that byte pattern appears in the inspected content, it triggers:

*   Signature ID (e.g. EICAR\_TEST\_FILE)
*   Name, severity, category (virus/test)

*   That’s what you will see in 128T / Conductor logs and AV/IDP logs.

9.  **Action & Logging**

*   Based on policy:

*   **Inline block** – drop/ reset connection, log event.
*   **Monitor-only** – allow traffic but log event.
*   **Quarantine file** – in endpoint AV scenarios (less relevant here).

*   Logs usually include:

*   Source/destination, protocol, app
*   Signature name (EICAR)
*   Action (blocked/allowed)
*   Direction (upload/download)

* * *

**How This Maps to the Test Summary**

When the script prints:

HTTP POST                    : BLOCKED

Multipart Upload             : BLOCKED

HTTPS                        : ALLOWED

Encoded                      : ALLOWED

Socket                       : BLOCKED

File Transfer                : BLOCKED

DNS Tunnel                   : ALLOWED

WebSocket                    : ALLOWED

Overall Score: 5/8 transmissions blocked

You can interpret it as:

*   **BLOCKED tests** → AV/IDPS is successfully decoding + scanning that protocol/encoding path.
*   **ALLOWED tests** → either:

*   AV/IDPS is not inspecting that path (e.g., no SSL inspection, encoded payload not decoded), or
*   It’s allowed by policy (monitor-only), but you might still see a logged event.

You then correlate **each test type** to:

*   Transport protocol: TCP/80, TCP/443, UDP/53, TCP/80 (raw, WebSocket).
*   Application protocol: HTTP, HTTPS, DNS, WebSocket-like.
*   What decoders & policies need to be enabled in the 128T / NGFW config.

* * *

