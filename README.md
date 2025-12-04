# 128T / Router EICAR AV Scheduled Testing Guide

## Overview

This guide explains how to install and use the **Svoto EICAR Outbound AV Test** as a **scheduled job** on a Linux host sitting behind your 128T router (or any router/firewall).

The tool:

- Installs a Python script that sends **EICAR test signatures** through your router to external test servers.
- Configures a **systemd service + timer** so the test:
  - Runs **once immediately** after install.
  - Then runs **automatically every 12 hours** with no user interaction.

Your router / firewall **should detect, log, and (ideally) block** these transmissions.

> ⚠️ **Important:** Only use this on networks you own or are explicitly authorized to test.

---

## Components

### 1. `install_eicar_av_test.sh` – One-Shot Installer

- Creates the install directory:  
  `/usr/local/eicar-av-test/`
- Writes the main Python test script:  
  `/usr/local/eicar-av-test/eicar_router_test.py`
- Creates systemd units:

  - `/etc/systemd/system/eicar-av-test.service`
  - `/etc/systemd/system/eicar-av-test.timer`

- Reloads systemd and enables the timer:

  ```bash
  systemctl daemon-reload
  systemctl enable --now eicar-av-test.timer
  systemctl start eicar-av-test.service



# 128T Router EICAR Antivirus Testing Guide

## Overview
This guide helps you test the antivirus capabilities of your 128T router by sending EICAR test virus signatures through the router to external test servers. The router should detect and block these transmissions.

## Test Scripts

### 1. **eicar_128t_test.py** - Quick 128T Test
- Focused test for 128T routers
- Tests HTTP, HTTPS, and encoded transmissions
- Uses httpbin.org and postman-echo.com
- Takes about 1 minute

### 2. **eicar_outbound_test.py** - Comprehensive Outbound Test
- Tests 8 different transmission methods
- Includes socket-level testing
- DNS tunneling simulation
- WebSocket simulation
- Takes 3-5 minutes

### 3. **eicar_webhook_test.py** - Webhook Service Test
- Uses webhook testing services
- Tests multiple encoding methods
- Simulates cloud uploads
- Most detailed results

## Quick Start

```bash
# Run the quick 128T-specific test
python3 eicar_128t_test.py

# Or run the comprehensive test
python3 eicar_outbound_test.py
```

## How It Works

The scripts send the EICAR test string through your network:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

This string is:
- **Completely harmless** - contains no actual malware
- **Industry standard** - recognized by all AV systems
- **Designed for testing** - specifically for validating AV detection

## What Gets Tested

1. **HTTP POST** - Plain text EICAR in HTTP body
2. **HTTPS POST** - Encrypted transmission (tests SSL inspection)
3. **File Upload** - Multipart form upload with EICAR
4. **Base64 Encoding** - Tests deep packet inspection
5. **Large Payloads** - EICAR embedded in larger data
6. **Various MIME Types** - Different content types
7. **Multiple HTTP Methods** - POST, PUT, PATCH
8. **Direct Socket** - Raw TCP transmission

## Expected Behavior

### ✅ When AV is Working:
- Connections timeout or are reset
- HTTP requests return error codes
- Python shows connection errors
- Tests show "✓ Blocked" messages

### ⚠️ When AV is NOT Working:
- HTTP requests return 200 OK
- Data successfully transmits
- Tests show "⚠ WARNING" messages
- No errors in transmission

## Checking 128T Router Logs

### 1. Via Conductor GUI
```
Navigate to:
- Monitor > Events > IDPS Events
- Look for "EICAR" or "Test" entries
- Check timestamp matches your test
```

### 2. Via CLI on Router
```bash
# SSH to your 128T router
ssh admin@<router-ip>

# Check antivirus service status
systemctl status 128t-anti-virus

# View real-time logs
sudo journalctl -u 128t-anti-virus -f

# Check log files
sudo ls -la /var/log/128t-anti-virus/
sudo tail -f /var/log/128t-anti-virus/anti-virus.log
```

### 3. Via PCLI
```bash
# Enter PCLI
pcli

# Show IDPS events
show events type idps

# Show security events
show events category security

# Check signature version
show idps signatures
```

## Configuration Checklist

Ensure your 128T router has:

### Service Policy Configuration
```
service-policy <policy-name>
    name <policy-name>
    service <service-name>
    security idps-inline
        mode inline  # Not just 'monitor'
    exit
exit
```

### Security Settings
```
authority
    router <router-name>
        node <node-name>
            device-interface <interface-name>
                network-interface <network-name>
                    source-nat true  # If needed
                exit
            exit
        exit
    exit
exit
```

### IDP/IPS Configuration
```
authority
    idps-profile <profile-name>
        name <profile-name>
        provider fortinet  # or your provider
        mode inline
        ssl-decryption enabled  # For HTTPS inspection
    exit
exit
```

## Troubleshooting

### Issue: All tests pass through (not blocked)

1. **Check AV Service**
   ```bash
   systemctl status 128t-anti-virus
   systemctl restart 128t-anti-virus
   ```

2. **Update Signatures**
   ```bash
   # From PCLI
   request idps update-signatures
   show idps signatures
   ```

3. **Verify Mode**
   - Ensure mode is "inline" not "monitor"
   - Monitor mode only logs, doesn't block

4. **Check Session Type**
   - Session must allow payload inspection
   - Check service-class settings

5. **SSL Inspection**
   - Enable for HTTPS detection
   - Configure certificate authority

### Issue: Partial blocking

- **HTTP blocked but HTTPS passes**: Enable SSL decryption
- **Small payloads blocked, large pass**: Increase inspection buffer
- **Some encodings pass**: Enable deep packet inspection

### Issue: No logs generated

1. Check logging level:
   ```bash
   # From PCLI
   configure authority router <name> system log-level idps debug
   ```

2. Verify log categories are enabled:
   ```bash
   show events categories
   ```

## Best Practices

1. **Test Regularly**: Run tests after any configuration change
2. **Check Logs**: Always verify detection in logs, not just blocking
3. **Update Signatures**: Keep AV signatures current
4. **Test All Protocols**: HTTP, HTTPS, FTP if used
5. **Document Results**: Keep records of test results

## Understanding Results

### Excellent Protection (90-100% blocked)
- Router AV properly configured
- All major threat vectors covered
- Continue regular testing

### Good Protection (70-89% blocked)
- Most threats blocked
- Review failed tests
- Fine-tune configuration

### Needs Improvement (<70% blocked)
- Significant gaps in protection
- Review configuration thoroughly
- Consider professional assistance

## Support Resources

- **128T Documentation**: https://docs.128technology.com/
- **AV Configuration**: https://docs.128technology.com/docs/sec-config-antivirus/
- **IDPS Guide**: https://docs.128technology.com/docs/idps/
- **Community Forum**: https://community.128technology.com/

## Safety Reminder

⚠️ **Only test on networks you own or have permission to test**

These tests will:
- Generate security alerts
- Create log entries
- May notify security teams
- Could impact performance during testing

## Next Steps

After testing:
1. Review all blocked/allowed transmissions
2. Check router logs for detection details
3. Adjust configuration as needed
4. Document your security posture
5. Schedule regular retesting

---

**Remember**: The EICAR test string is harmless but designed to trigger AV systems. This is the industry-standard way to verify your antivirus is working correctly.

