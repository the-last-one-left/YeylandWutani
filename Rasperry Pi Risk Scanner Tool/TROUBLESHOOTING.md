# Yeyland Wutani Risk Scanner — Troubleshooting Guide

**Yeyland Wutani LLC** | *Building Better Systems*

---

## Log Locations

| Log | Location |
|---|---|
| Main scanner log | `/opt/risk-scanner/logs/risk-scanner.log` |
| Initial check-in log | `/opt/risk-scanner/logs/initial-checkin.log` |
| Systemd journal (daily scan) | `sudo journalctl -u risk-scanner-daily.service -n 100` |
| Systemd journal (weekly report) | `sudo journalctl -u risk-scanner-report.service -n 100` |
| Systemd journal (check-in) | `sudo journalctl -u risk-scanner-checkin.service -n 100` |

## Service Status

```bash
# Check all scanner services at once:
sudo systemctl status risk-scanner-*.service risk-scanner-*.timer

# View recent daily scan output:
sudo journalctl -u risk-scanner-daily.service -n 100 --no-pager

# Follow logs in real time:
sudo journalctl -u risk-scanner-daily.service -f

# Check timer schedules (next run times):
sudo systemctl list-timers risk-scanner-*
```

---

## SSH Scanning Issues

### Authentication failure / wrong credentials

The scan log will show `paramiko.ssh_exception.AuthenticationException`. Steps to resolve:

1. Verify the username and password are correct by testing manually from the Pi:
   ```bash
   ssh scanuser@10.0.1.10
   ```
2. Check `/var/log/auth.log` on the target host for the specific rejection reason:
   ```bash
   sudo tail -50 /var/log/auth.log
   ```
3. Re-enter the credential profile:
   ```bash
   sudo /opt/risk-scanner/bin/add-credential.sh
   ```
4. Test the updated credential:
   ```bash
   sudo /opt/risk-scanner/bin/test-credential.sh 10.0.1.10
   ```

### Host key verification failure

The scanner uses paramiko with trust-on-first-use (TOFU) behavior — it accepts and stores host keys on first connection, then verifies on subsequent connections. If a host's SSH key changes (e.g., after OS reinstall), the stored key will no longer match.

Resolution: Remove the stored host key entry from the scanner's known_hosts file:

```bash
sudo -u risk-scanner ssh-keygen -R 10.0.1.10 -f /opt/risk-scanner/config/known_hosts
```

Then re-run the scan or test-credential to accept the new key.

### Port 22 blocked / connection refused

The scan log will show `Connection refused` or the host appears in `ssh_failed` with a timeout error.

1. Confirm SSH is running on the target:
   ```bash
   nmap -p 22 10.0.1.10
   ```
   If the port shows `filtered`, a firewall is blocking it from the scanner's IP.
2. Check the target's firewall rules (Linux):
   ```bash
   sudo iptables -L INPUT -n | grep 22
   sudo ufw status
   ```
3. If SSH runs on a non-standard port, this is not currently supported via the credential profile — the scanner assumes port 22.

### SSH timeout

If the connection opens but commands hang, increase the per-command timeout:

```json
"scan": {
    "ssh_timeout": 30
}
```

Run `sudo /opt/risk-scanner/bin/update-config.sh` to apply.

### Permission denied collecting package list

The scanner runs as a non-root account. Full package enumeration (`dpkg -l`, `rpm -qa`) requires either:

- The scan account has `sudo` access without a password for those specific commands:
  ```bash
  echo "scanuser ALL=(ALL) NOPASSWD: /usr/bin/dpkg, /usr/bin/rpm, /usr/bin/apt" \
    | sudo tee /etc/sudoers.d/risk-scanner-readonly
  ```
- Or accept partial results — the scanner logs a warning and continues with whatever it can collect without elevated access. CVE correlation still works for services identified via nmap banners.

---

## WMI/WinRM Issues

### WinRM not enabled

The most common Windows scanning failure. On the target host, open an elevated PowerShell prompt and run:

```powershell
Enable-PSRemoting -Force
winrm quickconfig -force
```

Verify WinRM is listening:

```powershell
winrm enumerate winrm/config/listener
```

You should see a listener on port 5985 (HTTP) or 5986 (HTTPS).

### Access denied

Even with correct credentials, access may be blocked by group membership or session configuration.

Add the scan account to the Remote Management Users group:

```powershell
Add-LocalGroupMember -Group "Remote Management Users" -Member "DOMAIN\scanaccount"
```

If that does not resolve it, open the session security descriptor:

```powershell
Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI
```

Add the scan account with Execute/Read/Write access.

### Local account UAC remote restrictions

Windows restricts remote access for local (non-domain) accounts by default. If using a local account for scanning, set this registry value on the target:

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord
```

This allows local admin accounts to connect over WinRM without token filtering.

### Windows Firewall blocking WinRM

Add the WinRM rule if the built-in Enable-PSRemoting did not create it:

```cmd
netsh advfirewall firewall add rule name="WinRM-HTTP" dir=in action=allow protocol=TCP localport=5985
```

Or with PowerShell:

```powershell
New-NetFirewallRule -Name "WinRM-HTTP" -DisplayName "WinRM HTTP" `
  -Protocol TCP -LocalPort 5985 -Direction Inbound -Action Allow
```

### WMI DCOM fallback (port 135 / RPC)

If WinRM fails, the scanner automatically falls back to WMI DCOM via impacket. This requires RPC (port 135) and dynamic high ports (49152–65535) to be accessible from the scanner's IP. If your firewall blocks these, WMI DCOM will also fail.

For environments where neither WinRM nor WMI DCOM can be opened, the scanner will collect nmap-level data only for those hosts.

### Wrong domain format

Both `DOMAIN\username` and `username@domain.com` formats are accepted. For local accounts, use just `username` with no domain prefix.

---

## SNMP Issues

### No SNMP response

1. Verify SNMP is enabled on the target device (check device configuration).
2. Confirm port 161 UDP is reachable from the scanner:
   ```bash
   snmpwalk -v2c -c public 10.0.1.1 sysDescr
   ```
3. If no response, check firewall rules on the device — SNMP is UDP/161.
4. Verify the scanner's IP is in the device's SNMP permitted hosts list.

### Wrong community string

Many devices change the default community string from `public`. Check the device's SNMP configuration for the correct community string and update the credential profile:

```bash
sudo /opt/risk-scanner/bin/add-credential.sh
```

### SNMP v3 authentication failure

SNMP v3 auth failures are usually a mismatch between configured and expected protocols or keys.

1. Verify the auth protocol (SHA vs MD5) matches what is configured on the device.
2. Verify the priv protocol (AES vs DES) matches.
3. Verify the username, auth key, and priv key are exactly correct (case-sensitive).
4. Test directly:
   ```bash
   snmpwalk -v3 -l authPriv -u scanuser -a SHA -A "authkey" -x AES -X "privkey" 10.0.1.1 sysDescr
   ```

### MIB not found / cannot import module

Run the MIB downloader to install standard MIB files:

```bash
sudo apt-get install snmp-mibs-downloader
sudo download-mibs
```

Ensure mibs are enabled in `/etc/snmp/snmp.conf` — the line `mibs +ALL` should be present (not commented out).

### Device rate-limiting SNMP polls

Some managed switches and routers throttle SNMP to prevent DoS. Symptoms: intermittent timeouts, partial data. Options:

- Increase `snmp_timeout` in `config.json`
- Reduce `max_threads` to spread SNMP queries over more time
- Check the device's SNMP rate-limit configuration and increase the threshold for the scanner's IP

---

## NVD API Issues

### Rate limiting (HTTP 403 or 429) during initial seed

Without an NVD API key, the NVD enforces a rate limit of 5 requests per 30 seconds. The initial database seed covers thousands of pages and can take 60 minutes or more at this rate.

**Resolution: Register for a free NVD API key** at https://nvd.nist.gov/developers/request-an-api-key

With an API key (50 req/30 sec), the initial seed takes 10–15 minutes.

Run the initial seed with your key:

```bash
sudo -u risk-scanner /opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/update-vuln-db.py \
  --init --nvd-api-key YOUR_KEY_HERE
```

### CVE database is stale

The scanner logs a warning if the CVE DB has not been updated in more than 3 days. Run a manual update:

```bash
sudo -u risk-scanner /opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/update-vuln-db.py --update
```

Check DB status (CVE count, KEV count, last updated):

```bash
sudo -u risk-scanner /opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/update-vuln-db.py --stats
```

### DB size growing too large

The default 5-year CVE window is approximately 400 MB. If the device has limited storage, reduce the window:

```json
"vulnerability": {
    "vuln_db_max_age_years": 3
}
```

Then re-seed to rebuild the DB at the new size:

```bash
sudo -u risk-scanner /opt/risk-scanner/venv/bin/python /opt/risk-scanner/bin/update-vuln-db.py --init
```

---

## Credential Decryption Failure

### Machine-ID changed after OS reinstall

The credential encryption key is derived from `/etc/machine-id`. If the Pi OS is reinstalled, a new machine-id is generated and `credentials.enc` becomes permanently unreadable.

**This is by design** — credentials are machine-bound to prevent them from being stolen by copying the file to another device.

Resolution: Re-enter all credential profiles after an OS reinstall:

```bash
sudo /opt/risk-scanner/bin/add-credential.sh
```

Run this once per credential profile (SSH, WMI, SNMP) until all profiles are restored.

View the current machine-id:

```bash
cat /etc/machine-id
```

**Backup recommendation**: Before any OS change, export your credential profile details (usernames, subnets — not passwords) to a separate secure location so you have a reference list for re-entering them after reinstall.

---

## Graph API / Email Issues

### Token acquisition failure

The scanner log will show `MSAL token acquisition failed` with an AADSTS error code.

| Error Code | Cause | Resolution |
|---|---|---|
| `AADSTS700016` | Invalid client ID or wrong tenant | Verify `tenant_id` and `client_id` in `config.json` |
| `AADSTS7000215` | Invalid or expired client secret | Rotate the secret in Azure Portal; run `update-config.sh` |
| `AADSTS650057` | `Mail.Send` permission not granted | Check Azure App Registration — admin consent must be granted |
| `Authorization_RequestDenied` | Admin consent not granted | In Azure Portal: App registrations → API permissions → Grant admin consent |
| `ErrorSendAsDenied` | `from_email` not in tenant or unlicensed | Verify the from_email mailbox exists and is active |

### InvalidAuthenticationToken — clock skew

Azure AD token validation is time-sensitive. If the Pi's clock is significantly out of sync, tokens appear invalid immediately after acquisition.

Check NTP sync status:

```bash
timedatectl status
```

Force NTP sync:

```bash
sudo ntpdate -u pool.ntp.org
```

Or wait 60 seconds after boot for the Pi to sync automatically. The scanner's systemd service has an `After=time-sync.target` dependency to help with this.

### Mail.Send permission not granted

In the Azure Portal, navigate to:

App registrations → YW Risk Scanner → API permissions

The `Mail.Send` permission must show a green checkmark with "Granted for [your organization]". If it shows a yellow warning, admin consent has not been granted. Click "Grant admin consent for {tenant}" and confirm.

See [GRAPH_API_SETUP.md](GRAPH_API_SETUP.md) for the full setup walkthrough.

### Rate limiting (HTTP 429)

The scanner includes automatic retry with exponential backoff for 429 responses. No action is needed for occasional rate limiting. If the error is persistent across multiple weekly reports, check the tenant's outbound email send limits in the Microsoft 365 admin center.

### Large PDF attachment failure

PDFs larger than 3 MB automatically use the Graph API upload session endpoint (chunked upload). This is handled transparently with no configuration needed. If the upload session itself fails, check the scanner log for the specific error — it may be a transient network issue or a tenant-level attachment size limit.

---

## General Issues

### Scan is taking too long

A full credentialed scan of 50 hosts typically takes 30–90 minutes. For larger networks or if the scan is consistently timing out:

1. Reduce the port scan scope:
   ```json
   "scan": {
       "port_scan_top_ports": 100,
       "port_scan_full": false
   }
   ```
2. Reduce parallelism if the Pi is CPU/memory constrained:
   ```json
   "scan": {
       "max_threads": 15
   }
   ```
3. Check for unreachable subnets in your routing — hosts in unreachable subnets cause scan phases to wait until each timeout expires. Exclude unreachable CIDRs:
   ```json
   "scan": {
       "excluded_hosts": ["172.16.99.0/24"]
   }
   ```
4. Increase the scan timeout if you have a very large network:
   ```json
   "scan": {
       "scan_timeout": 7200
   }
   ```

### Lock file stuck / scanner won't start

If a previous scan crashed without releasing its lock, subsequent scans will refuse to start.

Check if the scanner is actually running:

```bash
ps aux | grep risk-scanner
```

If no scanner process is running, remove the stale lock file:

```bash
sudo rm /opt/risk-scanner/data/.scanner.lock
```

### Permission errors

If files were modified by root or another process, reset ownership:

```bash
sudo chown -R risk-scanner:risk-scanner /opt/risk-scanner/
sudo chmod 640 /opt/risk-scanner/config/config.json
sudo chmod 600 /opt/risk-scanner/config/credentials.enc
```

### Missing Python packages

If the scanner fails with `ModuleNotFoundError`:

```bash
sudo -u risk-scanner /opt/risk-scanner/venv/bin/pip install -r /opt/risk-scanner/requirements.txt
```

If a package is missing entirely from `requirements.txt`, run `self-update.sh` to pull the latest version of the tool which may include the updated dependency list:

```bash
sudo /opt/risk-scanner/bin/self-update.sh
```

### `risk-scanner` user not found

If the service user was accidentally deleted:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin risk-scanner
sudo usermod -aG netdev risk-scanner
sudo chown -R risk-scanner:risk-scanner /opt/risk-scanner/
```

---

*Yeyland Wutani LLC — IT Consulting & Cybersecurity Services*
*For issues: https://github.com/the-last-one-left/YeylandWutani/issues*
