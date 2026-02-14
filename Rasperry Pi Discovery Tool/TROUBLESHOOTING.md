# Troubleshooting Guide

**Yeyland Wutani - Network Discovery Pi**

---

## Log Locations

| Log | Location |
|-----|----------|
| Discovery main log | `/opt/network-discovery/logs/discovery.log` |
| Initial check-in log | `/opt/network-discovery/logs/initial-checkin.log` |
| Systemd journal (discovery) | `sudo journalctl -u nd-discovery` |
| Systemd journal (check-in) | `sudo journalctl -u nd-checkin` |
| Installer log | `/tmp/nd-install-*.log` |

---

## Service Status

```bash
# Check if services are running
sudo systemctl status initial-checkin.service
sudo systemctl status network-discovery.service

# View recent journal output
sudo journalctl -u nd-discovery -n 50 --no-pager
sudo journalctl -u nd-checkin -n 50 --no-pager

# Follow logs in real time
sudo journalctl -u nd-discovery -f
```

---

## Initial Check-In Did Not Arrive

1. **Check if the flag file exists** (check-in won't run a second time):
   ```bash
   ls -la /opt/network-discovery/data/.checkin_complete
   ```
   If it exists, check-in already ran. Use `reset-checkin.sh` to re-run.

2. **Check the service status**:
   ```bash
   sudo systemctl status initial-checkin.service
   ```

3. **Check network connectivity**:
   ```bash
   ip addr show
   ip route show default
   ping -c 3 8.8.8.8
   ```

4. **Test email manually**:
   ```bash
   /opt/network-discovery/venv/bin/python3 /opt/network-discovery/bin/test-email.py
   ```

5. **Reset and re-run**:
   ```bash
   sudo /opt/network-discovery/bin/reset-checkin.sh
   sudo systemctl start initial-checkin.service
   ```

---

## Discovery Report Did Not Arrive

1. **Check if the lock file is stuck**:
   ```bash
   cat /opt/network-discovery/data/.discovery.lock
   # If the PID is dead, remove it:
   sudo rm -f /opt/network-discovery/data/.discovery.lock
   ```

2. **Run manually to see output**:
   ```bash
   sudo /opt/network-discovery/bin/manual-scan.sh
   ```

3. **Check the discovery log**:
   ```bash
   tail -100 /opt/network-discovery/logs/discovery.log
   ```

---

## Graph API / Email Errors

### `AADSTS700016` - Invalid client/tenant ID
- Verify `tenant_id` and `client_id` in `config.json`
- Run: `sudo /opt/network-discovery/bin/update-config.sh`

### `AADSTS7000215` - Invalid client secret
- Secret may have expired. Rotate in Azure Portal and update config.
- Run: `sudo /opt/network-discovery/bin/update-config.sh`

### `Authorization_RequestDenied` / `Mail.Send` errors
- Ensure `Mail.Send` **application permission** (not delegated) is added to the app registration
- Ensure **admin consent was granted** (green checkmark in Azure Portal)
- See [GRAPH_API_SETUP.md](GRAPH_API_SETUP.md)

### `ErrorSendAsDenied`
- The `from_email` address must be a licensed Microsoft 365 mailbox in your tenant
- Verify the email address is correct and active

### `429 Too Many Requests`
- The Graph API is throttling requests. The mailer includes automatic retry with backoff.
- If persistent, reduce scan frequency.

---

## Network Scanning Issues

### No hosts discovered

- Check which interface is active: `ip addr show`
- Verify the Pi is on the correct VLAN/subnet
- Ensure arp-scan can run: `sudo arp-scan --localnet`
- Check nmap works: `sudo nmap -sn 192.168.1.0/24` (replace with your subnet)

### ARP scan requires root / Permission denied

```bash
# Grant setuid to arp-scan
sudo chmod +s $(which arp-scan)

# Or grant cap_net_raw to the venv python3
sudo setcap cap_net_raw+eip /opt/network-discovery/venv/bin/python3
```

### nmap SYN scan requires root

The systemd service includes `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`. If running manually:
```bash
sudo /opt/network-discovery/bin/manual-scan.sh
```

### Scan is slow or timing out

In `config.json`, try reducing scan scope:
```json
"port_scan_top_ports": 50,
"max_threads": 25,
"enable_traceroute": false
```

Then: `sudo /opt/network-discovery/bin/update-config.sh`

---

## Service Won't Start

```bash
# Check systemd unit file syntax
systemd-analyze verify /etc/systemd/system/network-discovery.service

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart network-discovery.service
```

### `network-discovery` user not found

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin network-discovery
sudo chown -R network-discovery:network-discovery /opt/network-discovery/logs /opt/network-discovery/data
```

---

## Performance Tuning

| Pi Model | Recommended `max_threads` | Notes |
|----------|--------------------------|-------|
| Pi Zero 2 W | 20 | Low memory - be conservative |
| Pi 3B/3B+ | 30 | Adequate for most SMB networks |
| Pi 4 | 50 | Full performance |
| Pi 5 | 75 | Can handle larger networks |

For networks >254 hosts, increase `scan_timeout` to 900-1200 seconds.

---

## Reinstalling / Updating

To pull the latest version from GitHub:

```bash
# Remove old code (keep config and logs)
sudo /opt/network-discovery/uninstall.sh  # choose "yes" to keep data

# Re-run installer (will re-clone from GitHub)
sudo bash -c "git clone --depth=1 --filter=blob:none --sparse https://github.com/the-last-one-left/YeylandWutani.git /tmp/ndpi-install && cd /tmp/ndpi-install && git sparse-checkout set 'Rasperry Pi Discovery Tool' && sudo bash '/tmp/ndpi-install/Rasperry Pi Discovery Tool/install.sh'"
```

---

*Yeyland Wutani LLC — IT Consulting & Cybersecurity Services*
*For support or issues: https://github.com/the-last-one-left/YeylandWutani/issues*
