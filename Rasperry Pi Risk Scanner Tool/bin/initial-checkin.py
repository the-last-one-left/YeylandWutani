#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Pi
initial-checkin.py - First-boot check-in email
Sends once after install to confirm deployment. Sets flag file on success.
"""

import html
import json
import logging
import logging.handlers
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# Ensure lib/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

# Paths
BASE_DIR = Path("/opt/risk-scanner")
CONFIG_PATH = BASE_DIR / "config" / "config.json"
LOG_FILE = BASE_DIR / "logs" / "initial-checkin.log"
DATA_DIR = BASE_DIR / "data"
CHECKIN_FLAG = DATA_DIR / ".checkin_sent"
VULN_DB_PATH = DATA_DIR / "vuln-db" / "nvd-cache.json"

# Logging — always log to file and stderr
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
_log_format = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
_file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
)
_file_handler.setFormatter(logging.Formatter(_log_format))
logging.basicConfig(
    level=logging.INFO,
    format=_log_format,
    handlers=[
        logging.StreamHandler(sys.stderr),
        _file_handler,
    ],
)
logger = logging.getLogger("initial-checkin")


# ── Connectivity ─────────────────────────────────────────────────────────────

def wait_for_connectivity(timeout: int = 300, interval: int = 15) -> bool:
    """Ping 8.8.8.8 until success or timeout. Log attempt count."""
    deadline = time.time() + timeout
    attempt = 0
    logger.info("Waiting for network connectivity (timeout: %ds, interval: %ds)...", timeout, interval)

    while time.time() < deadline:
        attempt += 1
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "3", "8.8.8.8"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("Network connectivity confirmed on attempt %d.", attempt)
                return True
        except (subprocess.TimeoutExpired, OSError):
            pass

        remaining = deadline - time.time()
        logger.info("No connectivity yet (attempt %d). Retrying in %ds (%.0fs remaining)...",
                    attempt, interval, max(0, remaining))
        if remaining > interval:
            time.sleep(interval)
        elif remaining > 0:
            time.sleep(remaining)
        else:
            break

    logger.error("Network connectivity not established after %d attempt(s) (%ds).", attempt, timeout)
    return False


# ── System info ───────────────────────────────────────────────────────────────

def gather_system_info(config: dict) -> dict:
    """Collect hostname, interfaces, WAN IP, OS version, Python version, disk usage, uptime."""
    logger.info("Gathering system information...")
    t0 = time.time()

    info = {
        "timestamp": datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "interfaces": _get_interfaces(),
        "wan_ip": _get_wan_ip(),
        "os_info": _get_os_release(),
        "python_version": sys.version.split()[0],
        "disk_usage": _get_disk_usage(),
        "uptime": _get_uptime(),
    }

    logger.info("  Hostname: %s", info["hostname"])
    logger.info("  OS: %s", info["os_info"].get("PRETTY_NAME", "Unknown"))
    logger.info("  Python: %s", info["python_version"])
    logger.info("  WAN IP: %s", info["wan_ip"] or "unavailable")
    logger.info("  Uptime: %s", info["uptime"])
    disk = info["disk_usage"]
    logger.info(
        "  Disk (/opt/risk-scanner): %.1f GB total, %.1f GB free (%.0f%%)",
        disk.get("total_gb", 0), disk.get("free_gb", 0), disk.get("free_pct", 0),
    )
    logger.info("System info gathered in %.1fs.", time.time() - t0)
    return info


def _get_interfaces() -> list:
    """Return list of {name, ip, mac, cidr} for all non-loopback interfaces."""
    interfaces = []
    try:
        import ipaddress
        result = subprocess.run(
            ["ip", "-j", "addr", "show"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for iface in json.loads(result.stdout):
                name = iface.get("ifname", "")
                if name == "lo":
                    continue
                mac = iface.get("address", "")
                for addr_info in iface.get("addr_info", []):
                    if addr_info.get("family") == "inet":
                        ip = addr_info.get("local", "")
                        prefix = addr_info.get("prefixlen", 24)
                        interfaces.append({
                            "name": name,
                            "ip": ip,
                            "mac": mac,
                            "cidr": f"{ip}/{prefix}",
                        })
            return interfaces
    except Exception as e:
        logger.debug("ip -j addr failed: %s — falling back to socket", e)

    # Fallback: hostname resolution only
    try:
        ip = socket.gethostbyname(socket.gethostname())
        interfaces.append({"name": "eth0", "ip": ip, "mac": "", "cidr": ""})
    except Exception:
        pass
    return interfaces


def _get_wan_ip() -> str:
    """Fetch public IP from ipify.org."""
    import urllib.request
    import urllib.error
    providers = [
        ("https://api.ipify.org", "text"),
        ("https://checkip.amazonaws.com", "text"),
        ("https://api4.my-ip.io/ip.json", "json_ip"),
    ]
    for url, fmt in providers:
        try:
            with urllib.request.urlopen(url, timeout=8) as resp:
                raw = resp.read().decode("utf-8").strip()
            if fmt == "json_ip":
                raw = json.loads(raw).get("ip", "")
            if raw:
                return raw
        except Exception as exc:
            logger.debug("WAN IP lookup failed (%s): %s", url, exc)
    return ""


def _get_os_release() -> dict:
    """Parse /etc/os-release into a dict."""
    info = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, _, v = line.partition("=")
                    info[k.strip()] = v.strip().strip('"')
    except Exception as e:
        logger.debug("Could not read /etc/os-release: %s", e)
        info["PRETTY_NAME"] = "Unknown OS"
    return info


def _get_disk_usage() -> dict:
    """Return disk usage for /opt/risk-scanner (or / as fallback)."""
    import shutil
    for path in [str(BASE_DIR), "/"]:
        try:
            usage = shutil.disk_usage(path)
            return {
                "path": path,
                "total_gb": usage.total / (1024 ** 3),
                "used_gb": usage.used / (1024 ** 3),
                "free_gb": usage.free / (1024 ** 3),
                "free_pct": usage.free / max(usage.total, 1) * 100,
            }
        except Exception:
            continue
    return {}


def _get_uptime() -> str:
    """Read uptime from /proc/uptime."""
    try:
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
        mins, secs = divmod(int(secs), 60)
        hours, mins = divmod(mins, 60)
        days, hours = divmod(hours, 24)
        if days > 0:
            return f"{days}d {hours}h {mins}m"
        return f"{hours}h {mins}m {secs}s"
    except Exception as e:
        logger.debug("Could not read uptime: %s", e)
        return "Unknown"


# ── Vulnerability DB status ───────────────────────────────────────────────────

def get_vuln_db_status() -> dict:
    """Read vuln DB mtime, stats, and staleness."""
    status = {
        "last_updated": None,
        "cve_count": 0,
        "kev_count": 0,
        "stale": True,
    }

    if not VULN_DB_PATH.exists():
        status["error"] = "Database not found"
        return status

    mtime = VULN_DB_PATH.stat().st_mtime
    age_days = (time.time() - mtime) / 86400
    status["last_updated"] = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
    status["stale"] = age_days > 3

    try:
        from vuln_db import get_db_stats
        db_stats = get_db_stats()
        status["cve_count"] = db_stats.get("cve_count", 0)
        status["kev_count"] = db_stats.get("kev_count", 0)
        status.update(db_stats)
    except ImportError:
        logger.debug("vuln_db module not available; reading cache directly for stats.")
        try:
            with open(VULN_DB_PATH) as f:
                cache = json.load(f)
            status["cve_count"] = len(cache.get("vulnerabilities", cache.get("cves", [])))
        except Exception as e:
            logger.debug("Could not read vuln DB for stats: %s", e)

    return status


# ── Credential summary ────────────────────────────────────────────────────────

def get_credential_summary(config: dict) -> dict:
    """Count credentials by type. NEVER log passwords."""
    summary = {"total": 0, "ssh": 0, "wmi": 0, "snmp": 0}
    try:
        from credential_store import load_credentials
        creds = load_credentials(config)
        for cred in creds:
            cred_type = cred.get("type", "").lower()
            summary["total"] += 1
            if cred_type in summary:
                summary[cred_type] += 1
    except ImportError:
        logger.debug("credential_store module not available — using config directly.")
        cred_profiles = config.get("credentials", {}).get("profiles", [])
        for profile in cred_profiles:
            cred_type = profile.get("type", "").lower()
            summary["total"] += 1
            if cred_type in ("ssh", "wmi", "snmp"):
                summary[cred_type] += 1
    except Exception as e:
        logger.warning("Could not load credential summary: %s", e)

    logger.info(
        "Credential profiles: total=%d, ssh=%d, wmi=%d, snmp=%d",
        summary["total"], summary["ssh"], summary["wmi"], summary["snmp"],
    )
    return summary


# ── Next scan times ───────────────────────────────────────────────────────────

def get_next_scan_times(config: dict) -> dict:
    """Parse scan_schedule and compute next daily scan and weekly report times."""
    schedule = config.get("scan_schedule", {})
    daily_time_str = schedule.get("daily_time", "02:00")
    report_day_str = schedule.get("weekly_report_day", "monday").lower()
    report_time_str = schedule.get("weekly_report_time", "06:00")

    weekday_map = {
        "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
        "friday": 4, "saturday": 5, "sunday": 6,
    }

    now = datetime.now()

    def _next_time_today_or_tomorrow(time_str: str) -> datetime:
        hour, minute = (int(p) for p in time_str.split(":"))
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate

    def _next_weekday(target_weekday: int, time_str: str) -> datetime:
        hour, minute = (int(p) for p in time_str.split(":"))
        days_ahead = (target_weekday - now.weekday()) % 7
        candidate = (now + timedelta(days=days_ahead)).replace(
            hour=hour, minute=minute, second=0, microsecond=0
        )
        if candidate <= now:
            candidate += timedelta(weeks=1)
        return candidate

    try:
        next_scan = _next_time_today_or_tomorrow(daily_time_str)
    except Exception:
        next_scan = now + timedelta(hours=24)

    try:
        target_wd = weekday_map.get(report_day_str, 0)
        next_report = _next_weekday(target_wd, report_time_str)
    except Exception:
        next_report = now + timedelta(days=7)

    return {
        "next_scan": next_scan.strftime("%Y-%m-%d %H:%M"),
        "next_report": next_report.strftime("%Y-%m-%d %H:%M"),
        "daily_time": daily_time_str,
        "report_day": report_day_str.capitalize(),
    }


# ── Email builder ─────────────────────────────────────────────────────────────

def build_checkin_email(
    system_info: dict,
    vuln_status: dict,
    cred_summary: dict,
    next_times: dict,
    config: dict,
) -> str:
    """Return HTML email body for the deployment check-in."""
    company_name = config.get("reporting", {}).get("company_name", "Yeyland Wutani LLC")
    company_color = config.get("reporting", {}).get("company_color", "#FF6600")
    tagline = config.get("reporting", {}).get("tagline", "Building Better Systems")
    client_name = config.get("reporting", {}).get("client_name", "Client")
    device_name = config.get("system", {}).get("device_name", "RiskScanner-Pi")

    def _e(v) -> str:
        return html.escape(str(v)) if v else "N/A"

    hostname = _e(system_info.get("hostname"))
    timestamp = _e(system_info.get("timestamp", datetime.now().isoformat()))
    os_info = system_info.get("os_info", {})
    os_str = _e(os_info.get("PRETTY_NAME", os_info.get("NAME", "Unknown OS")))
    py_ver = _e(system_info.get("python_version"))
    wan_ip = _e(system_info.get("wan_ip")) or "Unavailable"
    uptime = _e(system_info.get("uptime"))
    disk = system_info.get("disk_usage", {})
    disk_str = "N/A"
    if disk:
        disk_str = (
            f"{disk.get('free_gb', 0):.1f} GB free of "
            f"{disk.get('total_gb', 0):.1f} GB "
            f"({disk.get('free_pct', 0):.0f}% free)"
        )

    # Interface rows
    iface_rows = ""
    for iface in system_info.get("interfaces", []):
        iface_rows += (
            f"<tr>"
            f"<td style='padding:6px 10px; border-bottom:1px solid #eee;'>{_e(iface.get('name'))}</td>"
            f"<td style='padding:6px 10px; border-bottom:1px solid #eee;'>{_e(iface.get('ip'))}</td>"
            f"<td style='padding:6px 10px; border-bottom:1px solid #eee;'>{_e(iface.get('mac'))}</td>"
            f"<td style='padding:6px 10px; border-bottom:1px solid #eee;'>{_e(iface.get('cidr'))}</td>"
            f"</tr>"
        )
    if not iface_rows:
        iface_rows = "<tr><td colspan='4' style='padding:8px 10px; color:#888;'>No interfaces detected</td></tr>"

    # Vuln DB section
    db_last = _e(vuln_status.get("last_updated")) or "Never"
    db_cve = _e(vuln_status.get("cve_count", 0))
    db_kev = _e(vuln_status.get("kev_count", 0))
    db_stale = vuln_status.get("stale", True)
    stale_html = ""
    if db_stale:
        stale_html = (
            "<tr><td colspan='2' style='padding:6px 10px; color:#c0392b; font-weight:bold;'>"
            "&#9888; Database is stale (&gt;3 days old) — run update-vuln-db.py --update"
            "</td></tr>"
        )
    db_error = _e(vuln_status.get("error", "")) if vuln_status.get("error") else ""
    db_error_html = (
        f"<tr><td colspan='2' style='padding:6px 10px; color:#c0392b;'>"
        f"Error: {db_error}</td></tr>" if db_error else ""
    )

    # Feature flags
    features = config.get("features", {})
    feature_rows = ""
    feature_map = {
        "enable_ai_insights": "AI Insights (Hatz)",
        "enable_executive_report": "Executive PDF Report",
        "enable_detail_report": "Detail PDF Report",
        "enable_authenticated_scan": "Authenticated Scanning",
        "enable_delta_reporting": "Delta/Change Reporting",
        "enable_kev_check": "CISA KEV Check",
    }
    for key, label in feature_map.items():
        enabled = features.get(key, False)
        color = "#27ae60" if enabled else "#bbb"
        badge = "Enabled" if enabled else "Disabled"
        feature_rows += (
            f"<tr>"
            f"<td style='padding:4px 10px; font-size:12px; color:#444;'>{html.escape(label)}</td>"
            f"<td style='padding:4px 10px; font-size:12px; color:{color}; font-weight:bold;'>{badge}</td>"
            f"</tr>"
        )

    ai_enabled = bool(config.get("hatz_ai", {}).get("api_key", ""))

    body_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Risk Scanner - Deployment Check-In</title>
</head>
<body style="margin:0; padding:0; background:#f4f4f4; font-family:Arial, Helvetica, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4; padding:20px 0;">
    <tr><td align="center">
      <table width="640" cellpadding="0" cellspacing="0"
             style="background:#fff; border-radius:4px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,.1);">

        <!-- Header -->
        <tr>
          <td style="background:{company_color}; padding:28px 32px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  <div style="color:#fff; font-size:22px; font-weight:bold;">{html.escape(company_name)}</div>
                  <div style="color:rgba(255,255,255,.85); font-size:13px; margin-top:4px;">
                    Risk Scanner Pi &bull; Deployment Check-In
                  </div>
                </td>
                <td align="right">
                  <div style="color:rgba(255,255,255,.9); font-size:12px; font-style:italic;">
                    {html.escape(tagline)}
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Status banner -->
        <tr>
          <td style="background:#e8f7e8; border-left:4px solid {company_color}; padding:14px 32px;">
            <span style="color:#1a7a1a; font-size:15px; font-weight:bold;">
              &#10003; Risk Scanner deployed and online
            </span>
            <span style="color:#555; font-size:13px; margin-left:16px;">{timestamp}</span>
          </td>
        </tr>

        <tr><td style="padding:28px 32px;">

          <p style="color:#333; font-size:14px; margin:0 0 20px 0;">
            The Risk Scanner Pi (<strong>{_e(device_name)}</strong>) for <strong>{_e(client_name)}</strong>
            has completed its initial deployment and is ready to begin vulnerability scanning.
          </p>

          <!-- Device info -->
          <h2 style="color:{company_color}; font-size:15px; margin:0 0 10px 0;
                     border-bottom:2px solid {company_color}; padding-bottom:6px;">
            Device Information
          </h2>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:22px; font-size:13px;">
            <tr>
              <td style="padding:5px 0; color:#555; width:160px;">Hostname</td>
              <td style="padding:5px 0; color:#222; font-weight:bold;">{hostname}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">WAN / Public IP</td>
              <td style="padding:5px 0; color:#222; font-weight:bold;">{wan_ip}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">Operating System</td>
              <td style="padding:5px 0; color:#222;">{os_str}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">Python Version</td>
              <td style="padding:5px 0; color:#222;">{py_ver}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">Uptime</td>
              <td style="padding:5px 0; color:#222;">{uptime}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">Disk Space</td>
              <td style="padding:5px 0; color:#222;">{html.escape(disk_str)}</td>
            </tr>
          </table>

          <!-- Network interfaces -->
          <h2 style="color:{company_color}; font-size:15px; margin:0 0 10px 0;
                     border-bottom:2px solid {company_color}; padding-bottom:6px;">
            Network Interfaces
          </h2>
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="border-collapse:collapse; margin-bottom:22px; font-size:12px;">
            <tr style="background:{company_color}; color:#fff;">
              <th style="padding:7px 10px; text-align:left;">Interface</th>
              <th style="padding:7px 10px; text-align:left;">IP Address</th>
              <th style="padding:7px 10px; text-align:left;">MAC Address</th>
              <th style="padding:7px 10px; text-align:left;">CIDR</th>
            </tr>
            {iface_rows}
          </table>

          <!-- Schedule -->
          <h2 style="color:{company_color}; font-size:15px; margin:0 0 10px 0;
                     border-bottom:2px solid {company_color}; padding-bottom:6px;">
            Scan Schedule
          </h2>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:22px; font-size:13px;">
            <tr>
              <td style="padding:5px 0; color:#555; width:160px;">Daily Scan Time</td>
              <td style="padding:5px 0; color:#222;">{_e(next_times.get("daily_time"))}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">Next Scan</td>
              <td style="padding:5px 0; color:#222; font-weight:bold;">{_e(next_times.get("next_scan"))}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">Weekly Report Day</td>
              <td style="padding:5px 0; color:#222;">{_e(next_times.get("report_day"))}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">Next Report</td>
              <td style="padding:5px 0; color:#222; font-weight:bold;">{_e(next_times.get("next_report"))}</td>
            </tr>
          </table>

          <!-- Vulnerability DB -->
          <h2 style="color:{company_color}; font-size:15px; margin:0 0 10px 0;
                     border-bottom:2px solid {company_color}; padding-bottom:6px;">
            Vulnerability Database Status
          </h2>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:22px; font-size:13px;">
            <tr>
              <td style="padding:5px 0; color:#555; width:160px;">CVE Count</td>
              <td style="padding:5px 0; color:#222;">{db_cve}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">KEV Count</td>
              <td style="padding:5px 0; color:#222;">{db_kev}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">Last Updated</td>
              <td style="padding:5px 0; color:#222;">{db_last}</td>
            </tr>
            {stale_html}
            {db_error_html}
          </table>

          <!-- Credentials -->
          <h2 style="color:{company_color}; font-size:15px; margin:0 0 10px 0;
                     border-bottom:2px solid {company_color}; padding-bottom:6px;">
            Credential Profiles
          </h2>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:22px; font-size:13px;">
            <tr>
              <td style="padding:5px 0; color:#555; width:160px;">Total Profiles</td>
              <td style="padding:5px 0; color:#222; font-weight:bold;">{cred_summary.get("total", 0)}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">SSH Credentials</td>
              <td style="padding:5px 0; color:#222;">{cred_summary.get("ssh", 0)}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">WMI Credentials</td>
              <td style="padding:5px 0; color:#222;">{cred_summary.get("wmi", 0)}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">SNMP Community Strings</td>
              <td style="padding:5px 0; color:#222;">{cred_summary.get("snmp", 0)}</td>
            </tr>
          </table>

          <!-- Config summary -->
          <h2 style="color:{company_color}; font-size:15px; margin:0 0 10px 0;
                     border-bottom:2px solid {company_color}; padding-bottom:6px;">
            Configuration Summary
          </h2>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:22px; font-size:13px;">
            <tr>
              <td style="padding:5px 0; color:#555; width:160px;">Client</td>
              <td style="padding:5px 0; color:#222;">{_e(client_name)}</td>
            </tr>
            <tr>
              <td style="padding:5px 0; color:#555;">AI Insights</td>
              <td style="padding:5px 0; color:{'#27ae60' if ai_enabled else '#bbb'}; font-weight:bold;">
                {'Enabled' if ai_enabled else 'Disabled (no API key)'}
              </td>
            </tr>
            {feature_rows}
          </table>

        </td></tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f8f8f8; border-top:1px solid #e8e8e8; padding:14px 32px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="color:#888; font-size:11px;">
                  Powered by <strong style="color:{company_color};">Yeyland Wutani LLC</strong>
                  &bull; <em>{html.escape(tagline)}</em>
                </td>
                <td align="right" style="color:#bbb; font-size:11px;">{timestamp}</td>
              </tr>
            </table>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""

    return body_html


# ── Self-update ───────────────────────────────────────────────────────────────

def _run_self_update():
    """Run /opt/risk-scanner/bin/self-update.sh. Non-fatal."""
    update_script = BASE_DIR / "bin" / "self-update.sh"
    if not update_script.exists():
        logger.debug("self-update.sh not found, skipping.")
        return

    logger.info("Running self-update from %s...", update_script)
    t0 = time.time()
    try:
        result = subprocess.run(
            ["/bin/bash", str(update_script)],
            capture_output=True,
            text=True,
            timeout=90,
        )
        elapsed = time.time() - t0
        if result.returncode != 0:
            logger.warning(
                "self-update.sh exited %d after %.1fs. stderr: %s",
                result.returncode, elapsed,
                result.stderr.strip()[:300],
            )
        elif "UPDATED" in result.stdout:
            logger.info("Self-update applied in %.1fs — code updated from GitHub.", elapsed)
        else:
            logger.info("Self-update: already up to date (%.1fs).", elapsed)
    except subprocess.TimeoutExpired:
        logger.warning("Self-update timed out after 90s. Continuing.")
    except Exception as e:
        logger.warning("Self-update failed: %s. Continuing.", e)


# ── Config loader ─────────────────────────────────────────────────────────────

def _load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Could not load config.json (%s). Using defaults.", e)
        return {}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    logger.info("=" * 60)
    logger.info("Yeyland Wutani - Risk Scanner Pi: Initial Check-In")
    logger.info("=" * 60)

    # If flag file exists, this Pi has already checked in successfully
    if CHECKIN_FLAG.exists():
        logger.info("Check-in flag file exists (%s). Already checked in — exiting.", CHECKIN_FLAG)
        sys.exit(0)

    # Self-update before anything else (pull latest code)
    _run_self_update()

    # Wait for internet connectivity
    if not wait_for_connectivity(timeout=300, interval=15):
        logger.error("Could not establish connectivity within 5 minutes. Exiting.")
        sys.exit(1)

    # Brief settle delay for DNS and routing to stabilise
    logger.info("Network up. Waiting 15s for DNS/routing to settle...")
    time.sleep(15)

    config = _load_config()

    # Gather all info
    system_info = gather_system_info(config)
    vuln_status = get_vuln_db_status()
    cred_summary = get_credential_summary(config)
    next_times = get_next_scan_times(config)

    logger.info("Building check-in email...")
    body_html = build_checkin_email(system_info, vuln_status, cred_summary, next_times, config)

    client_name = config.get("reporting", {}).get("client_name", "Client")
    hostname = system_info.get("hostname", "unknown")
    subject = f"[Risk Scanner] Deployment Check-In: {hostname} — {client_name}"

    # Send via Graph API
    try:
        from graph_mailer import load_mailer_from_config, GraphMailerError
        mailer = load_mailer_from_config(str(CONFIG_PATH))
        logger.info("Sending check-in email: %s", subject)
        t0 = time.time()
        mailer.send_email(subject=subject, body_html=body_html)
        logger.info("Check-in email sent in %.1fs.", time.time() - t0)
    except Exception as e:
        logger.error("Failed to send check-in email: %s", e, exc_info=True)
        sys.exit(1)

    # Write flag file to prevent future re-runs
    try:
        CHECKIN_FLAG.parent.mkdir(parents=True, exist_ok=True)
        CHECKIN_FLAG.write_text(datetime.now().isoformat())
        logger.info("Flag file written: %s", CHECKIN_FLAG)
    except Exception as e:
        logger.warning("Could not write flag file: %s", e)

    logger.info("Initial check-in complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
