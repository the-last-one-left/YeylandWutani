#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
health-check.py - Weekly System Health Report

Runs on a weekly systemd timer. Checks Pi system health (disk, RAM, CPU temp,
service status, scan age) and sends a brief status email via the Graph API.

If all checks pass: sends "All systems nominal" confirmation.
If any issue is found: sends a summary of issues found with severity.
"""

import json
import logging
import shutil
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Allow running from bin/ directory
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from graph_mailer import GraphMailer, GraphMailerError, load_mailer_from_config

# ── Paths ─────────────────────────────────────────────────────────────────────
INSTALL_DIR = Path("/opt/network-discovery")
CONFIG_PATH = INSTALL_DIR / "config" / "config.json"
DATA_DIR = INSTALL_DIR / "data"
LOG_FILE = INSTALL_DIR / "logs" / "health-check.log"

# ── Thresholds ────────────────────────────────────────────────────────────────
DISK_WARNING_PCT = 75     # Warn if disk > 75% full
DISK_CRITICAL_PCT = 90    # Critical if disk > 90% full
CPU_TEMP_WARNING = 70     # Warning if CPU temp > 70°C
CPU_TEMP_CRITICAL = 80    # Critical if CPU temp > 80°C
SCAN_AGE_WARNING_DAYS = 8  # Warn if last scan is > 8 days old
RAM_WARNING_PCT = 85      # Warn if RAM > 85% used

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(LOG_FILE), encoding="utf-8"),
    ],
)
logger = logging.getLogger("health-check")


def load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Could not load config: {e}")
        return {}


def check_disk() -> dict:
    """Check disk usage on the install partition."""
    try:
        usage = shutil.disk_usage(str(INSTALL_DIR))
        pct = int(usage.used / usage.total * 100)
        free_gb = usage.free / 1024 ** 3
        total_gb = usage.total / 1024 ** 3
        result = {
            "check": "Disk Space",
            "value": f"{pct}% used ({free_gb:.1f} GB free of {total_gb:.1f} GB)",
            "pct": pct,
        }
        if pct >= DISK_CRITICAL_PCT:
            result.update({"status": "CRITICAL", "message": f"Disk {pct}% full — immediate action needed"})
        elif pct >= DISK_WARNING_PCT:
            result.update({"status": "WARNING", "message": f"Disk {pct}% full — consider cleanup"})
        else:
            result.update({"status": "OK", "message": f"Disk usage normal ({pct}%)"})
        return result
    except Exception as e:
        return {"check": "Disk Space", "status": "ERROR", "message": str(e), "value": "Unknown"}


def check_ram() -> dict:
    """Check RAM usage from /proc/meminfo."""
    try:
        meminfo = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
        total_kb = meminfo.get("MemTotal", 0)
        avail_kb = meminfo.get("MemAvailable", 0)
        if total_kb == 0:
            return {"check": "RAM", "status": "OK", "message": "Could not read meminfo", "value": "Unknown"}
        used_pct = int((total_kb - avail_kb) / total_kb * 100)
        avail_mb = avail_kb // 1024
        total_mb = total_kb // 1024
        result = {
            "check": "RAM",
            "value": f"{used_pct}% used ({avail_mb} MB free of {total_mb} MB)",
            "pct": used_pct,
        }
        if used_pct >= RAM_WARNING_PCT:
            result.update({"status": "WARNING", "message": f"RAM {used_pct}% used — only {avail_mb} MB free"})
        else:
            result.update({"status": "OK", "message": f"RAM usage normal ({used_pct}%)"})
        return result
    except Exception as e:
        return {"check": "RAM", "status": "ERROR", "message": str(e), "value": "Unknown"}


def check_cpu_temp() -> dict:
    """Check CPU temperature (Raspberry Pi specific)."""
    temp_file = Path("/sys/class/thermal/thermal_zone0/temp")
    if not temp_file.exists():
        return {"check": "CPU Temp", "status": "OK", "message": "Temperature sensor not available", "value": "N/A"}
    try:
        raw = int(temp_file.read_text().strip())
        temp_c = raw / 1000
        result = {
            "check": "CPU Temperature",
            "value": f"{temp_c:.1f}°C",
            "temp_c": temp_c,
        }
        if temp_c >= CPU_TEMP_CRITICAL:
            result.update({"status": "CRITICAL", "message": f"CPU temperature critical: {temp_c:.1f}°C"})
        elif temp_c >= CPU_TEMP_WARNING:
            result.update({"status": "WARNING", "message": f"CPU temperature high: {temp_c:.1f}°C"})
        else:
            result.update({"status": "OK", "message": f"CPU temperature normal ({temp_c:.1f}°C)"})
        return result
    except Exception as e:
        return {"check": "CPU Temperature", "status": "ERROR", "message": str(e), "value": "Unknown"}


def check_services() -> dict:
    """Check that the discovery service is active/enabled."""
    services_to_check = [
        ("network-discovery.service", "Network Discovery"),
        ("initial-checkin.service", "Initial Check-In"),
    ]
    results = []
    overall_status = "OK"
    for svc_name, label in services_to_check:
        try:
            proc = subprocess.run(
                ["systemctl", "is-enabled", svc_name],
                capture_output=True, text=True, timeout=5
            )
            enabled = proc.stdout.strip()
            proc2 = subprocess.run(
                ["systemctl", "is-active", svc_name],
                capture_output=True, text=True, timeout=5
            )
            active = proc2.stdout.strip()
            # For oneshot services, "inactive" is normal (they ran and exited)
            if enabled in ("enabled", "static") or active in ("active", "inactive"):
                results.append(f"{label}: {enabled}/{active}")
            else:
                results.append(f"{label}: {enabled}/{active} ⚠")
                overall_status = "WARNING"
        except Exception as e:
            results.append(f"{label}: error ({e})")
            overall_status = "WARNING"

    return {
        "check": "Systemd Services",
        "status": overall_status,
        "value": ", ".join(results),
        "message": "All services enabled" if overall_status == "OK" else "Service issue detected",
    }


def check_scan_age() -> dict:
    """Check when the last scan was completed."""
    scan_files = sorted(
        DATA_DIR.glob("scan_*.json"),
        key=lambda f: f.stat().st_mtime,
        reverse=True
    )
    if not scan_files:
        return {
            "check": "Last Scan",
            "status": "WARNING",
            "value": "No scan files found",
            "message": "No scan has been completed yet",
        }

    last_scan = scan_files[0]
    last_mtime = datetime.fromtimestamp(last_scan.stat().st_mtime)
    age_days = (datetime.now() - last_mtime).days
    age_str = f"{age_days} day(s) ago ({last_mtime.strftime('%Y-%m-%d %H:%M')})"

    if age_days > SCAN_AGE_WARNING_DAYS:
        return {
            "check": "Last Scan",
            "status": "WARNING",
            "value": age_str,
            "message": f"Last scan was {age_days} days ago — discovery may not be running",
        }
    return {
        "check": "Last Scan",
        "status": "OK",
        "value": age_str,
        "message": f"Last scan: {age_str}",
    }


def check_log_errors() -> dict:
    """Check discovery log for recent errors."""
    log_path = INSTALL_DIR / "logs" / "discovery.log"
    if not log_path.exists():
        return {"check": "Log Errors", "status": "OK", "value": "Log not found", "message": "No discovery log yet"}
    try:
        # Read last 200 lines of the log
        proc = subprocess.run(
            ["tail", "-n", "200", str(log_path)],
            capture_output=True, text=True, timeout=5
        )
        lines = proc.stdout.splitlines()
        error_lines = [l for l in lines if " [ERROR] " in l or " [CRITICAL] " in l]
        if error_lines:
            last_errors = error_lines[-3:]  # Show up to 3 most recent
            return {
                "check": "Log Errors",
                "status": "WARNING",
                "value": f"{len(error_lines)} errors in last 200 log lines",
                "message": "Recent errors: " + " | ".join(e[-80:] for e in last_errors),
            }
        return {"check": "Log Errors", "status": "OK", "value": "No errors in recent log", "message": "Log clean"}
    except Exception as e:
        return {"check": "Log Errors", "status": "OK", "value": f"Could not read log: {e}", "message": ""}


def build_health_email(checks: list, config: dict) -> tuple:
    """Build the health check email subject and HTML body."""
    company_name = config.get("reporting", {}).get("company_name", "Pacific Office Automation Inc.")
    company_color = config.get("reporting", {}).get("company_color", "#00A0D9")
    tagline = config.get("reporting", {}).get("tagline", "Problem Solved.")
    device_name = config.get("system", {}).get("device_name", "NetDiscovery-Pi")

    issues = [c for c in checks if c.get("status") in ("WARNING", "CRITICAL", "ERROR")]
    all_ok = len(issues) == 0
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    if all_ok:
        status_icon = "&#10003;"
        status_text = "All Systems Nominal"
        status_bg = "#d8f3dc"
        status_border = "#2d6a4f"
        status_text_color = "#1a5c2e"
        subject = f"[Network Discovery Pi] {device_name} — Weekly Health Check: All OK"
    else:
        critical_count = sum(1 for c in issues if c.get("status") == "CRITICAL")
        if critical_count > 0:
            status_icon = "&#9888;"
            status_text = f"{critical_count} Critical Issue(s) Found"
            status_bg = "#fff5f5"
            status_border = "#dc3545"
            status_text_color = "#8b0000"
        else:
            status_icon = "&#9888;"
            status_text = f"{len(issues)} Warning(s) Found"
            status_bg = "#fff8e6"
            status_border = "#fd7e14"
            status_text_color = "#7a4000"
        subject = f"[Network Discovery Pi] {device_name} — Weekly Health Check: {len(issues)} Issue(s)"

    # Build check rows
    check_rows = ""
    for c in checks:
        s = c.get("status", "OK")
        if s == "OK":
            row_bg = "#f8fff8"
            badge_bg = "#2d6a4f"
            badge_txt = "OK"
        elif s == "WARNING":
            row_bg = "#fffbe6"
            badge_bg = "#fd7e14"
            badge_txt = "WARN"
        elif s == "CRITICAL":
            row_bg = "#fff0f0"
            badge_bg = "#dc3545"
            badge_txt = "CRIT"
        else:
            row_bg = "#f5f5f5"
            badge_bg = "#888"
            badge_txt = "ERR"

        check_rows += f"""
          <tr style="background:{row_bg}; border-bottom:1px solid #eee;">
            <td style="padding:7px 10px; font-size:12px; font-weight:bold; color:#333;">{c.get('check', '')}</td>
            <td style="padding:7px 10px; font-size:12px; color:#555;">{c.get('value', '')}</td>
            <td style="padding:7px 10px; text-align:center;">
              <span style="background:{badge_bg}; color:#fff; padding:2px 6px; border-radius:3px; font-size:11px; font-weight:bold;">{badge_txt}</span>
            </td>
          </tr>"""

    # Issues summary
    issues_html = ""
    if issues:
        issue_items = ""
        for c in issues:
            sev = c.get("status", "WARNING")
            color = "#dc3545" if sev == "CRITICAL" else "#fd7e14"
            issue_items += f"""
          <li style="margin-bottom:6px; color:{color};">
            <strong>{c.get('check', '')}:</strong> {c.get('message', '')}
          </li>"""
        issues_html = f"""
          <div style="background:#fff8e6; border:1px solid #ffc107; border-left:4px solid #e69900; border-radius:3px; padding:12px 14px; margin-bottom:18px;">
            <div style="font-size:13px; font-weight:bold; color:#856404; margin-bottom:8px;">Issues Requiring Attention:</div>
            <ul style="margin:0; padding-left:18px; font-size:12px;">
              {issue_items}
            </ul>
          </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Network Discovery Pi - Weekly Health Check</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f4f4; font-family:Arial, Helvetica, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f4; padding:20px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:4px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,0.1);">

          <!-- Header -->
          <tr>
            <td style="background-color:{company_color}; padding:24px 28px;">
              <div style="color:#ffffff; font-size:20px; font-weight:bold;">{company_name}</div>
              <div style="color:rgba(255,255,255,0.85); font-size:12px; margin-top:3px;">
                Network Discovery Pi &bull; Weekly Health Check &bull; {device_name}
              </div>
            </td>
          </tr>

          <!-- Status Banner -->
          <tr>
            <td style="background-color:{status_bg}; border-left:4px solid {status_border}; padding:14px 28px;">
              <span style="color:{status_text_color}; font-size:15px; font-weight:bold;">
                {status_icon} {status_text}
              </span>
              <span style="color:#666; font-size:12px; margin-left:12px;">{timestamp}</span>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:24px 28px;">

              {issues_html}

              <h2 style="color:{company_color}; font-size:15px; margin:0 0 10px 0; border-bottom:2px solid {company_color}; padding-bottom:5px;">
                System Checks
              </h2>

              <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; font-size:12px;">
                <tr style="background:{company_color}; color:#fff;">
                  <th style="padding:7px 10px; text-align:left; font-size:11px;">Check</th>
                  <th style="padding:7px 10px; text-align:left; font-size:11px;">Value</th>
                  <th style="padding:7px 10px; text-align:center; font-size:11px; width:60px;">Status</th>
                </tr>
                {check_rows}
              </table>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color:#f8f8f8; border-top:1px solid #e8e8e8; padding:14px 28px;">
              <span style="color:#888; font-size:11px;">
                Powered by <strong style="color:{company_color};">Yeyland Wutani</strong>
                Network Discovery Pi &bull; {company_name} &bull; <em>{tagline}</em>
              </span>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    return subject, html


def main():
    logger.info("=" * 60)
    logger.info("Yeyland Wutani - Network Discovery Pi: Weekly Health Check")
    logger.info("=" * 60)

    config = load_config()
    device_name = config.get("system", {}).get("device_name", "NetDiscovery-Pi")
    logger.info(f"Device: {device_name}")

    # Run all checks
    checks = [
        check_disk(),
        check_ram(),
        check_cpu_temp(),
        check_services(),
        check_scan_age(),
        check_log_errors(),
    ]

    for c in checks:
        status = c.get("status", "OK")
        logger.info(f"  {c['check']}: {status} — {c.get('value', '')}")

    issues = [c for c in checks if c.get("status") in ("WARNING", "CRITICAL", "ERROR")]
    if issues:
        logger.warning(f"{len(issues)} health issue(s) found.")
    else:
        logger.info("All health checks passed.")

    # Build and send email
    subject, body_html = build_health_email(checks, config)

    try:
        mailer = load_mailer_from_config(str(CONFIG_PATH))
        logger.info(f"Sending health check email: {subject}")
        mailer.send_email(subject=subject, body_html=body_html)
        logger.info("Health check email sent successfully.")
    except Exception as e:
        logger.error(f"Failed to send health check email: {e}")
        sys.exit(1)

    logger.info("Health check complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
