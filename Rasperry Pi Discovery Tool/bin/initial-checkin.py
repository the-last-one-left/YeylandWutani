#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
initial-checkin.py - First Boot Connectivity Report

Runs once on first boot after network connectivity is established.
Gathers Pi and network info, sends a branded confirmation email via Graph API,
then writes a flag file to prevent re-running.
"""

import json
import logging
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Allow running from bin/ directory
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from graph_auth import GraphAuthError, load_credentials_from_config
from graph_mailer import GraphMailer, GraphMailerError, load_mailer_from_config
from network_utils import (
    get_default_gateway,
    get_dns_servers,
    get_hostname,
    get_network_interfaces,
    get_os_info,
    get_pi_model,
    reverse_dns,
)

# Paths
CONFIG_PATH = Path("/opt/network-discovery/config/config.json")
FLAG_FILE = Path("/opt/network-discovery/data/.checkin_complete")
LOG_FILE = Path("/opt/network-discovery/logs/initial-checkin.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
logger = logging.getLogger("initial-checkin")


def already_checked_in() -> bool:
    return FLAG_FILE.exists()


def mark_checkin_complete():
    FLAG_FILE.parent.mkdir(parents=True, exist_ok=True)
    FLAG_FILE.write_text(datetime.now().isoformat())
    logger.info(f"Check-in flag written: {FLAG_FILE}")


def wait_for_connectivity(retries: int = 12, delay: int = 10) -> bool:
    """Wait for a default gateway to appear, indicating network is up."""
    logger.info("Waiting for network connectivity...")
    for attempt in range(1, retries + 1):
        gw = get_default_gateway()
        if gw:
            logger.info(f"Network up. Default gateway: {gw}")
            return True
        logger.info(f"No gateway yet (attempt {attempt}/{retries}). Waiting {delay}s...")
        time.sleep(delay)
    return False


def gather_system_info() -> dict:
    """Collect Pi hardware, OS, and network information."""
    info = {
        "timestamp": datetime.now().isoformat(),
        "hostname": get_hostname(),
        "pi_model": get_pi_model(),
        "os_info": get_os_info(),
        "python_version": platform.python_version(),
        "interfaces": [],
        "default_gateway": None,
        "gateway_hostname": None,
        "dns_servers": [],
        "uptime": _get_uptime(),
        "boot_time": _get_boot_time(),
    }

    # Network interfaces
    interfaces = get_network_interfaces()
    info["interfaces"] = interfaces
    logger.info(f"Discovered {len(interfaces)} network interface(s)")

    # Gateway
    gw = get_default_gateway()
    info["default_gateway"] = gw
    if gw:
        info["gateway_hostname"] = reverse_dns(gw) or "N/A"
        logger.info(f"Gateway: {gw} ({info['gateway_hostname']})")

    # DNS
    info["dns_servers"] = get_dns_servers()
    logger.info(f"DNS servers: {info['dns_servers']}")

    return info


def _get_uptime() -> str:
    try:
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
        mins, secs = divmod(int(secs), 60)
        hours, mins = divmod(mins, 60)
        return f"{hours}h {mins}m {secs}s"
    except Exception:
        return "Unknown"


def _get_boot_time() -> str:
    try:
        result = subprocess.check_output(["who", "-b"], text=True, timeout=5)
        match = result.strip()
        return match if match else "Unknown"
    except Exception:
        return "Unknown"


def _run_self_update() -> bool:
    """
    Pull the latest code from GitHub before sending the check-in email.
    This ensures all deployed Pis automatically pick up code changes on boot.

    Returns True if an actual update was applied, False otherwise.
    Non-fatal: any failure is logged as a warning and execution continues.
    """
    update_script = Path(__file__).parent / "self-update.sh"
    if not update_script.exists():
        logger.debug("self-update.sh not found, skipping auto-update.")
        return False

    logger.info("Running self-update from GitHub...")
    try:
        result = subprocess.run(
            ["/bin/bash", str(update_script)],
            capture_output=True,
            text=True,
            timeout=90,  # Allow up to 90s for slow connections
        )
        if result.returncode != 0:
            logger.warning(f"self-update.sh exited with code {result.returncode}")
        if "UPDATED" in result.stdout:
            logger.info("Self-update applied — code updated from GitHub.")
            return True
        else:
            logger.info("Self-update: already up to date or skipped.")
            return False
    except subprocess.TimeoutExpired:
        logger.warning("Self-update timed out after 90s, continuing with check-in...")
        return False
    except Exception as e:
        logger.warning(f"Self-update failed: {e}. Continuing with check-in...")
        return False


def build_checkin_email(info: dict, config: dict) -> tuple:
    """Build the subject and HTML body for the check-in email."""
    company_name = config.get("reporting", {}).get("company_name", "Pacific Office Automation Inc.")
    company_color = config.get("reporting", {}).get("company_color", "#00A0D9")
    tagline = config.get("reporting", {}).get("tagline", "Problem Solved.")
    device_name = config.get("system", {}).get("device_name", "NetDiscovery-Pi")

    hostname = info.get("hostname", "unknown")
    pi_model = info.get("pi_model", "Raspberry Pi")
    os_info = info.get("os_info", "Raspberry Pi OS")
    gateway = info.get("default_gateway", "N/A")
    gateway_hostname = info.get("gateway_hostname", "N/A")
    dns_servers = ", ".join(info.get("dns_servers", [])) or "N/A"
    uptime = info.get("uptime", "N/A")
    timestamp = info.get("timestamp", datetime.now().isoformat())

    # Build interface rows
    iface_rows = ""
    for iface in info.get("interfaces", []):
        iface_rows += f"""
        <tr>
          <td style="padding:6px 12px; border-bottom:1px solid #e8e8e8;">{iface.get('name', 'N/A')}</td>
          <td style="padding:6px 12px; border-bottom:1px solid #e8e8e8;">{iface.get('ip', 'N/A')}</td>
          <td style="padding:6px 12px; border-bottom:1px solid #e8e8e8;">{iface.get('cidr', 'N/A')}</td>
          <td style="padding:6px 12px; border-bottom:1px solid #e8e8e8;">{iface.get('mac', 'N/A')}</td>
        </tr>"""

    subject = f"[Network Discovery Pi] Initial Check-In: {hostname} is online"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Discovery Pi - Initial Check-In</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f4f4; font-family:Arial, Helvetica, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f4; padding:20px 0;">
    <tr>
      <td align="center">
        <table width="640" cellpadding="0" cellspacing="0" style="background:#ffffff; border-radius:4px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,0.1);">

          <!-- Header -->
          <tr>
            <td style="background-color:{company_color}; padding:28px 32px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td>
                    <div style="color:#ffffff; font-size:22px; font-weight:bold; letter-spacing:0.5px;">
                      {company_name}
                    </div>
                    <div style="color:rgba(255,255,255,0.85); font-size:13px; margin-top:4px;">
                      Network Discovery Pi &bull; Initial Check-In Report
                    </div>
                  </td>
                  <td align="right" style="vertical-align:middle;">
                    <div style="color:rgba(255,255,255,0.9); font-size:12px; font-style:italic; text-align:right;">
                      {tagline}
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Status Banner -->
          <tr>
            <td style="background-color:#e8f7ff; border-left:4px solid {company_color}; padding:16px 32px;">
              <span style="color:#00628a; font-size:15px; font-weight:bold;">
                &#10003; Device Online &amp; Connected
              </span>
              <span style="color:#555; font-size:13px; margin-left:16px;">
                {timestamp}
              </span>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:28px 32px;">

              <p style="color:#333; font-size:14px; margin:0 0 20px 0;">
                Your Network Discovery Pi (<strong>{device_name}</strong>) has connected to the customer network
                and is ready to begin discovery. This is the initial connectivity confirmation.
              </p>

              <!-- Device Info -->
              <h2 style="color:{company_color}; font-size:16px; margin:0 0 12px 0; border-bottom:2px solid {company_color}; padding-bottom:6px;">
                Device Information
              </h2>
              <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
                <tr>
                  <td style="padding:5px 0; color:#555; font-size:13px; width:160px;">Hostname</td>
                  <td style="padding:5px 0; color:#222; font-size:13px; font-weight:bold;">{hostname}</td>
                </tr>
                <tr>
                  <td style="padding:5px 0; color:#555; font-size:13px;">Device Name</td>
                  <td style="padding:5px 0; color:#222; font-size:13px;">{device_name}</td>
                </tr>
                <tr>
                  <td style="padding:5px 0; color:#555; font-size:13px;">Pi Model</td>
                  <td style="padding:5px 0; color:#222; font-size:13px;">{pi_model}</td>
                </tr>
                <tr>
                  <td style="padding:5px 0; color:#555; font-size:13px;">Operating System</td>
                  <td style="padding:5px 0; color:#222; font-size:13px;">{os_info}</td>
                </tr>
                <tr>
                  <td style="padding:5px 0; color:#555; font-size:13px;">Uptime</td>
                  <td style="padding:5px 0; color:#222; font-size:13px;">{uptime}</td>
                </tr>
              </table>

              <!-- Network Info -->
              <h2 style="color:{company_color}; font-size:16px; margin:0 0 12px 0; border-bottom:2px solid {company_color}; padding-bottom:6px;">
                Network Information
              </h2>
              <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
                <tr>
                  <td style="padding:5px 0; color:#555; font-size:13px; width:160px;">Default Gateway</td>
                  <td style="padding:5px 0; color:#222; font-size:13px; font-weight:bold;">{gateway}</td>
                </tr>
                <tr>
                  <td style="padding:5px 0; color:#555; font-size:13px;">Gateway Hostname</td>
                  <td style="padding:5px 0; color:#222; font-size:13px;">{gateway_hostname}</td>
                </tr>
                <tr>
                  <td style="padding:5px 0; color:#555; font-size:13px;">DNS Servers</td>
                  <td style="padding:5px 0; color:#222; font-size:13px;">{dns_servers}</td>
                </tr>
              </table>

              <!-- Interface Table -->
              <h2 style="color:{company_color}; font-size:16px; margin:0 0 12px 0; border-bottom:2px solid {company_color}; padding-bottom:6px;">
                Network Interfaces
              </h2>
              <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; margin-bottom:24px;">
                <tr style="background-color:{company_color}; color:#ffffff;">
                  <th style="padding:8px 12px; text-align:left; font-size:12px; font-weight:bold;">Interface</th>
                  <th style="padding:8px 12px; text-align:left; font-size:12px; font-weight:bold;">IP Address</th>
                  <th style="padding:8px 12px; text-align:left; font-size:12px; font-weight:bold;">Network (CIDR)</th>
                  <th style="padding:8px 12px; text-align:left; font-size:12px; font-weight:bold;">MAC Address</th>
                </tr>
                {iface_rows}
              </table>

              <p style="color:#555; font-size:13px; margin:20px 0 0 0;">
                Full network discovery will begin shortly. You will receive a comprehensive report
                when scanning is complete.
              </p>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color:#f8f8f8; border-top:1px solid #e8e8e8; padding:16px 32px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="color:#888; font-size:11px;">
                    Powered by <strong style="color:{company_color};">Yeyland Wutani</strong> Network Discovery Pi
                    &bull; {company_name} &bull; <em>{tagline}</em>
                  </td>
                  <td align="right" style="color:#bbb; font-size:11px;">
                    {timestamp}
                  </td>
                </tr>
              </table>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    return subject, html


def load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Could not load config.json ({e}). Using defaults.")
        return {}


def main():
    logger.info("=" * 60)
    logger.info("Yeyland Wutani - Network Discovery Pi: Initial Check-In")
    logger.info("=" * 60)

    # Check if already done
    if already_checked_in():
        logger.info("Check-in already completed. Exiting.")
        sys.exit(0)

    # Wait for connectivity
    if not wait_for_connectivity():
        logger.error("Network connectivity not established after waiting. Exiting.")
        sys.exit(1)

    # Auto-update from GitHub before proceeding (non-fatal if it fails)
    _run_self_update()

    # Gather system info
    logger.info("Gathering system information...")
    info = gather_system_info()

    # Load config
    config = load_config()

    # Build email
    logger.info("Building check-in email...")
    subject, body_html = build_checkin_email(info, config)

    # Send email
    try:
        mailer = load_mailer_from_config(str(CONFIG_PATH))
        logger.info(f"Sending check-in email: {subject}")
        mailer.send_email(subject=subject, body_html=body_html)
        logger.info("Check-in email sent successfully.")
    except (GraphMailerError, GraphAuthError) as e:
        logger.error(f"Failed to send check-in email: {e}")
        sys.exit(1)

    # Mark complete
    mark_checkin_complete()
    logger.info("Initial check-in complete.")
    sys.exit(0)


if __name__ == "__main__":
    main()
