#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
discovery-main.py - Main Orchestration Script

Orchestrates the full discovery workflow:
  1. Validate config + Graph API credentials
  2. Manage disk space — prune oldest scan archives if SD card is low
  3. Send "Discovery Starting" notification
  4. Run network scanner
  5. Generate HTML report
  6. Send report via Graph API (with CSV attachment)
  7. Archive scan data — remove uncompressed intermediaries after send
  8. Exit with appropriate status code
"""

import gzip
import html
import json
import logging
import logging.handlers
import os
import platform
import shutil
import signal
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path

# Ensure lib/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from graph_auth import GraphAuthError, load_credentials_from_config
from graph_mailer import GraphMailer, GraphMailerError, load_mailer_from_config
from report_generator import build_csv_attachment, build_discovery_report, build_error_email

# Paths
BASE_DIR = Path("/opt/network-discovery")
CONFIG_PATH = BASE_DIR / "config" / "config.json"
LOG_FILE = BASE_DIR / "logs" / "discovery.log"
DATA_DIR = BASE_DIR / "data"
LOCK_FILE = BASE_DIR / "data" / ".discovery.lock"

# Set up logging before anything else — rotating logs to avoid filling the SD card
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
_log_format = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
_file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
)
_file_handler.setFormatter(logging.Formatter(_log_format))
logging.basicConfig(
    level=logging.INFO,
    format=_log_format,
    handlers=[
        logging.StreamHandler(sys.stdout),
        _file_handler,
    ],
)
logger = logging.getLogger("discovery-main")

# ── Config loading ─────────────────────────────────────────────────────────

def load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        logger.info(f"Config loaded from {CONFIG_PATH}")
        return config
    except FileNotFoundError:
        logger.error(f"Config file not found: {CONFIG_PATH}")
        logger.error("Run the installer or copy config.json.template to config.json and configure it.")
        sys.exit(2)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {e}")
        sys.exit(2)


def apply_log_level(config: dict):
    level_str = config.get("system", {}).get("log_level", "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)
    logging.getLogger().setLevel(level)
    logger.debug(f"Log level set to {level_str}")


# ── Lock file (prevent concurrent runs) ───────────────────────────────────

def acquire_lock() -> bool:
    if LOCK_FILE.exists():
        try:
            raw = LOCK_FILE.read_text().strip()
            if not raw:
                raise ValueError("empty lock file")
            pid = int(raw)
            # Check if process is still running
            try:
                os.kill(pid, 0)
                logger.error(f"Another discovery instance is running (PID {pid}). Exiting.")
                return False
            except ProcessLookupError:
                logger.warning(f"Stale lock file (PID {pid} not running). Removing.")
                LOCK_FILE.unlink()
        except ValueError:
            logger.warning("Corrupt lock file detected (non-integer PID). Removing.")
            LOCK_FILE.unlink(missing_ok=True)
        except Exception:
            logger.warning("Could not read lock file. Removing.")
            LOCK_FILE.unlink(missing_ok=True)

    # Write lock atomically: write to temp file then rename, so a power loss
    # mid-write never leaves a truncated/corrupt lock file.
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(LOCK_FILE.parent), prefix=".lock_")
    try:
        os.write(fd, str(os.getpid()).encode())
    finally:
        os.close(fd)
    try:
        os.replace(tmp_path, str(LOCK_FILE))
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise
    return True


def release_lock():
    LOCK_FILE.unlink(missing_ok=True)


# ── Scan Archive Management ────────────────────────────────────────────────

def cleanup_after_send(timestamp_str: str):
    """Remove uncompressed intermediary files after a successful email send.

    The compressed .gz archives are retained for local reference.  The raw
    .csv and .json are only needed to build the email — once the email
    is confirmed sent we can safely delete them.
    """
    removed = 0
    for suffix in (".csv", ".json"):
        path = DATA_DIR / f"scan_{timestamp_str}{suffix}"
        try:
            if path.exists():
                path.unlink()
                removed += 1
        except Exception as e:
            logger.warning(f"Could not remove intermediary {path.name}: {e}")
    if removed:
        logger.info(f"Removed {removed} uncompressed intermediary file(s).")


def manage_disk_space(config: dict):
    """Check available disk space and prune oldest scan archives if low.

    Called early in startup to ensure there is enough room for the next
    scan.  Deletes the oldest .gz / .csv / .json scan files first, one
    at a time, until the free-space threshold is met or no files remain.
    """
    sys_cfg = config.get("system", {})
    min_free_mb = sys_cfg.get("min_free_disk_mb", 200)

    try:
        usage = shutil.disk_usage(str(DATA_DIR))
        free_mb = usage.free / (1024 * 1024)
    except Exception as e:
        logger.warning(f"Could not check disk space: {e}")
        return

    if free_mb >= min_free_mb:
        logger.info(f"Disk space OK: {free_mb:.0f} MB free (threshold: {min_free_mb} MB).")
        return

    logger.warning(
        f"Low disk space: {free_mb:.0f} MB free (threshold: {min_free_mb} MB). "
        "Pruning oldest scan archives..."
    )

    # Gather ALL scan artefacts, sort oldest first by modification time
    scan_files = sorted(
        [
            f
            for pattern in ("scan_*.json.gz", "scan_*.csv.gz", "scan_*.json", "scan_*.csv")
            for f in DATA_DIR.glob(pattern)
            if f.is_file()
        ],
        key=lambda f: f.stat().st_mtime,
    )

    removed = 0
    freed_bytes = 0
    for f in scan_files:
        try:
            size = f.stat().st_size
            f.unlink()
            freed_bytes += size
            removed += 1
            logger.info(f"  Pruned: {f.name} ({size / 1024:.0f} KB)")
        except Exception as e:
            logger.warning(f"  Could not remove {f.name}: {e}")

        # Re-check after each deletion
        try:
            usage = shutil.disk_usage(str(DATA_DIR))
            if usage.free / (1024 * 1024) >= min_free_mb:
                break
        except Exception:
            break

    if removed:
        logger.info(
            f"Pruned {removed} scan file(s), freed {freed_bytes / (1024 * 1024):.1f} MB."
        )
    else:
        logger.warning("No scan files available to prune. Disk may remain low.")


# ── Starting notification email ────────────────────────────────────────────

def send_starting_email(mailer: GraphMailer, config: dict):
    reporting = config.get("reporting", {})
    company_name = html.escape(reporting.get("company_name", "Yeyland Wutani LLC"))
    company_color = html.escape(reporting.get("company_color", "#FF6600"))
    tagline = html.escape(reporting.get("tagline", "Building Better Systems"))
    device_name = html.escape(config.get("system", {}).get("device_name", "NetDiscovery-Pi"))
    timestamp = html.escape(datetime.now().isoformat())

    subject = f"[Network Discovery Pi] Scan Starting on {device_name}"
    body_html = f"""<!DOCTYPE html>
<html lang="en">
<body style="margin:0; padding:20px; background:#f4f4f4; font-family:Arial, sans-serif;">
  <table width="600" cellpadding="0" cellspacing="0" style="background:#fff; border-radius:4px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,0.1); margin:auto;">
    <tr><td style="background:{company_color}; padding:24px 28px;">
      <div style="color:#fff; font-size:20px; font-weight:bold;">{company_name}</div>
      <div style="color:rgba(255,255,255,0.85); font-size:12px; margin-top:4px;">
        Network Discovery Pi &bull; Scan Starting
      </div>
    </td></tr>
    <tr><td style="background:#e8f7ff; border-left:4px solid {company_color}; padding:14px 28px;">
      <strong style="color:#00628a;">&#9654; Discovery scan is now running on {device_name}</strong>
    </td></tr>
    <tr><td style="padding:24px 28px;">
      <p style="color:#333; font-size:14px;">
        Full network discovery has started at <strong>{timestamp}</strong>.
        You will receive a comprehensive report when scanning completes.
      </p>
      <p style="color:#555; font-size:13px;">Scanning typically completes within 15 minutes for a typical SMB network.</p>
    </td></tr>
    <tr><td style="background:#f8f8f8; border-top:1px solid #e8e8e8; padding:14px 28px;">
      <span style="color:#888; font-size:11px;">
        Powered by <strong style="color:{company_color};">Yeyland Wutani</strong> &bull; {company_name} &bull; <em>{tagline}</em>
      </span>
    </td></tr>
  </table>
</body></html>"""

    try:
        mailer.send_email(subject=subject, body_html=body_html)
        logger.info("'Discovery Starting' notification sent.")
    except GraphMailerError as e:
        logger.warning(f"Could not send starting notification: {e}")


# ── Signal handling ────────────────────────────────────────────────────────

_shutdown_requested = False


def _handle_signal(signum, frame):
    global _shutdown_requested
    logger.warning(f"Signal {signum} received. Requesting graceful shutdown...")
    _shutdown_requested = True


signal.signal(signal.SIGTERM, _handle_signal)
signal.signal(signal.SIGINT, _handle_signal)


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    logger.info("=" * 70)
    logger.info("Yeyland Wutani - Network Discovery Pi: Starting Discovery")
    logger.info("=" * 70)

    # Log system environment for diagnostics
    try:
        uname = platform.uname()
        logger.info(f"System: {uname.system} {uname.release} ({uname.machine})")
        logger.info(f"Python: {platform.python_version()} ({sys.executable})")
        logger.info(f"PID: {os.getpid()}  |  User: {os.getenv('USER', 'unknown')}")
        usage = shutil.disk_usage(str(DATA_DIR))
        logger.info(
            f"Disk: {usage.total / (1024**3):.1f} GB total, "
            f"{usage.used / (1024**3):.1f} GB used, "
            f"{usage.free / (1024**3):.1f} GB free "
            f"({usage.free / max(usage.total, 1) * 100:.0f}%)"
        )
    except Exception as e:
        logger.warning(f"Could not gather system diagnostics: {e}")

    # Prevent concurrent runs
    if not acquire_lock():
        sys.exit(1)

    config = load_config()
    apply_log_level(config)

    # Log enabled feature flags so an engineer knows what will run
    nd = config.get("network_discovery", {})
    features = {
        "WiFi scan": nd.get("enable_wifi_scan", True),
        "mDNS": nd.get("enable_mdns", True),
        "UPnP/SSDP": nd.get("enable_upnp", True),
        "DHCP analysis": nd.get("enable_dhcp_analysis", True),
        "NTP check": nd.get("enable_ntp_check", True),
        "802.1X/NAC": nd.get("enable_dot1x_check", True),
        "OSINT": nd.get("enable_osint", True),
        "SSL audit": nd.get("enable_ssl_audit", True),
        "Backup/DR posture": nd.get("enable_backup_posture", True),
        "EOL detection": nd.get("enable_eol_detection", True),
    }
    enabled = [k for k, v in features.items() if v]
    disabled = [k for k, v in features.items() if not v]
    logger.info(f"Enabled features: {', '.join(enabled) if enabled else '(none)'}")
    if disabled:
        logger.info(f"Disabled features: {', '.join(disabled)}")

    # Prune oldest archives if disk space is low (before we generate new data)
    manage_disk_space(config)

    mailer = None
    scan_results = None
    exit_code = 0

    try:
        # Validate Graph API credentials
        logger.info("Validating Graph API credentials...")
        try:
            mailer = load_mailer_from_config(str(CONFIG_PATH))
            auth = mailer.auth
            if not auth.validate_credentials():
                raise GraphAuthError("Credential validation returned False")
            logger.info("Graph API credentials validated.")
        except (GraphAuthError, GraphMailerError) as e:
            logger.error(f"Graph API credential validation failed: {e}")
            logger.error("Discovery aborted. Fix credentials in config.json / .env and retry.")
            sys.exit(2)

        # Send starting notification
        send_starting_email(mailer, config)

        if _shutdown_requested:
            logger.info("Shutdown requested before scan start. Exiting cleanly.")
            sys.exit(0)

        # Run discovery
        logger.info("Starting network scanner...")
        # Import here to avoid import overhead before credentials are validated
        import importlib.util
        scanner_path = Path(__file__).parent / "network-scanner.py"
        spec = importlib.util.spec_from_file_location("network_scanner", scanner_path)
        scanner_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner_mod)

        scan_start = time.time()
        scan_results = scanner_mod.run_discovery(
            progress_callback=lambda msg: logger.info(f"[Scanner] {msg}")
        )
        scan_duration = time.time() - scan_start
        host_count = len(scan_results.get("hosts", []))
        logger.info(f"Network scan completed in {scan_duration:.1f}s — {host_count} host(s) found")

        if _shutdown_requested:
            logger.warning("Shutdown requested during scan. Sending partial results...")

        # Generate report
        logger.info("Generating discovery report...")
        report_start = time.time()
        subject, html_body = build_discovery_report(scan_results, config)
        report_duration = time.time() - report_start

        html_size_mb = len(html_body.encode("utf-8")) / (1024 * 1024)
        logger.info(f"HTML report generated in {report_duration:.1f}s ({html_size_mb:.2f} MB)")
        if html_size_mb > 3.0:
            logger.warning(f"HTML report is {html_size_mb:.1f} MB — may exceed Graph API limits.")

        # Build CSV attachment with gzip compression
        csv_start = time.time()
        csv_data = build_csv_attachment(scan_results.get("hosts", []), scan_results)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save raw CSV for local reference
        csv_path = DATA_DIR / f"scan_{timestamp_str}.csv"
        csv_path.write_bytes(csv_data)
        logger.info(f"CSV report saved: {csv_path} ({len(csv_data) / 1024:.0f} KB)")

        # Compress for email attachment
        csv_gz_path = DATA_DIR / f"scan_{timestamp_str}.csv.gz"
        with gzip.open(csv_gz_path, "wb", compresslevel=6) as gz:
            gz.write(csv_data)
        gz_size = csv_gz_path.stat().st_size
        logger.info(
            f"Compressed CSV: {gz_size / 1024:.0f} KB "
            f"({100 - gz_size / max(len(csv_data), 1) * 100:.0f}% reduction)"
        )

        # Also save the full scan JSON (gzipped) for archival
        json_data = json.dumps(scan_results, indent=2).encode("utf-8")
        json_gz_path = DATA_DIR / f"scan_{timestamp_str}.json.gz"
        with gzip.open(json_gz_path, "wb", compresslevel=6) as gz:
            gz.write(json_data)
        csv_duration = time.time() - csv_start
        logger.info(
            f"Compressed JSON report saved: {json_gz_path} — "
            f"archive build took {csv_duration:.1f}s"
        )

        # Send report with compressed CSV + JSON attachments
        total_attach_kb = (gz_size + json_gz_path.stat().st_size) / 1024
        logger.info(f"Sending discovery report email ({total_attach_kb:.0f} KB attachments)...")
        attachment_paths = [str(csv_gz_path), str(json_gz_path)]
        email_start = time.time()
        try:
            mailer.send_email(
                subject=subject,
                body_html=html_body,
                attachment_paths=attachment_paths,
            )
            email_duration = time.time() - email_start
            logger.info(f"Discovery report email sent successfully in {email_duration:.1f}s.")
            # Email confirmed sent — remove uncompressed intermediaries,
            # keep the .gz archives for local reference
            cleanup_after_send(timestamp_str)
        except GraphMailerError as e:
            email_duration = time.time() - email_start
            logger.error(
                f"Failed to send report email after {email_duration:.1f}s: {e}",
                exc_info=True,
            )
            logger.info("Keeping uncompressed files since email send failed.")
            exit_code = 1

        # Final summary
        summary = scan_results.get("summary", {})
        total_duration = time.time() - scan_start
        logger.info("-" * 50)
        logger.info("DISCOVERY RUN SUMMARY")
        logger.info(f"  Total duration:        {total_duration:.0f}s")
        logger.info(f"  Scan phase:            {scan_duration:.0f}s")
        logger.info(f"  Report generation:     {report_duration:.1f}s")
        logger.info(f"  Email delivery:        {email_duration:.1f}s")
        logger.info(f"  Hosts discovered:      {summary.get('total_hosts', 0)}")
        logger.info(f"  Open ports:            {summary.get('total_open_ports', 0)}")
        logger.info(f"  Security observations: {summary.get('security_observations', 0)}")
        logger.info("-" * 50)

    except Exception as e:
        logger.critical(f"Unhandled exception in discovery: {e}", exc_info=True)
        exit_code = 1

        # Attempt to send error notification
        if mailer:
            try:
                err_subject, err_html = build_error_email(str(e), config)
                mailer.send_email(subject=err_subject, body_html=err_html)
                logger.info("Error notification email sent.")
            except Exception as mail_err:
                logger.error(f"Could not send error notification: {mail_err}")

    finally:
        release_lock()
        logger.info(f"Discovery process finished with exit code {exit_code}.")
        logger.info("=" * 70)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
