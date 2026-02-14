#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
discovery-main.py - Main Orchestration Script

Orchestrates the full discovery workflow:
  1. Validate config + Graph API credentials
  2. Send "Discovery Starting" notification
  3. Run network scanner
  4. Generate HTML report
  5. Send report via Graph API (with CSV attachment)
  6. Clean up old scan data
  7. Exit with appropriate status code
"""

import gzip
import json
import logging
import os
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

# Set up logging before anything else
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
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


# ── Cleanup old scans ──────────────────────────────────────────────────────

def cleanup_old_scans(config: dict):
    days = config.get("system", {}).get("cleanup_old_scans_days", 7)
    cutoff = datetime.now() - timedelta(days=days)
    removed = 0
    for pattern in ("scan_*.json", "scan_*.csv", "scan_*.json.gz", "scan_*.csv.gz"):
        for f in DATA_DIR.glob(pattern):
            try:
                if datetime.fromtimestamp(f.stat().st_mtime) < cutoff:
                    f.unlink()
                    removed += 1
            except Exception:
                pass
    if removed:
        logger.info(f"Cleaned up {removed} old scan file(s) (>{days} days old).")


# ── Starting notification email ────────────────────────────────────────────

def send_starting_email(mailer: GraphMailer, config: dict):
    reporting = config.get("reporting", {})
    company_name = reporting.get("company_name", "Pacific Office Automation Inc.")
    company_color = reporting.get("company_color", "#00A0D9")
    tagline = reporting.get("tagline", "Problem Solved.")
    device_name = config.get("system", {}).get("device_name", "NetDiscovery-Pi")
    timestamp = datetime.now().isoformat()

    subject = f"[Network Discovery Pi] Scan Starting on {device_name}"
    html = f"""<!DOCTYPE html>
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
        mailer.send_email(subject=subject, body_html=html)
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

    # Prevent concurrent runs
    if not acquire_lock():
        sys.exit(1)

    config = load_config()
    apply_log_level(config)

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

        scan_results = scanner_mod.run_discovery(
            progress_callback=lambda msg: logger.info(f"[Scanner] {msg}")
        )

        if _shutdown_requested:
            logger.warning("Shutdown requested during scan. Sending partial results...")

        # Generate report
        logger.info("Generating discovery report...")
        subject, html_body = build_discovery_report(scan_results, config)

        html_size_mb = len(html_body.encode("utf-8")) / (1024 * 1024)
        if html_size_mb > 3.0:
            logger.warning(f"HTML report is {html_size_mb:.1f} MB — may exceed Graph API limits.")
        else:
            logger.info(f"HTML report size: {html_size_mb:.2f} MB")

        # Build CSV attachment with gzip compression
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
        logger.info(f"Compressed JSON report saved: {json_gz_path}")

        # Send report with compressed CSV + JSON attachments
        logger.info("Sending discovery report email...")
        attachment_paths = [str(csv_gz_path), str(json_gz_path)]
        try:
            mailer.send_email(
                subject=subject,
                body_html=html_body,
                attachment_paths=attachment_paths,
            )
            logger.info("Discovery report email sent successfully.")
        except GraphMailerError as e:
            logger.error(f"Failed to send report email: {e}")
            exit_code = 1

        # Cleanup old data
        cleanup_old_scans(config)

        summary = scan_results.get("summary", {})
        logger.info(
            f"Discovery complete. "
            f"Hosts: {summary.get('total_hosts', 0)}, "
            f"Open ports: {summary.get('total_open_ports', 0)}, "
            f"Security observations: {summary.get('security_observations', 0)}"
        )

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
