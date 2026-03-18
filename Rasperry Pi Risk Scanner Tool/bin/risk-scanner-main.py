#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Pi
risk-scanner-main.py - Main orchestration: scan → delta → AI → reports → email
"""

import argparse
import gzip
import importlib.util
import json
import logging
import logging.handlers
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

# Ensure lib/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

# Paths
BASE_DIR = Path("/opt/risk-scanner")
CONFIG_PATH = BASE_DIR / "config" / "config.json"
LOG_FILE = BASE_DIR / "logs" / "risk-scanner.log"
DATA_DIR = BASE_DIR / "data"
HISTORY_DIR = DATA_DIR / "history"
LOCK_FILE = DATA_DIR / ".scanner.lock"
VULN_DB_PATH = DATA_DIR / "vuln-db" / "vuln-db.sqlite"

logger = logging.getLogger("risk-scanner-main")

# ── Required config keys ────────────────────────────────────────────────────

_REQUIRED_KEYS = [
    ("graph_api", "tenant_id"),
    ("graph_api", "client_id"),
    ("graph_api", "client_secret"),
    ("graph_api", "from_email"),
    ("graph_api", "to_email"),
]

_OPTIONAL_KEYS = [
    ("hatz_ai", "api_key"),
    ("reporting", "client_name"),
    ("reporting", "company_color"),
    ("system", "min_free_disk_mb"),
    ("system", "log_level"),
    ("system", "device_name"),
    ("vuln_db_update_interval_days",),
    ("scan_schedule", "daily_time"),
    ("scan_schedule", "weekly_report_day"),
]


# ── Config ──────────────────────────────────────────────────────────────────

def load_config(path=str(CONFIG_PATH)) -> dict:
    """Load and validate config. Exit on missing required keys."""
    try:
        with open(path) as f:
            config = json.load(f)
    except FileNotFoundError:
        # Logger may not be configured yet; print directly
        print(f"ERROR: Config file not found: {path}", file=sys.stderr)
        print("Run the installer or copy config.json.template to config.json.", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in config file: {e}", file=sys.stderr)
        sys.exit(2)

    # Validate required keys
    missing = []
    for key_path in _REQUIRED_KEYS:
        node = config
        for part in key_path:
            if not isinstance(node, dict) or part not in node:
                missing.append(".".join(key_path))
                break
            node = node[part]
    if missing:
        print(f"ERROR: Config missing required keys: {', '.join(missing)}", file=sys.stderr)
        sys.exit(2)

    # Warn on missing optional keys (after logger is up)
    for key_path in _OPTIONAL_KEYS:
        node = config
        found = True
        for part in key_path:
            if not isinstance(node, dict) or part not in node:
                found = False
                break
            node = node[part]
        if not found:
            logger.debug("Config: optional key '%s' not set — using default", ".".join(key_path))

    logger.info("Config loaded from %s", path)
    return config


# ── Logging ─────────────────────────────────────────────────────────────────

def setup_logging(config: dict):
    """Configure rotating file handler plus optional console output."""
    log_dir = LOG_FILE.parent
    log_dir.mkdir(parents=True, exist_ok=True)

    level_str = config.get("system", {}).get("log_level", "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)

    fmt = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    formatter = logging.Formatter(fmt)

    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    handlers = [file_handler]
    if sys.stdout.isatty():
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        handlers.append(console_handler)

    logging.basicConfig(level=level, handlers=handlers)
    logger.info("Logging initialised — level=%s, file=%s", level_str, LOG_FILE)


# ── Lock file ────────────────────────────────────────────────────────────────

def acquire_lock(lock_path=str(LOCK_FILE)) -> bool:
    """Write PID to lock file. Return False if lock exists and PID still running."""
    lock = Path(lock_path)
    if lock.exists():
        try:
            raw = lock.read_text().strip()
            if not raw:
                raise ValueError("empty lock file")
            pid = int(raw)
            try:
                os.kill(pid, 0)
                logger.error("Another risk-scanner instance is running (PID %d). Exiting.", pid)
                return False
            except ProcessLookupError:
                logger.warning("Stale lock file (PID %d not running). Removing.", pid)
                lock.unlink()
        except (ValueError, OSError):
            logger.warning("Corrupt lock file. Removing.")
            lock.unlink(missing_ok=True)

    lock.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(lock.parent), prefix=".lock_")
    try:
        os.write(fd, str(os.getpid()).encode())
    finally:
        os.close(fd)
    os.replace(tmp, str(lock))
    logger.debug("Lock acquired: %s (PID %d)", lock_path, os.getpid())
    return True


def release_lock(lock_path=str(LOCK_FILE)):
    """Remove lock file."""
    Path(lock_path).unlink(missing_ok=True)
    logger.debug("Lock released: %s", lock_path)


# ── Disk space management ────────────────────────────────────────────────────

def manage_disk_space(config: dict):
    """Delete oldest history archives until free disk >= min_free_disk_mb."""
    min_free_mb = config.get("system", {}).get("min_free_disk_mb", 500)
    history = HISTORY_DIR
    history.mkdir(parents=True, exist_ok=True)

    try:
        usage = shutil.disk_usage(str(history))
        free_mb = usage.free / (1024 * 1024)
    except Exception as e:
        logger.warning("Could not check disk space: %s", e)
        return

    if free_mb >= min_free_mb:
        logger.info("Disk space OK: %.0f MB free (threshold: %d MB).", free_mb, min_free_mb)
        return

    logger.warning(
        "Low disk space: %.0f MB free (threshold: %d MB). Pruning oldest archives...",
        free_mb, min_free_mb,
    )

    removed = 0
    try:
        import scan_history as _sh
        while True:
            deleted_path = _sh.delete_oldest_scan()
            if not deleted_path:
                break
            removed += 1
            logger.info("  Pruned oldest scan (archive: %s)", deleted_path or "no file")
            try:
                usage = shutil.disk_usage(str(history))
                if usage.free / (1024 * 1024) >= min_free_mb:
                    break
            except Exception:
                break
    except Exception as e:
        logger.warning("scan_history: disk pruning failed: %s", e)

    if removed:
        logger.info("Pruned %d archive(s).", removed)
    else:
        logger.warning("No archives available to prune. Disk may remain low.")


# ── Vulnerability DB update ──────────────────────────────────────────────────

def update_vuln_db_if_due(config: dict):
    """Run update-vuln-db.py --update if NVD cache is older than configured interval."""
    interval_days = config.get("vuln_db_update_interval_days", 1)

    if VULN_DB_PATH.exists():
        age_days = (time.time() - VULN_DB_PATH.stat().st_mtime) / 86400
        if age_days < interval_days:
            logger.info(
                "Vuln DB is current (%.1f days old, threshold: %d days). Skipping update.",
                age_days, interval_days,
            )
            return
        logger.info(
            "Vuln DB is %.1f days old (threshold: %d days). Triggering update...",
            age_days, interval_days,
        )
    else:
        logger.info("Vuln DB not found. Triggering initial update...")

    updater = Path(__file__).parent / "update-vuln-db.py"
    if not updater.exists():
        logger.warning("update-vuln-db.py not found at %s — skipping.", updater)
        return

    try:
        result = subprocess.run(
            [sys.executable, str(updater), "--update"],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode == 0:
            logger.info("Vuln DB updated successfully.")
        else:
            logger.warning(
                "update-vuln-db.py exited %d: %s",
                result.returncode,
                result.stderr.strip()[:300],
            )
    except subprocess.TimeoutExpired:
        logger.warning("Vuln DB update timed out after 600s. Continuing with existing DB.")
    except Exception as e:
        logger.warning("Vuln DB update failed: %s. Continuing with existing DB.", e)


# ── Scan execution ───────────────────────────────────────────────────────────

def run_scan(config: dict) -> dict:
    """Load scan-engine.py via importlib (hyphen in name) and run scan."""
    engine_path = Path(__file__).parent / "scan-engine.py"
    if not engine_path.exists():
        raise FileNotFoundError(f"scan-engine.py not found at {engine_path}")

    logger.info("Loading scan engine from %s", engine_path)
    spec = importlib.util.spec_from_file_location("scan_engine", engine_path)
    scan_engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scan_engine)

    logger.info("Starting vulnerability scan...")
    t0 = time.time()
    results = scan_engine.run_scan(config)
    elapsed = time.time() - t0

    host_count = len(results.get("hosts", []))
    vuln_count = results.get("summary", {}).get("total_vulnerabilities", 0)
    risk_score = results.get("summary", {}).get("risk_score", "N/A")
    logger.info(
        "Scan completed in %.1fs — %d host(s), %d vulnerability/ies, risk score: %s",
        elapsed, host_count, vuln_count, risk_score,
    )
    return results


# ── Save / load scan results ─────────────────────────────────────────────────

def save_scan_results(results: dict, data_dir=str(HISTORY_DIR)) -> Path:
    """Gzip-compress JSON scan results to history/scan_YYYYMMDD_HHMMSS.json.gz."""
    history = Path(data_dir)
    history.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = history / f"scan_{timestamp}.json.gz"

    json_bytes = json.dumps(results, indent=2, default=str).encode("utf-8")
    with gzip.open(out_path, "wb", compresslevel=6) as gz:
        gz.write(json_bytes)

    logger.info(
        "Scan results saved: %s (%.0f KB compressed)",
        out_path, out_path.stat().st_size / 1024,
    )
    return out_path


def load_latest_scan(data_dir=str(HISTORY_DIR)) -> dict | None:
    """Return the most recent scan from SQLite history, falling back to legacy .json.gz."""
    try:
        import scan_history as _sh
        result = _sh.load_latest_scan()
        if result is not None:
            return result
    except Exception as e:
        logger.warning("scan_history: SQLite load failed (%s) — trying legacy archives", e)

    history = Path(data_dir)
    archives = sorted(history.glob("scan_*.json.gz"), key=lambda f: f.stat().st_mtime)
    if not archives:
        return None
    latest = archives[-1]
    logger.info("Loading scan from legacy archive %s", latest)
    with gzip.open(latest, "rb") as gz:
        return json.loads(gz.read().decode("utf-8"))


def _compute_delta(current: dict, previous: dict | None) -> dict:
    """Compute new/resolved/changed vulnerabilities between two scans."""
    if previous is None:
        return {"new_vulns": [], "resolved_vulns": [], "changed_hosts": [], "is_first_scan": True}

    def _vuln_ids(results):
        ids = set()
        for host in results.get("hosts", []):
            for v in host.get("vulnerabilities", []):
                ids.add(v.get("cve_id") or v.get("id", ""))
        return ids

    current_ids = _vuln_ids(current)
    previous_ids = _vuln_ids(previous)

    new_vulns = list(current_ids - previous_ids)
    resolved_vulns = list(previous_ids - current_ids)

    prev_risk = previous.get("summary", {}).get("risk_score", 0)
    curr_risk = current.get("summary", {}).get("risk_score", 0)

    return {
        "new_vulns": new_vulns,
        "resolved_vulns": resolved_vulns,
        "risk_score_delta": curr_risk - prev_risk if isinstance(curr_risk, (int, float)) else 0,
        "is_first_scan": False,
    }


# ── AI insights ──────────────────────────────────────────────────────────────

def get_ai_insights(results: dict, delta: dict, config: dict):
    """Call hatz_ai.get_risk_insights(); store result in results['ai_insights']. Non-fatal."""
    api_key = config.get("hatz_ai", {}).get("api_key", "")
    if not api_key:
        logger.info("Hatz AI: API key not configured — skipping.")
        return

    logger.info("Hatz AI: requesting risk insights...")
    t0 = time.time()
    try:
        from hatz_ai import get_risk_insights
        insights = get_risk_insights(results, delta, api_key)
        if insights:
            results["ai_insights"] = insights
            logger.info("Hatz AI: insights received in %.1fs.", time.time() - t0)
        else:
            logger.info("Hatz AI: no insights returned (%.1fs).", time.time() - t0)
    except ImportError:
        logger.warning("hatz_ai module not found — skipping AI insights.")
    except Exception as e:
        logger.warning("Hatz AI request failed (%.1fs): %s", time.time() - t0, e)


# ── Report generation ────────────────────────────────────────────────────────

def generate_reports(results: dict, config: dict) -> list:
    """Generate HTML + PDF reports. Returns list of PDF Path objects generated."""
    from report_generator import build_html_report

    report_paths = []
    rep_cfg = config.get("reporting", {})

    # HTML report (always generated; used for email body)
    logger.info("Building HTML report...")
    try:
        results["_html_report"] = build_html_report(results, config)
        logger.info("HTML report built.")
    except Exception as e:
        logger.error("HTML report generation failed: %s", e, exc_info=True)
        results["_html_report"] = ""

    # Executive PDF
    if rep_cfg.get("enable_executive_report", True):
        logger.info("Generating executive PDF report...")
        try:
            from executive_report import generate_executive_pdf
            pdf_bytes = generate_executive_pdf(results, config)
            out = HISTORY_DIR / f"exec_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            out.write_bytes(pdf_bytes)
            report_paths.append(out)
            logger.info("Executive PDF: %s (%.0f KB)", out.name, len(pdf_bytes) / 1024)
        except ImportError:
            logger.warning("executive_report module not found — skipping executive PDF.")
        except Exception as e:
            logger.error("Executive PDF generation failed: %s", e, exc_info=True)
    else:
        logger.info("Executive PDF disabled in config.")

    # Detail PDF  (build_detail_pdf writes the file itself and returns the path)
    if rep_cfg.get("enable_detail_report", True):
        logger.info("Generating detail PDF report...")
        try:
            from detail_report import build_detail_pdf
            out = HISTORY_DIR / f"detail_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            HISTORY_DIR.mkdir(parents=True, exist_ok=True)
            result_path = build_detail_pdf(results, config, str(out))
            report_paths.append(Path(result_path))
            logger.info("Detail PDF: %s (%.0f KB)", out.name, out.stat().st_size / 1024)
        except ImportError:
            logger.warning("detail_report module not found — skipping detail PDF.")
        except Exception as e:
            logger.error("Detail PDF generation failed: %s", e, exc_info=True)
    else:
        logger.info("Detail PDF disabled in config.")

    logger.info("Report generation complete — %d PDF(s) produced.", len(report_paths))
    return report_paths


# ── Email delivery ───────────────────────────────────────────────────────────

def send_weekly_report(results: dict, report_paths: list, config: dict):
    """Send the weekly risk report email with PDF attachments."""
    from graph_mailer import load_mailer_from_config

    device_name = config.get("system", {}).get("device_name", "RiskScanner-Pi")
    client_name = config.get("reporting", {}).get("client_name", "Client")
    risk_score = results.get("summary", {}).get("risk_score", "N/A")
    delta = results.get("_delta", {})
    delta_str = ""
    if isinstance(delta.get("risk_score_delta"), (int, float)):
        d = delta["risk_score_delta"]
        if d > 0:
            delta_str = f" (▲+{d:.1f})"
        elif d < 0:
            delta_str = f" (▼{d:.1f})"

    subject = (
        f"[Risk Scanner] Weekly Report — {client_name} — "
        f"Risk Score: {risk_score}{delta_str} — {device_name}"
    )

    html_body = results.get("_html_report", "")
    if not html_body:
        html_body = (
            "<html><body><p>Risk scan completed. "
            "Please see attached PDF reports for details.</p></body></html>"
        )

    attachment_paths = [str(p) for p in report_paths if Path(p).exists()]
    total_kb = sum(Path(p).stat().st_size for p in attachment_paths) / 1024
    logger.info(
        "Sending weekly report email: subject='%s', %d attachment(s), %.0f KB total",
        subject, len(attachment_paths), total_kb,
    )

    mailer = load_mailer_from_config(str(CONFIG_PATH))
    mailer.send_email(
        subject=subject,
        body_html=html_body,
        attachment_paths=attachment_paths,
    )
    logger.info("Weekly report email sent successfully.")


# ── Cleanup ──────────────────────────────────────────────────────────────────

def cleanup_after_send(tmp_files: list):
    """Remove temp PDF files. Compressed .gz archives are retained."""
    removed = 0
    for f in tmp_files:
        p = Path(f)
        if p.suffix == ".gz":
            logger.debug("Retaining archive: %s", p.name)
            continue
        try:
            if p.exists():
                p.unlink()
                removed += 1
                logger.debug("Removed temp file: %s", p.name)
        except Exception as e:
            logger.warning("Could not remove %s: %s", p.name, e)
    if removed:
        logger.info("Cleaned up %d temporary file(s).", removed)


# ── Signal handling ──────────────────────────────────────────────────────────

_lock_path_for_signal = str(LOCK_FILE)


def handle_signal(signum, frame):
    logger.warning("Received signal %d, shutting down cleanly.", signum)
    release_lock(_lock_path_for_signal)
    sys.exit(0)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Yeyland Wutani Risk Scanner Pi — main orchestration"
    )
    parser.add_argument("--scan-only", action="store_true",
                        help="Run scan and save results; skip report and email")
    parser.add_argument("--report-only", action="store_true",
                        help="Generate report from latest saved scan; skip live scan")
    parser.add_argument("--config", default=str(CONFIG_PATH), metavar="PATH",
                        help=f"Config file path (default: {CONFIG_PATH})")
    args = parser.parse_args()

    if args.scan_only and args.report_only:
        print("ERROR: --scan-only and --report-only are mutually exclusive.", file=sys.stderr)
        sys.exit(2)

    # Register signal handlers before anything else
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Bootstrap: load config and logging with minimal setup first
    # (setup_logging needs config; load_config needs print-only fallback)
    config = load_config(args.config)
    setup_logging(config)

    logger.info("=" * 70)
    logger.info("Yeyland Wutani - Risk Scanner Pi: Starting")
    logger.info("=" * 70)
    logger.info("PID: %d | User: %s | Mode: %s",
                os.getpid(),
                os.getenv("USER", "unknown"),
                "scan-only" if args.scan_only else "report-only" if args.report_only else "full")

    if not acquire_lock():
        logger.error("Failed to acquire lock. Another instance may be running.")
        sys.exit(1)

    exit_code = 0
    report_paths = []

    try:
        manage_disk_space(config)

        if not args.report_only:
            # ── Scan branch ──────────────────────────────────────────────────
            try:
                update_vuln_db_if_due(config)
            except Exception as e:
                logger.error("Vuln DB update raised unhandled exception: %s", e, exc_info=True)

            logger.info("Starting vulnerability scan...")
            results = run_scan(config)

            previous = load_latest_scan()
            delta = _compute_delta(results, previous)
            results["_delta"] = delta
            logger.info(
                "Delta: %d new vuln(s), %d resolved, risk delta: %s",
                len(delta.get("new_vulns", [])),
                len(delta.get("resolved_vulns", [])),
                delta.get("risk_score_delta", "N/A"),
            )

            archive_path = save_scan_results(results)

            try:
                import scan_history as _sh
                _sh.save_scan(results, archive_path=str(archive_path))
                logger.info("scan_history: scan indexed in SQLite.")
            except Exception as e:
                logger.warning("scan_history: SQLite save failed: %s", e)

            try:
                get_ai_insights(results, delta, config)
            except Exception as e:
                logger.error("AI insights raised unhandled exception: %s", e, exc_info=True)
        else:
            # ── Report-only branch ───────────────────────────────────────────
            logger.info("--report-only: loading latest saved scan...")
            results = load_latest_scan()
            if results is None:
                logger.error("No saved scan results found in %s. Cannot generate report.", HISTORY_DIR)
                sys.exit(1)
            logger.info("Loaded scan results (host count: %d).", len(results.get("hosts", [])))
            archive_path = None

        if not args.scan_only:
            # ── Report + email branch ────────────────────────────────────────
            logger.info("Generating reports...")
            try:
                report_paths = generate_reports(results, config)
            except Exception as e:
                logger.error("Report generation failed: %s", e, exc_info=True)
                logger.info("Continuing — will attempt to send email without PDF attachments.")
                report_paths = []

            logger.info("Sending weekly report email...")
            try:
                send_weekly_report(results, report_paths, config)
            except Exception as e:
                logger.error("Failed to send report email: %s", e, exc_info=True)
                exit_code = 1

            cleanup_after_send([str(p) for p in report_paths])
        else:
            logger.info("--scan-only: skipping report generation and email.")

        # Final summary
        summary = results.get("summary", {})
        logger.info("-" * 50)
        logger.info("RUN SUMMARY")
        logger.info("  Hosts scanned:         %d", len(results.get("hosts", [])))
        logger.info("  Total vulnerabilities: %d", summary.get("total_vulnerabilities", 0))
        logger.info("  Critical/High:         %d", summary.get("critical_high_count", 0))
        logger.info("  Risk score:            %s", summary.get("risk_score", "N/A"))
        logger.info("  PDF reports sent:      %d", len(report_paths))
        if archive_path:
            logger.info("  Archive:               %s", archive_path.name)
        logger.info("-" * 50)

    except SystemExit:
        raise
    except Exception as e:
        logger.critical("Unhandled exception in main: %s", e, exc_info=True)
        exit_code = 1
    finally:
        release_lock()
        logger.info("Risk scanner finished with exit code %d.", exit_code)
        logger.info("=" * 70)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
