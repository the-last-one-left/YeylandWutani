#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Pi
generate-report.py - On-demand report generator from saved scan data
"""

import argparse
import gzip
import json
import logging
import logging.handlers
import sys
import time
from pathlib import Path

# Ensure lib/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

BASE_DIR = Path("/opt/risk-scanner")
CONFIG_PATH = BASE_DIR / "config" / "config.json"
HISTORY_DIR = BASE_DIR / "data" / "history"
DEFAULT_OUTPUT_DIR = Path("/tmp/risk-scanner-reports")
LOG_FILE = BASE_DIR / "logs" / "generate-report.log"

logger = logging.getLogger("generate-report")


# ── Logging ───────────────────────────────────────────────────────────────────

def _setup_logging():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    formatter = logging.Formatter(fmt)

    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    logging.basicConfig(level=logging.INFO, handlers=[file_handler, console_handler])


# ── Config ────────────────────────────────────────────────────────────────────

def _load_config(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error("Config file not found: %s", path)
        sys.exit(2)
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in config file: %s", e)
        sys.exit(2)


# ── Scan file loading ─────────────────────────────────────────────────────────

def _load_scan_file(path: Path) -> dict:
    """Load and decompress a .json.gz scan archive."""
    logger.info("Loading scan file: %s", path)
    try:
        with gzip.open(path, "rb") as gz:
            data = json.loads(gz.read().decode("utf-8"))
        host_count = len(data.get("hosts", []))
        risk_score = data.get("summary", {}).get("risk_score", "N/A")
        logger.info(
            "Loaded scan: %d host(s), risk score: %s, scan timestamp: %s",
            host_count, risk_score,
            data.get("scan_timestamp", data.get("timestamp", "unknown")),
        )
        return data
    except (OSError, gzip.BadGzipFile) as e:
        logger.error("Could not read scan file %s: %s", path, e)
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in scan file %s: %s", path, e)
        sys.exit(1)


def _find_latest_scan(history_dir: Path) -> Path | None:
    """Return path to most recent .json.gz in history_dir, or None."""
    archives = sorted(history_dir.glob("scan_*.json.gz"), key=lambda f: f.stat().st_mtime)
    return archives[-1] if archives else None


# ── Report generators ─────────────────────────────────────────────────────────

def _generate_executive(results: dict, config: dict, output_dir: Path) -> Path | None:
    """Generate executive PDF. Return output path or None on failure."""
    try:
        from executive_report import build_executive_pdf
        logger.info("Generating executive PDF...")
        t0 = time.time()
        pdf_bytes = build_executive_pdf(results, config)
        out_path = output_dir / _report_filename(results, "executive_report")
        out_path.write_bytes(pdf_bytes)
        logger.info(
            "Executive PDF: %s (%.0f KB, %.1fs)",
            out_path.name, len(pdf_bytes) / 1024, time.time() - t0,
        )
        return out_path
    except ImportError:
        logger.error("executive_report module not found in lib/. Cannot generate executive PDF.")
        return None
    except Exception as e:
        logger.error("Executive PDF generation failed: %s", e, exc_info=True)
        return None


def _generate_detail(results: dict, config: dict, output_dir: Path) -> Path | None:
    """Generate detail PDF. Return output path or None on failure."""
    try:
        from detail_report import build_detail_pdf
        logger.info("Generating detail PDF...")
        t0 = time.time()
        pdf_bytes = build_detail_pdf(results, config)
        out_path = output_dir / _report_filename(results, "detail_report")
        out_path.write_bytes(pdf_bytes)
        logger.info(
            "Detail PDF: %s (%.0f KB, %.1fs)",
            out_path.name, len(pdf_bytes) / 1024, time.time() - t0,
        )
        return out_path
    except ImportError:
        logger.error("detail_report module not found in lib/. Cannot generate detail PDF.")
        return None
    except Exception as e:
        logger.error("Detail PDF generation failed: %s", e, exc_info=True)
        return None


def _report_filename(results: dict, label: str) -> str:
    """Build a timestamped output filename."""
    ts = results.get("scan_timestamp", results.get("timestamp", ""))
    if ts:
        # Normalise ISO timestamp to filesystem-safe string
        ts_safe = ts[:19].replace(":", "").replace("-", "").replace("T", "_")
    else:
        from datetime import datetime
        ts_safe = datetime.now().strftime("%Y%m%d_%H%M%S")
    client = results.get("client_name", "")
    prefix = f"{client}_" if client else ""
    return f"{prefix}{ts_safe}_{label}.pdf"


# ── Email delivery ────────────────────────────────────────────────────────────

def _send_email(results: dict, report_paths: list, config: dict):
    """Send reports via Graph API mailer."""
    from graph_mailer import load_mailer_from_config, GraphMailerError

    device_name = config.get("system", {}).get("device_name", "RiskScanner-Pi")
    client_name = config.get("reporting", {}).get("client_name", "Client")
    risk_score = results.get("summary", {}).get("risk_score", "N/A")

    subject = (
        f"[Risk Scanner] On-Demand Report — {client_name} — "
        f"Risk Score: {risk_score} — {device_name}"
    )

    # Build a minimal HTML body if no report_generator available
    html_body = results.get("_html_report", "")
    if not html_body:
        try:
            from report_generator import build_html_report
            html_body = build_html_report(results, config)
        except Exception as e:
            logger.warning("Could not build HTML report body: %s. Using plain fallback.", e)
            html_body = (
                "<html><body>"
                "<p>On-demand risk scan report. "
                "See attached PDF(s) for full details.</p>"
                "</body></html>"
            )

    attachment_paths = [str(p) for p in report_paths if p and Path(p).exists()]
    total_kb = sum(Path(p).stat().st_size for p in attachment_paths) / 1024
    logger.info(
        "Sending email: subject='%s', %d attachment(s), %.0f KB",
        subject, len(attachment_paths), total_kb,
    )

    mailer = load_mailer_from_config(str(CONFIG_PATH))
    mailer.send_email(
        subject=subject,
        body_html=html_body,
        attachment_paths=attachment_paths,
    )
    logger.info("Email sent successfully.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Yeyland Wutani Risk Scanner Pi — on-demand report generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                   Generate all reports from latest scan, send email
  %(prog)s --no-email                        Generate PDFs locally, no email
  %(prog)s --type exec                       Executive report only
  %(prog)s --type detail --no-email          Detail report only, no email
  %(prog)s --scan-file /path/to/scan.json.gz Use a specific scan archive
  %(prog)s --output /tmp/reports/            Write PDFs to a custom directory
""",
    )
    parser.add_argument(
        "--scan-file",
        metavar="PATH",
        help="Specific .json.gz scan file to use (default: latest from data/history/)",
    )
    parser.add_argument(
        "--output",
        metavar="DIR",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"Output directory for generated PDFs (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--no-email",
        action="store_true",
        help="Generate PDFs but do not send email",
    )
    parser.add_argument(
        "--type",
        choices=["exec", "detail", "all"],
        default="all",
        help="Which reports to generate: exec, detail, or all (default: all)",
    )
    parser.add_argument(
        "--config",
        default=str(CONFIG_PATH),
        metavar="PATH",
        help=f"Config file path (default: {CONFIG_PATH})",
    )
    args = parser.parse_args()

    _setup_logging()

    logger.info("=" * 60)
    logger.info("Yeyland Wutani - Risk Scanner Pi: On-Demand Report Generator")
    logger.info("=" * 60)
    logger.info("Type: %s | Email: %s | Output: %s",
                args.type, "no" if args.no_email else "yes", args.output)

    config = _load_config(args.config)

    # ── Resolve scan file ──────────────────────────────────────────────────────
    if args.scan_file:
        scan_path = Path(args.scan_file)
        if not scan_path.exists():
            logger.error("Scan file not found: %s", scan_path)
            sys.exit(1)
        results = _load_scan_file(scan_path)
    else:
        logger.info("No --scan-file specified. Looking for latest scan in %s...", HISTORY_DIR)
        scan_path = _find_latest_scan(HISTORY_DIR)
        if scan_path is None:
            logger.error(
                "No scan archives found in %s. Run risk-scanner-main.py first.", HISTORY_DIR
            )
            sys.exit(1)
        logger.info("Using latest scan: %s", scan_path.name)
        results = _load_scan_file(scan_path)

    # ── Prepare output directory ───────────────────────────────────────────────
    output_dir = Path(args.output)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Output directory: %s", output_dir)
    except OSError as e:
        logger.error("Cannot create output directory %s: %s", output_dir, e)
        sys.exit(1)

    # ── Generate reports ───────────────────────────────────────────────────────
    report_paths = []
    run_start = time.time()

    if args.type in ("exec", "all"):
        path = _generate_executive(results, config, output_dir)
        if path:
            report_paths.append(path)

    if args.type in ("detail", "all"):
        path = _generate_detail(results, config, output_dir)
        if path:
            report_paths.append(path)

    if not report_paths:
        logger.error("No reports were generated. Check that report modules are installed in lib/.")
        sys.exit(1)

    # ── Print generated files ──────────────────────────────────────────────────
    print()
    print("Generated reports:")
    for p in report_paths:
        size_kb = Path(p).stat().st_size / 1024
        print(f"  {p}  ({size_kb:.0f} KB)")
    print()

    # ── Send email ─────────────────────────────────────────────────────────────
    if not args.no_email:
        logger.info("Sending report email...")
        try:
            _send_email(results, report_paths, config)
            print("Email sent successfully.")
        except Exception as e:
            logger.error("Failed to send email: %s", e, exc_info=True)
            print(f"ERROR: Failed to send email: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        logger.info("--no-email specified. Skipping email delivery.")
        print("Email skipped (--no-email).")

    total_duration = time.time() - run_start
    logger.info(
        "Done. %d PDF(s) generated in %.1fs.",
        len(report_paths), total_duration,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
