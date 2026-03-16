#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
generate-report.py - Client-Facing PDF Report Generator CLI

Generates professional client-facing PDF reports from saved network scan data.

Usage:
  generate-report.py [options]

Options:
  --json PATH       Path to scan JSON or JSON.gz file
                    (defaults to the most recent scan in /opt/network-discovery/data/)
  --config PATH     Path to config.json
                    (defaults to /opt/network-discovery/config/config.json)
  --output DIR      Output directory for generated PDFs
                    (defaults to same directory as the JSON file, or /tmp)
  --client-name STR Override the client name from config (e.g. "Acme Corp")
  --color HEX       Override client brand color (e.g. "#00A0D9")
  --summary         Generate Summary Report PDF  (default: both)
  --detail          Generate Detail Report PDF   (default: both)
  --no-summary      Skip Summary Report
  --no-detail       Skip Detail Report

Examples:
  # Generate from latest scan using configured client info
  sudo /opt/network-discovery/venv/bin/python generate-report.py

  # Generate from a specific file with a client name override
  python generate-report.py \\
      --json /tmp/scan_20260309.json.gz \\
      --client-name "Acme Corp" \\
      --color "#00A0D9"

  # Summary only, custom output directory
  python generate-report.py --summary --output /tmp/reports/
"""

import argparse
import gzip
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Ensure lib/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("generate-report")

DATA_DIR   = Path("/opt/network-discovery/data")
CONFIG_PATH = Path("/opt/network-discovery/config/config.json")


# ── Helpers ───────────────────────────────────────────────────────────────────

def find_latest_scan(data_dir: Path) -> Path | None:
    """Return the most recently modified scan JSON or JSON.gz in data_dir."""
    candidates = sorted(
        list(data_dir.glob("scan_*.json")) +
        list(data_dir.glob("scan_*.json.gz")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def load_scan(path: Path) -> dict:
    """Load and return scan_results dict from a JSON or JSON.gz file."""
    logger.info(f"Loading scan data from {path}")
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    else:
        with open(path, encoding="utf-8") as f:
            return json.load(f)


def load_config(path: Path) -> dict:
    """Load config.json; return a minimal default if not found."""
    if path.exists():
        logger.info(f"Loading config from {path}")
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    logger.warning(f"Config not found at {path} — using defaults.")
    return {
        "reporting": {
            "company_name": "Client",
            "company_color": "#FF6600",
            "tagline": "Building Better Systems",
        }
    }


def _stem(path: Path) -> str:
    """Return the filename stem without any .json/.gz extensions."""
    name = path.name
    for ext in (".json.gz", ".json"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return path.stem


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate client-facing PDF reports from network scan data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--json",        metavar="PATH",
                        help="Scan JSON or JSON.gz file path")
    parser.add_argument("--config",      metavar="PATH",
                        default=str(CONFIG_PATH),
                        help=f"Config file path (default: {CONFIG_PATH})")
    parser.add_argument("--output",      metavar="DIR",
                        help="Output directory for PDFs")
    parser.add_argument("--client-name", metavar="NAME",
                        help="Override client name (e.g. 'Acme Corp')")
    parser.add_argument("--color",       metavar="HEX",
                        help="Override brand color (e.g. '#00A0D9')")
    parser.add_argument("--summary",     action="store_true",
                        help="Generate Summary Report (default: both)")
    parser.add_argument("--detail",      action="store_true",
                        help="Generate Detail Report (default: both)")
    parser.add_argument("--no-summary",  action="store_true",
                        help="Skip Summary Report")
    parser.add_argument("--no-detail",   action="store_true",
                        help="Skip Detail Report")
    args = parser.parse_args()

    # Decide which reports to generate
    want_summary = not args.no_summary
    want_detail  = not args.no_detail
    if args.summary and not args.detail:
        want_detail = False
    if args.detail and not args.summary:
        want_summary = False

    # ── Locate scan file ───────────────────────────────────────────────────
    if args.json:
        json_path = Path(args.json)
        if not json_path.exists():
            logger.error(f"File not found: {json_path}")
            return 1
    else:
        # Try to find the most recent scan
        json_path = find_latest_scan(DATA_DIR)
        if json_path is None:
            logger.error(
                f"No scan files found in {DATA_DIR}. "
                "Run the discovery scanner first, or specify --json PATH."
            )
            return 1
        logger.info(f"Using most recent scan: {json_path.name}")

    # ── Load data ──────────────────────────────────────────────────────────
    try:
        scan_results = load_scan(json_path)
    except Exception as e:
        logger.error(f"Failed to load scan data: {e}")
        return 1

    config = load_config(Path(args.config))

    # Apply CLI overrides to config
    if args.client_name:
        config.setdefault("reporting", {})["company_name"] = args.client_name
        logger.info(f"Client name override: {args.client_name}")
    if args.color:
        config.setdefault("reporting", {})["company_color"] = args.color
        logger.info(f"Color override: {args.color}")

    # ── Output directory ───────────────────────────────────────────────────
    if args.output:
        out_dir = Path(args.output)
    else:
        out_dir = json_path.parent

    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Import PDF generator ───────────────────────────────────────────────
    try:
        from client_report import (
            build_client_summary_pdf,
            build_client_detail_pdf,
            compute_risk_score,
            REPORTLAB_AVAILABLE,
        )
    except ImportError as e:
        logger.error(f"Could not import client_report: {e}")
        return 1

    if not REPORTLAB_AVAILABLE:
        logger.error(
            "reportlab is not installed. "
            "Install it with: pip install reportlab"
        )
        return 1

    stem      = _stem(json_path)
    client    = config.get("reporting", {}).get("company_name", "Client")
    risk      = compute_risk_score(scan_results)
    hosts     = scan_results.get("hosts", [])

    logger.info(f"Client: {client}")
    logger.info(f"Devices discovered: {len(hosts)}")
    logger.info(f"Risk score: {risk}/100")

    generated = []

    # ── Summary Report ─────────────────────────────────────────────────────
    if want_summary:
        out_path = out_dir / f"{stem}_Summary_Report.pdf"
        logger.info(f"Generating Summary Report -> {out_path}")
        try:
            pdf_bytes = build_client_summary_pdf(scan_results, config)
            out_path.write_bytes(pdf_bytes)
            size_kb = len(pdf_bytes) / 1024
            logger.info(f"  Summary Report: {size_kb:.0f} KB  ({out_path})")
            generated.append(str(out_path))
        except Exception as e:
            logger.error(f"Summary Report generation failed: {e}", exc_info=True)

    # ── Detail Report ──────────────────────────────────────────────────────
    if want_detail:
        out_path = out_dir / f"{stem}_Detail_Report.pdf"
        logger.info(f"Generating Detail Report -> {out_path}")
        try:
            pdf_bytes = build_client_detail_pdf(scan_results, config)
            out_path.write_bytes(pdf_bytes)
            size_kb = len(pdf_bytes) / 1024
            logger.info(f"  Detail Report: {size_kb:.0f} KB  ({out_path})")
            generated.append(str(out_path))
        except Exception as e:
            logger.error(f"Detail Report generation failed: {e}", exc_info=True)

    if generated:
        logger.info(f"Done. {len(generated)} PDF(s) generated:")
        for p in generated:
            logger.info(f"  {p}")
        return 0
    else:
        logger.error("No PDFs were generated.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
