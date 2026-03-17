#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Pi
update-vuln-db.py - Vulnerability database management CLI
"""

import argparse
import json
import logging
import logging.handlers
import sys
import time
from datetime import datetime
from pathlib import Path

# Ensure lib/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

BASE_DIR = Path("/opt/risk-scanner")
CONFIG_PATH = BASE_DIR / "config" / "config.json"
LOG_FILE = BASE_DIR / "logs" / "update-vuln-db.log"

logger = logging.getLogger("update-vuln-db")


# ── Logging ───────────────────────────────────────────────────────────────────

def _setup_logging():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    formatter = logging.Formatter(fmt)

    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=3, encoding="utf-8"
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


# ── Stats display ─────────────────────────────────────────────────────────────

def _print_stats(stats: dict):
    """Print a formatted stats table to stdout."""
    now = time.time()

    last_updated = stats.get("last_updated")
    if last_updated:
        try:
            if isinstance(last_updated, (int, float)):
                age_str = _format_age(now - last_updated)
                last_updated_str = datetime.fromtimestamp(last_updated).strftime("%Y-%m-%d %H:%M:%S")
            else:
                last_updated_str = str(last_updated)
                age_str = "unknown"
        except Exception:
            last_updated_str = str(last_updated)
            age_str = "unknown"
    else:
        last_updated_str = "Never"
        age_str = "N/A"

    stale = stats.get("stale", False)
    stale_str = "YES (>3 days)" if stale else "No"

    sep = "-" * 52
    print(sep)
    print("  Vulnerability Database Status")
    print(sep)
    print(f"  {'CVE Count':<30} {stats.get('cve_count', 0):>10,}")
    print(f"  {'KEV (Known Exploited) Count':<30} {stats.get('kev_count', 0):>10,}")
    print(f"  {'OSV Records':<30} {stats.get('osv_count', 0):>10,}")
    print(f"  {'Last Updated':<30} {last_updated_str:>10}")
    print(f"  {'Database Age':<30} {age_str:>10}")
    print(f"  {'Stale':<30} {stale_str:>10}")

    if stats.get("nvd_last_modified"):
        print(f"  {'NVD Last Modified':<30} {stats['nvd_last_modified']:>10}")
    if stats.get("kev_last_modified"):
        print(f"  {'KEV Last Modified':<30} {stats['kev_last_modified']:>10}")
    if stats.get("db_path"):
        print(f"  {'DB Path':<30} {stats['db_path']}")

    print(sep)
    if stale:
        print("  WARNING: Database is stale. Run --update to refresh.")
        print(sep)


def _format_age(seconds: float) -> str:
    if seconds < 3600:
        return f"{int(seconds / 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds / 3600)}h ago"
    return f"{int(seconds / 86400)}d ago"


# ── Update helpers ────────────────────────────────────────────────────────────

def _print_update_summary(label: str, result: dict):
    added = result.get("added", 0)
    updated = result.get("updated", 0)
    skipped = result.get("skipped", 0)
    errors = result.get("errors", 0)
    duration = result.get("duration_s", 0)
    total = result.get("total", 0)

    print(f"  {label}:")
    if total:
        print(f"    Total records in DB: {total:,}")
    if added or updated:
        print(f"    New: {added:,}  |  Updated: {updated:,}  |  Skipped: {skipped:,}")
    else:
        print(f"    No changes (already current)")
    if errors:
        print(f"    Errors: {errors}")
    print(f"    Duration: {duration:.1f}s")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Yeyland Wutani Risk Scanner Pi — vulnerability database manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --stats                           Show current DB statistics
  %(prog)s --update                          Incremental update (run daily via cron)
  %(prog)s --init                            Full initial seed (run once after install)
  %(prog)s --init --nvd-api-key KEY          Initial seed with NVD API key (10x faster)
""",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--init", action="store_true",
                      help="Full initial seed of NVD + KEV + OSV databases (30-60 min without API key)")
    mode.add_argument("--update", action="store_true",
                      help="Incremental update — only CVEs modified since last update")
    mode.add_argument("--stats", action="store_true",
                      help="Print database statistics and exit")
    parser.add_argument("--nvd-api-key", metavar="KEY",
                        help="NVD API key (overrides config; significantly speeds up --init)")
    parser.add_argument("--config", default=str(CONFIG_PATH), metavar="PATH",
                        help=f"Config file path (default: {CONFIG_PATH})")
    args = parser.parse_args()

    _setup_logging()

    config = _load_config(args.config)

    # Resolve NVD API key: CLI arg > config
    nvd_api_key = (
        args.nvd_api_key
        or config.get("vuln_db", {}).get("nvd_api_key", "")
        or config.get("nvd_api_key", "")
    )

    logger.info("Loading vuln_db module...")
    try:
        from vuln_db import (
            get_db_stats,
            update_nvd_cache,
            update_kev_catalog,
            update_osv_cache,
        )
    except ImportError as e:
        logger.error("Failed to import vuln_db: %s", e)
        logger.error("Ensure vuln_db.py is present in lib/ and dependencies are installed.")
        sys.exit(1)

    # ── Stats mode ────────────────────────────────────────────────────────────
    if args.stats:
        logger.info("Fetching DB statistics...")
        try:
            stats = get_db_stats()
            _print_stats(stats)
        except Exception as e:
            logger.error("Failed to retrieve DB stats: %s", e, exc_info=True)
            sys.exit(1)
        sys.exit(0)

    # ── Init mode ─────────────────────────────────────────────────────────────
    if args.init:
        print("=" * 52)
        print("  Risk Scanner — Initial Vulnerability DB Seed")
        print("=" * 52)
        if nvd_api_key:
            print("  NVD API key: configured (fast mode)")
        else:
            print("  NVD API key: NOT configured")
            print("  WARNING: Initial seed may take 30-60 minutes without an")
            print("  NVD API key due to rate limiting (6 req/30s vs 50 req/30s).")
            print("  Get a free key at: https://nvd.nist.gov/developers/request-an-api-key")
        print("=" * 52)
        print()

        logger.info("Starting full initial database seed...")
        run_start = time.time()
        errors = 0

        # NVD full seed
        print("  [1/3] Seeding NVD CVE database (full)...")
        logger.info("Seeding NVD CVE database (force_full=True)...")
        nvd_start = time.time()
        try:
            nvd_count = update_nvd_cache(api_key=nvd_api_key, force_full=True)
            _print_update_summary("NVD CVE Database", {"total": nvd_count, "duration_s": time.time() - nvd_start})
        except Exception as e:
            logger.error("NVD seed failed: %s", e, exc_info=True)
            print(f"  NVD seed FAILED: {e}")
            errors += 1

        # KEV catalog
        print()
        print("  [2/3] Downloading CISA KEV catalog...")
        logger.info("Updating CISA KEV catalog...")
        kev_start = time.time()
        try:
            kev_count = update_kev_catalog()
            _print_update_summary("CISA KEV Catalog", {"total": kev_count, "duration_s": time.time() - kev_start})
        except Exception as e:
            logger.error("KEV update failed: %s", e, exc_info=True)
            print(f"  KEV update FAILED: {e}")
            errors += 1

        # OSV database
        print()
        print("  [3/3] Seeding OSV (Open Source Vulnerabilities) database...")
        logger.info("Seeding OSV database...")
        osv_start = time.time()
        try:
            osv_count = update_osv_cache()
            _print_update_summary("OSV Database", {"total": osv_count, "duration_s": time.time() - osv_start})
        except Exception as e:
            logger.error("OSV seed failed: %s", e, exc_info=True)
            print(f"  OSV seed FAILED: {e}")
            errors += 1

        # Final stats
        total_duration = time.time() - run_start
        print()
        print("=" * 52)
        print(f"  Initial seed complete in {total_duration:.0f}s")
        if errors:
            print(f"  WARNING: {errors} source(s) encountered errors. Check the log.")
        else:
            print("  All sources seeded successfully.")
        print("=" * 52)

        try:
            stats = get_db_stats()
            _print_stats(stats)
        except Exception:
            pass

        logger.info("Initial seed finished in %.1fs with %d error(s).", total_duration, errors)
        sys.exit(1 if errors else 0)

    # ── Update mode ───────────────────────────────────────────────────────────
    if args.update:
        logger.info("Starting incremental vulnerability database update...")
        run_start = time.time()
        errors = 0

        print("  [1/3] Updating NVD CVE database (incremental)...")
        logger.info("Updating NVD CVE database (incremental)...")
        nvd_start = time.time()
        try:
            nvd_count = update_nvd_cache(api_key=nvd_api_key)
            _print_update_summary("NVD CVE Database", {"total": nvd_count, "duration_s": time.time() - nvd_start})
        except Exception as e:
            logger.error("NVD update failed: %s", e, exc_info=True)
            print(f"  NVD update FAILED: {e}")
            errors += 1

        print()
        print("  [2/3] Updating CISA KEV catalog...")
        logger.info("Updating CISA KEV catalog...")
        kev_start = time.time()
        try:
            kev_count = update_kev_catalog()
            _print_update_summary("CISA KEV Catalog", {"total": kev_count, "duration_s": time.time() - kev_start})
        except Exception as e:
            logger.error("KEV update failed: %s", e, exc_info=True)
            print(f"  KEV update FAILED: {e}")
            errors += 1

        print()
        print("  [3/3] Updating OSV database (incremental)...")
        logger.info("Updating OSV database (incremental)...")
        osv_start = time.time()
        try:
            osv_count = update_osv_cache()
            _print_update_summary("OSV Database", {"total": osv_count, "duration_s": time.time() - osv_start})
        except Exception as e:
            logger.error("OSV update failed: %s", e, exc_info=True)
            print(f"  OSV update FAILED: {e}")
            errors += 1

        total_duration = time.time() - run_start
        print()
        print("=" * 52)
        print(f"  Incremental update complete in {total_duration:.1f}s")
        if errors:
            print(f"  WARNING: {errors} source(s) encountered errors.")
        else:
            print("  All sources updated successfully.")
        print("=" * 52)

        logger.info("Incremental update finished in %.1fs with %d error(s).", total_duration, errors)
        sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
