#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
vuln_db.py - SQLite-backed Vulnerability Database

Replaces JSON flat-file caches with an indexed SQLite database.
Supports incremental NVD updates, CISA KEV catalog, and OSV lookups.
All lookups are query-based — nothing is loaded wholesale into memory.

Schema
------
  nvd_cves    - one row per CVE (CVSS scores, description, refs)
  nvd_cpe     - CPE match rows with extracted vendor/product/version fields
  kev_catalog - CISA Known Exploited Vulnerabilities
  osv_entries - OSV package:version → vulnerability ID mapping
  db_stats    - key/value metadata (timestamps, counts, resume markers)
"""

import io
import json
import logging
import re
import sqlite3
import time
import urllib.parse
import urllib.request
import urllib.error
import zipfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────
VULN_DB_DIR = Path("/opt/network-discovery/data/vuln-db")
DB_PATH     = VULN_DB_DIR / "vuln-db.sqlite"

# Legacy JSON paths — only used for one-time auto-migration
_LEGACY_NVD   = VULN_DB_DIR / "nvd-cache.json"
_LEGACY_KEV   = VULN_DB_DIR / "kev-catalog.json"
_LEGACY_OSV   = VULN_DB_DIR / "osv-cache.json"
_LEGACY_STATS = VULN_DB_DIR / "db-stats.json"

FALLBACK_DB_PATH = Path(__file__).parent.parent / "data" / "vuln-db" / "vuln-db-fallback.json"

# ── NVD API ────────────────────────────────────────────────────────────────
NVD_API_BASE             = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_ANON_DELAY = 6.5   # seconds between requests without key
NVD_RATE_LIMIT_KEY_DELAY  = 0.6   # seconds between requests with key
NVD_PAGE_SIZE             = 2000  # max results per API call
NVD_WINDOW_DAYS           = 119   # NVD enforces ≤120 day range per request

# ── KEV / OSV ──────────────────────────────────────────────────────────────
KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_GCS_BASE = "https://osv-vulnerabilities.storage.googleapis.com"

# ── Severity thresholds ────────────────────────────────────────────────────
CVSS_CRITICAL = 9.0
CVSS_HIGH     = 7.0
CVSS_MEDIUM   = 4.0

# ── Small in-memory caches ─────────────────────────────────────────────────
# KEV is ~1 500 rows — cheap to keep in RAM for fast is_kev() calls.
_kev_cache:   dict = {}
_fallback_db: dict = {}
_db_ready          = False


# ══════════════════════════════════════════════════════════════════════════
# Database init & connection
# ══════════════════════════════════════════════════════════════════════════

def _ensure_db_dir():
    VULN_DB_DIR.mkdir(parents=True, exist_ok=True)


@contextmanager
def _conn():
    """Short-lived SQLite connection with WAL mode and generous page cache."""
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-32000")   # 32 MB page cache
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS nvd_cves (
    cve_id           TEXT PRIMARY KEY,
    description      TEXT,
    cvss_v3_score    REAL,
    cvss_v3_vector   TEXT,
    cvss_v3_severity TEXT,
    cvss_v2_score    REAL,
    published        TEXT,
    last_modified    TEXT,
    references_json  TEXT
);

CREATE TABLE IF NOT EXISTS nvd_cpe (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL REFERENCES nvd_cves(cve_id) ON DELETE CASCADE,
    cpe             TEXT NOT NULL,
    cpe_vendor      TEXT,
    cpe_product     TEXT,
    cpe_version     TEXT,
    ver_start_incl  TEXT DEFAULT '',
    ver_end_incl    TEXT DEFAULT '',
    ver_start_excl  TEXT DEFAULT '',
    ver_end_excl    TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_cpe_product ON nvd_cpe(cpe_product);
CREATE INDEX IF NOT EXISTS idx_cpe_vendor  ON nvd_cpe(cpe_vendor);

CREATE TABLE IF NOT EXISTS kev_catalog (
    cve_id            TEXT PRIMARY KEY,
    product           TEXT,
    vendor            TEXT,
    short_description TEXT,
    required_action   TEXT,
    due_date          TEXT,
    date_added        TEXT
);

CREATE TABLE IF NOT EXISTS osv_entries (
    pkg_key TEXT NOT NULL,
    osv_id  TEXT NOT NULL,
    PRIMARY KEY (pkg_key, osv_id)
);

CREATE INDEX IF NOT EXISTS idx_osv_pkg ON osv_entries(pkg_key);

CREATE TABLE IF NOT EXISTS db_stats (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _migrate_schema():
    """Add new columns to nvd_cpe for existing databases (idempotent)."""
    with _conn() as c:
        cols = {r[1] for r in c.execute("PRAGMA table_info(nvd_cpe)")}
        for col in ("ver_start_incl", "ver_end_incl", "ver_start_excl", "ver_end_excl"):
            if col not in cols:
                c.execute(f"ALTER TABLE nvd_cpe ADD COLUMN {col} TEXT DEFAULT ''")


def _init_db():
    global _db_ready
    if _db_ready:
        return
    _ensure_db_dir()
    with _conn() as c:
        c.executescript(_SCHEMA)
    _migrate_schema()
    _db_ready = True
    _migrate_legacy_json()


def _migrate_legacy_json():
    """
    One-time import of legacy JSON caches into SQLite.
    Runs silently if SQLite already has data or the JSON files are absent.
    This lets a seed that completed against the old JSON code survive the
    upgrade without re-fetching everything from NVD.
    """
    with _conn() as c:
        nvd_count = c.execute("SELECT COUNT(*) FROM nvd_cves").fetchone()[0]
        kev_count = c.execute("SELECT COUNT(*) FROM kev_catalog").fetchone()[0]

    if nvd_count > 0 and kev_count > 0:
        return  # already migrated

    logger.info("vuln_db: migrating legacy JSON caches to SQLite (one-time)...")

    if _LEGACY_NVD.exists() and nvd_count == 0:
        try:
            data = json.loads(_LEGACY_NVD.read_text())
            _bulk_insert_nvd_dicts(data.values())
            logger.info(f"vuln_db: migrated {len(data):,} NVD entries from JSON")
        except Exception as e:
            logger.warning(f"vuln_db: NVD migration failed: {e}")

    if _LEGACY_KEV.exists() and kev_count == 0:
        try:
            data = json.loads(_LEGACY_KEV.read_text())
            _bulk_insert_kev_dicts(data.values())
            logger.info(f"vuln_db: migrated {len(data):,} KEV entries from JSON")
        except Exception as e:
            logger.warning(f"vuln_db: KEV migration failed: {e}")

    if _LEGACY_STATS.exists():
        try:
            stats = json.loads(_LEGACY_STATS.read_text())
            with _conn() as c:
                c.executemany(
                    "INSERT OR IGNORE INTO db_stats (key, value) VALUES (?, ?)",
                    [(k, str(v)) for k, v in stats.items()],
                )
        except Exception as e:
            logger.warning(f"vuln_db: stats migration failed: {e}")

    with _conn() as c:
        osv_count = c.execute("SELECT COUNT(*) FROM osv_entries").fetchone()[0]

    if _LEGACY_OSV.exists() and osv_count == 0:
        try:
            data = json.loads(_LEGACY_OSV.read_text())
            rows = []
            for pkg_key, ids in data.items():
                for osv_id in (ids if isinstance(ids, list) else [ids]):
                    rows.append((pkg_key, osv_id))
            with _conn() as c:
                c.executemany(
                    "INSERT OR IGNORE INTO osv_entries (pkg_key, osv_id) VALUES (?, ?)",
                    rows,
                )
            logger.info(f"vuln_db: migrated {len(rows):,} OSV entries from JSON")
        except Exception as e:
            logger.warning(f"vuln_db: OSV migration failed: {e}")


# ══════════════════════════════════════════════════════════════════════════
# Stats helpers
# ══════════════════════════════════════════════════════════════════════════

def _load_stats() -> dict:
    _init_db()
    with _conn() as c:
        return {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM db_stats")}


def _save_stats(stats: dict):
    _init_db()
    with _conn() as c:
        c.executemany(
            "INSERT OR REPLACE INTO db_stats (key, value) VALUES (?, ?)",
            [(k, str(v) if v is not None else "") for k, v in stats.items()],
        )


# ══════════════════════════════════════════════════════════════════════════
# CPE field parser
# ══════════════════════════════════════════════════════════════════════════

def _parse_cpe_fields(cpe: str) -> tuple:
    """Return (vendor, product, version) from a CPE 2.3 or 2.2 string."""
    parts = cpe.lower().split(":")
    if cpe.lower().startswith("cpe:2.3:") and len(parts) >= 6:
        return parts[3], parts[4], parts[5]
    if len(parts) >= 5:
        return parts[2], parts[3], parts[4]
    return "", "", ""


def _version_tuple(v: str) -> tuple:
    """Convert a version string to a comparable tuple of ints (up to 4 components)."""
    if not v or v in ("*", "-", ""):
        return ()
    parts = re.split(r"[.\-_]", v)
    result = []
    for p in parts[:4]:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result)


def _version_in_range(version: str,
                      start_incl: str, end_incl: str,
                      start_excl: str, end_excl: str) -> bool:
    """
    Return True if version falls within the given NVD CPE range bounds.
    Empty/missing bounds mean no constraint on that side.
    """
    v = _version_tuple(version)
    if not v:
        return True  # unparseable — can't confirm either way

    if start_incl:
        s = _version_tuple(start_incl)
        if s and v < s:
            return False
    if start_excl:
        s = _version_tuple(start_excl)
        if s and v <= s:
            return False
    if end_incl:
        e = _version_tuple(end_incl)
        if e and v > e:
            return False
    if end_excl:
        e = _version_tuple(end_excl)
        if e and v >= e:
            return False
    return True


# ══════════════════════════════════════════════════════════════════════════
# NVD batch insert helpers (shared by update and migration)
# ══════════════════════════════════════════════════════════════════════════

def _bulk_insert_nvd_dicts(entries):
    """
    Insert/replace a sequence of CVE dicts (old JSON format or new API format).
    Accepts both the legacy JSON cache dict format and the freshly-parsed format.
    """
    cve_rows = []
    cpe_rows = []
    for entry in entries:
        cve_id = entry.get("cve_id", "")
        if not cve_id:
            continue
        cve_rows.append((
            cve_id,
            (entry.get("description") or "")[:500],
            entry.get("cvss_v3_score"),
            entry.get("cvss_v3_vector"),
            entry.get("cvss_v3_severity"),
            entry.get("cvss_v2_score"),
            entry.get("published", ""),
            entry.get("last_modified", ""),
            json.dumps(entry.get("references", [])),
        ))
        for cpe_entry in entry.get("affected_cpe", []):
            if isinstance(cpe_entry, str):
                cpe_str = cpe_entry
                si = ei = sx = ex = ""
            else:
                cpe_str = cpe_entry.get("cpe", "")
                si = cpe_entry.get("ver_start_incl", "")
                ei = cpe_entry.get("ver_end_incl", "")
                sx = cpe_entry.get("ver_start_excl", "")
                ex = cpe_entry.get("ver_end_excl", "")
            if not cpe_str:
                continue
            v, p, ver = _parse_cpe_fields(cpe_str)
            cpe_rows.append((cve_id, cpe_str, v, p, ver, si, ei, sx, ex))

    if not cve_rows:
        return

    with _conn() as c:
        c.executemany(
            "INSERT OR REPLACE INTO nvd_cves "
            "(cve_id, description, cvss_v3_score, cvss_v3_vector, cvss_v3_severity, "
            " cvss_v2_score, published, last_modified, references_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            cve_rows,
        )
        # DELETE + re-INSERT CPE rows to handle updates cleanly
        c.executemany("DELETE FROM nvd_cpe WHERE cve_id = ?", [(r[0],) for r in cve_rows])
        if cpe_rows:
            c.executemany(
                "INSERT INTO nvd_cpe "
                "(cve_id, cpe, cpe_vendor, cpe_product, cpe_version, "
                " ver_start_incl, ver_end_incl, ver_start_excl, ver_end_excl) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                cpe_rows,
            )


# ══════════════════════════════════════════════════════════════════════════
# NVD Update
# ══════════════════════════════════════════════════════════════════════════

def update_nvd_cache(api_key: str = None, max_age_years: int = 5, force_full: bool = False) -> int:
    """
    Fetch CVEs from NVD 2.0 API and store in SQLite.

    - Without api_key: 5 req/30 s limit.  With key: 50 req/30 s.
    - Date range is chunked into 119-day windows (NVD API limit).
    - Interrupted seeds resume from the last completed window.
    - Returns number of CVEs processed in this run.
    """
    _init_db()
    stats = _load_stats()
    now_utc = datetime.now(timezone.utc)
    delay = NVD_RATE_LIMIT_KEY_DELAY if api_key else NVD_RATE_LIMIT_ANON_DELAY

    # ── Determine date range ───────────────────────────────────────────────
    if force_full or not stats.get("nvd_last_updated"):
        full_start = now_utc - timedelta(days=365 * max_age_years)
        resume_from = stats.get("nvd_init_window_start")
        if resume_from and not force_full:
            try:
                start_date = datetime.fromisoformat(resume_from).replace(tzinfo=timezone.utc)
                logger.info(f"NVD: Resuming full fetch from {start_date.date()}...")
            except Exception:
                start_date = full_start
                logger.info(f"NVD: Full fetch from {start_date.date()} (last {max_age_years} years)...")
        else:
            start_date = full_start
            logger.info(f"NVD: Full fetch from {start_date.date()} (last {max_age_years} years)...")
    else:
        last_updated = datetime.fromisoformat(stats["nvd_last_updated"]).replace(tzinfo=timezone.utc)
        start_date = last_updated - timedelta(days=1)
        logger.info(f"NVD: Incremental update from {start_date.date()}...")

    end_date = now_utc
    headers = {"User-Agent": "YeylandWutani-RiskScanner/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    new_count  = 0
    window_start = start_date

    while window_start < end_date:
        window_end    = min(window_start + timedelta(days=NVD_WINDOW_DAYS), end_date)
        win_start_str = window_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        win_end_str   = window_end.strftime("%Y-%m-%dT%H:%M:%S.000")
        logger.info(f"NVD: window {win_start_str[:10]} → {win_end_str[:10]}")

        start_index = 0
        while True:
            # NVD API requires literal colons in date strings (not %3A)
            params = (
                f"?pubStartDate={urllib.parse.quote(win_start_str, safe=':.-')}"
                f"&pubEndDate={urllib.parse.quote(win_end_str, safe=':.-')}"
                f"&startIndex={start_index}"
                f"&resultsPerPage={NVD_PAGE_SIZE}"
            )
            url = NVD_API_BASE + params

            data = {}
            for attempt in range(3):
                try:
                    req = urllib.request.Request(url, headers=headers)
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                    break
                except urllib.error.HTTPError as e:
                    if e.code == 403:
                        logger.warning("NVD API: 403 — check API key or rate limit")
                        time.sleep(30)
                    elif e.code == 503:
                        logger.warning(f"NVD API: 503 — retry {attempt+1}/3")
                        time.sleep(10 * (attempt + 1))
                    else:
                        raise
                except Exception as e:
                    if attempt < 2:
                        logger.warning(f"NVD API error (attempt {attempt+1}): {e}, retrying...")
                        time.sleep(5)
                    else:
                        raise

            vulnerabilities = data.get("vulnerabilities", [])
            total_results   = data.get("totalResults", 0)

            # Parse and batch-insert
            entries = []
            for vuln_wrapper in vulnerabilities:
                cve = vuln_wrapper.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                metrics = cve.get("metrics", {})
                cvss_v3_score = cvss_v3_vector = cvss_v3_severity = cvss_v2_score = None
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        cvss_v3_score    = m.get("baseScore")
                        cvss_v3_vector   = m.get("vectorString")
                        cvss_v3_severity = m.get("baseSeverity")
                        break
                if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    m = metrics["cvssMetricV2"][0].get("cvssData", {})
                    cvss_v2_score = m.get("baseScore")

                descriptions = cve.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    descriptions[0]["value"] if descriptions else "",
                )

                affected_cpe = []
                for config in cve.get("configurations", []):
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            if cpe_match.get("vulnerable"):
                                cpe = cpe_match.get("criteria", "")
                                if cpe:
                                    affected_cpe.append({
                                        "cpe":            cpe,
                                        "ver_start_incl": cpe_match.get("versionStartIncluding", ""),
                                        "ver_end_incl":   cpe_match.get("versionEndIncluding", ""),
                                        "ver_start_excl": cpe_match.get("versionStartExcluding", ""),
                                        "ver_end_excl":   cpe_match.get("versionEndExcluding", ""),
                                    })

                entries.append({
                    "cve_id":          cve_id,
                    "description":     description,
                    "cvss_v3_score":   cvss_v3_score,
                    "cvss_v3_vector":  cvss_v3_vector,
                    "cvss_v3_severity":cvss_v3_severity,
                    "cvss_v2_score":   cvss_v2_score,
                    "affected_cpe":    affected_cpe[:20],
                    "published":       cve.get("published", ""),
                    "last_modified":   cve.get("lastModified", ""),
                    "references":      [r.get("url", "") for r in cve.get("references", [])[:5]],
                })

            _bulk_insert_nvd_dicts(entries)
            new_count += len(entries)

            logger.info(
                f"NVD: fetched {len(vulnerabilities)} CVEs "
                f"(index {start_index}/{total_results}, window {win_start_str[:10]})"
            )

            start_index += len(vulnerabilities)
            if start_index >= total_results or not vulnerabilities:
                break

            time.sleep(delay)

        # Checkpoint: save next window start for resume on interruption
        next_window = window_end + timedelta(seconds=1)
        with _conn() as c:
            cve_count = c.execute("SELECT COUNT(*) FROM nvd_cves").fetchone()[0]
        _save_stats({
            "nvd_init_window_start": next_window.isoformat(),
            "nvd_cve_count":         str(cve_count),
        })
        window_start = next_window

    # Incremental: also fetch by lastModDate to catch edited CVEs
    if not force_full and stats.get("nvd_last_updated"):
        _fetch_modified_nvd(api_key, start_date, end_date, delay)

    with _conn() as c:
        final_count = c.execute("SELECT COUNT(*) FROM nvd_cves").fetchone()[0]
    _save_stats({
        "nvd_last_updated":      now_utc.isoformat(),
        "nvd_cve_count":         str(final_count),
        "nvd_init_window_start": "",   # clear resume marker on success
    })

    logger.info(f"NVD update complete: {new_count} CVEs processed, {final_count:,} total in DB")
    return new_count


def _fetch_modified_nvd(api_key, start_date, end_date, delay):
    """Fetch CVEs modified since last update and refresh their last_modified."""
    start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str   = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    headers   = {"User-Agent": "YeylandWutani-RiskScanner/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    params = (
        f"?lastModStartDate={urllib.parse.quote(start_str, safe=':.-')}"
        f"&lastModEndDate={urllib.parse.quote(end_str, safe=':.-')}"
        f"&resultsPerPage={NVD_PAGE_SIZE}"
    )
    try:
        req = urllib.request.Request(NVD_API_BASE + params, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        rows = [
            (v.get("cve", {}).get("lastModified", ""), v.get("cve", {}).get("id", ""))
            for v in data.get("vulnerabilities", [])
            if v.get("cve", {}).get("id")
        ]
        if rows:
            with _conn() as c:
                c.executemany(
                    "UPDATE nvd_cves SET last_modified = ? WHERE cve_id = ?", rows
                )
            logger.debug(f"NVD: refreshed last_modified for {len(rows)} CVEs")
    except Exception as e:
        logger.debug(f"NVD modified fetch failed (non-critical): {e}")


# ══════════════════════════════════════════════════════════════════════════
# KEV Update
# ══════════════════════════════════════════════════════════════════════════

def _bulk_insert_kev_dicts(entries):
    rows = []
    for vuln in entries:
        cve_id = vuln.get("cve_id") or vuln.get("cveID", "")
        if not cve_id:
            continue
        rows.append((
            cve_id,
            vuln.get("product", ""),
            vuln.get("vendor") or vuln.get("vendorProject", ""),
            vuln.get("short_description") or vuln.get("shortDescription", ""),
            vuln.get("required_action") or vuln.get("requiredAction", ""),
            vuln.get("due_date") or vuln.get("dueDate", ""),
            vuln.get("date_added") or vuln.get("dateAdded", ""),
        ))
    with _conn() as c:
        c.executemany(
            "INSERT OR REPLACE INTO kev_catalog "
            "(cve_id, product, vendor, short_description, required_action, due_date, date_added) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def update_kev_catalog() -> int:
    """Fetch CISA KEV catalog into SQLite. Returns entry count."""
    _init_db()
    global _kev_cache

    logger.info("KEV: Fetching CISA Known Exploited Vulnerabilities catalog...")
    try:
        req = urllib.request.Request(
            KEV_URL,
            headers={"User-Agent": "YeylandWutani-RiskScanner/1.0"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logger.error(f"KEV: Failed to fetch catalog: {e}")
        return 0

    count = _bulk_insert_kev_dicts(data.get("vulnerabilities", []))
    _kev_cache = {}   # invalidate in-memory cache

    _save_stats({
        "kev_last_updated": datetime.now(timezone.utc).isoformat(),
        "kev_cve_count":    str(count),
    })
    logger.info(f"KEV: catalog updated — {count} known exploited CVEs")
    return count


# ══════════════════════════════════════════════════════════════════════════
# OSV Update
# ══════════════════════════════════════════════════════════════════════════

def update_osv_cache(ecosystems: list = None) -> int:
    """
    Download OSV bulk data from GCS and store in SQLite.
    Uses https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
    Returns number of package/version entries written.
    """
    if ecosystems is None:
        ecosystems = ["PyPI", "npm"]

    _init_db()
    new_count = 0

    for ecosystem in ecosystems:
        url = f"{OSV_GCS_BASE}/{ecosystem}/all.zip"
        logger.info(f"OSV: Downloading {ecosystem} bulk data from GCS...")
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "YeylandWutani-RiskScanner/1.0"},
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                zip_data = resp.read()

            rows = []
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        vuln = json.loads(zf.read(name))
                    except Exception:
                        continue
                    osv_id = vuln.get("id", "")
                    for affected in vuln.get("affected", []):
                        pkg_name = affected.get("package", {}).get("name", "")
                        if not pkg_name:
                            continue
                        for version in affected.get("versions", []):
                            rows.append((f"{pkg_name}:{version}", osv_id))

            with _conn() as c:
                c.executemany(
                    "INSERT OR IGNORE INTO osv_entries (pkg_key, osv_id) VALUES (?, ?)",
                    rows,
                )
            new_count += len(rows)
            logger.info(f"OSV: {ecosystem} — {len(rows):,} entries")
        except Exception as e:
            logger.warning(f"OSV: {ecosystem} bulk download failed: {e}")

    with _conn() as c:
        total = c.execute("SELECT COUNT(*) FROM osv_entries").fetchone()[0]
    _save_stats({
        "osv_last_updated": datetime.now(timezone.utc).isoformat(),
        "osv_entry_count":  str(total),
    })
    logger.info(f"OSV: cache updated — {new_count:,} new entries, {total:,} total")
    return new_count


# ══════════════════════════════════════════════════════════════════════════
# Lookup Functions
# ══════════════════════════════════════════════════════════════════════════

def _row_to_cve_dict(row) -> dict:
    """Convert a SQLite Row from nvd_cves into the standard CVE dict."""
    return {
        "cve_id":           row["cve_id"],
        "description":      row["description"] or "",
        "cvss_v3_score":    row["cvss_v3_score"],
        "cvss_v3_vector":   row["cvss_v3_vector"],
        "cvss_v3_severity": row["cvss_v3_severity"],
        "cvss_v2_score":    row["cvss_v2_score"],
        "affected_cpe":     [],   # omitted from bulk queries for performance
        "published":        row["published"] or "",
        "last_modified":    row["last_modified"] or "",
        "references":       json.loads(row["references_json"] or "[]"),
    }


def _any_cpe_covers_version(version_l: str, cpe_list: list) -> bool:
    """
    Return True if any CPE row in cpe_list covers the given version string.
    cpe_list items: (cpe_version, ver_start_incl, ver_end_incl, ver_start_excl, ver_end_excl)
    """
    for cpe_ver, si, ei, sx, ex in cpe_list:
        if cpe_ver and cpe_ver not in ("*", "-", ""):
            # Explicit version — must match our version (substring both ways)
            if version_l in cpe_ver or cpe_ver in version_l:
                return True
        else:
            # Wildcard version — check range bounds if present
            if si or ei or sx or ex:
                if _version_in_range(version_l, si, ei, sx, ex):
                    return True
            else:
                # No range data at all (old or incomplete NVD entry) — assume covered
                return True
    return False


def verify_cve_for_service(cve_id: str, product: str, version: str) -> str:
    """
    Check whether a specific detected version is actually affected by cve_id
    according to NVD CPE data.

    Returns:
      "confirmed"      - NVD CPE data confirms this version is in an affected range
      "likely_patched" - NVD has CPE data for this product but this version is outside
                         all affected ranges (i.e. the vulnerability was patched)
      "unverified"     - No matching CPE rows found, or all rows lack range bounds
                         (cannot determine — treat conservatively)
    """
    if not version or not product:
        return "unverified"

    _init_db()
    product_l = product.lower().strip().replace(" ", "_")

    with _conn() as c:
        rows = c.execute(
            """
            SELECT cpe_version, ver_start_incl, ver_end_incl, ver_start_excl, ver_end_excl
            FROM nvd_cpe
            WHERE cve_id = ? AND cpe_product LIKE ?
            """,
            (cve_id, f"%{product_l}%"),
        ).fetchall()

    if not rows:
        return "unverified"

    has_checkable_data = False
    for row in rows:
        cpe_ver = row[0] or ""
        si, ei, sx, ex = row[1] or "", row[2] or "", row[3] or "", row[4] or ""

        if cpe_ver and cpe_ver not in ("*", "-", ""):
            has_checkable_data = True
            if _version_tuple(cpe_ver) == _version_tuple(version):
                return "confirmed"
        else:
            if si or ei or sx or ex:
                has_checkable_data = True
                if _version_in_range(version, si, ei, sx, ex):
                    return "confirmed"

    if has_checkable_data:
        return "likely_patched"
    return "unverified"


def lookup_cves(vendor: str, product: str, version: str = None) -> list:
    """
    Query SQLite for CVEs matching vendor/product/version via CPE indexes.
    Returns list of CVE dicts sorted by CVSS score descending.
    """
    _init_db()
    if not vendor and not product:
        return []

    vendor_l  = vendor.lower().strip().replace(" ", "_")
    product_l = product.lower().strip().replace(" ", "_")
    version_l = (version or "").lower().strip()

    results = []
    seen    = set()

    with _conn() as c:
        # ── Query 1: our product term appears within the CPE product field ──
        # Uses idx_cpe_product for the LIKE scan; fetches per-CPE-row range data
        # so Python-side version range filtering can decide inclusion.
        q1 = """
            SELECT cv.cve_id, cv.description, cv.cvss_v3_score, cv.cvss_v3_vector,
                   cv.cvss_v3_severity, cv.cvss_v2_score, cv.published,
                   cv.last_modified, cv.references_json,
                   cp.cpe_version, cp.ver_start_incl, cp.ver_end_incl,
                   cp.ver_start_excl, cp.ver_end_excl
            FROM nvd_cves cv
            JOIN nvd_cpe cp ON cv.cve_id = cp.cve_id
            WHERE cp.cpe_product LIKE ?
              AND (? = '' OR cp.cpe_vendor LIKE ? OR cp.cpe_vendor LIKE ?)
            LIMIT 1000
        """
        # Accumulate all CPE rows per CVE so we can test if ANY row covers the version
        _q1_cpe_data: dict = {}   # cve_id -> (first_row, [(cpe_ver, si, ei, sx, ex), ...])
        for row in c.execute(q1, (
            f"%{product_l}%",
            vendor_l, f"%{vendor_l}%", f"%{vendor.lower().replace(' ', '_')}%",
        )).fetchall():
            cve_id = row["cve_id"]
            cpe_data = (
                row["cpe_version"]    or "",
                row["ver_start_incl"] or "",
                row["ver_end_incl"]   or "",
                row["ver_start_excl"] or "",
                row["ver_end_excl"]   or "",
            )
            if cve_id not in _q1_cpe_data:
                _q1_cpe_data[cve_id] = (row, [])
            _q1_cpe_data[cve_id][1].append(cpe_data)

        for cve_id, (row, cpe_list) in _q1_cpe_data.items():
            if cve_id in seen:
                continue
            if version_l and not _any_cpe_covers_version(version_l, cpe_list):
                continue
            seen.add(cve_id)
            results.append(_row_to_cve_dict(row))

        # ── Query 2: CPE product field is a token inside our search term ──
        # (e.g. we search "internet_information_services", CPE has "iis")
        # SQLite can't reverse-LIKE with an index, so we fetch candidate rows
        # filtered by length and do the substring check in Python.
        if len(product_l) >= 8:
            q2 = """
                SELECT cv.cve_id, cv.description, cv.cvss_v3_score, cv.cvss_v3_vector,
                       cv.cvss_v3_severity, cv.cvss_v2_score, cv.published,
                       cv.last_modified, cv.references_json,
                       cp.cpe_product, cp.cpe_vendor, cp.cpe_version,
                       cp.ver_start_incl, cp.ver_end_incl, cp.ver_start_excl, cp.ver_end_excl
                FROM nvd_cves cv
                JOIN nvd_cpe cp ON cv.cve_id = cp.cve_id
                WHERE length(cp.cpe_product) BETWEEN 5 AND ?
                LIMIT 5000
            """
            _q2_cpe_data: dict = {}
            for row in c.execute(q2, (len(product_l) - 1,)).fetchall():
                cve_id = row["cve_id"]
                cp  = row["cpe_product"] or ""
                cvn = row["cpe_vendor"]  or ""
                if cp not in product_l:
                    continue
                if vendor_l and vendor_l not in cvn and vendor.lower().replace(" ", "_") not in cvn:
                    continue
                cpe_data = (
                    row["cpe_version"]    or "",
                    row["ver_start_incl"] or "",
                    row["ver_end_incl"]   or "",
                    row["ver_start_excl"] or "",
                    row["ver_end_excl"]   or "",
                )
                if cve_id not in _q2_cpe_data:
                    _q2_cpe_data[cve_id] = (row, [])
                _q2_cpe_data[cve_id][1].append(cpe_data)

            for cve_id, (row, cpe_list) in _q2_cpe_data.items():
                if cve_id in seen:
                    continue
                if version_l and not _any_cpe_covers_version(version_l, cpe_list):
                    continue
                seen.add(cve_id)
                results.append(_row_to_cve_dict(row))

    # Fallback to static DB if SQLite has nothing yet
    if not results:
        _load_fallback_db()
        for cve_id, entry in _fallback_db.items():
            if cve_id in seen:
                continue
            for cpe in entry.get("affected_cpe", []):
                if product_l in cpe.lower():
                    results.append(entry)
                    seen.add(cve_id)
                    break

    results.sort(
        key=lambda x: (x.get("cvss_v3_score") or x.get("cvss_v2_score") or 0),
        reverse=True,
    )
    return results


def lookup_cpe(cpe_string: str) -> list:
    """Exact or partial CPE string lookup. Returns list of CVE dicts."""
    _init_db()
    cpe_l = cpe_string.lower()
    with _conn() as c:
        rows = c.execute(
            "SELECT DISTINCT cv.* FROM nvd_cves cv "
            "JOIN nvd_cpe cp ON cv.cve_id = cp.cve_id "
            "WHERE cp.cpe = ? OR cp.cpe LIKE ?",
            (cpe_l, f"%{cpe_l}%"),
        ).fetchall()
    results = [_row_to_cve_dict(r) for r in rows]
    results.sort(
        key=lambda x: (x.get("cvss_v3_score") or x.get("cvss_v2_score") or 0),
        reverse=True,
    )
    return results


def _load_kev():
    global _kev_cache
    if _kev_cache:
        return
    _init_db()
    with _conn() as c:
        _kev_cache = {r["cve_id"]: dict(r) for r in c.execute("SELECT * FROM kev_catalog")}


def _load_fallback_db():
    global _fallback_db
    if _fallback_db:
        return
    if FALLBACK_DB_PATH.exists():
        try:
            _fallback_db = json.loads(FALLBACK_DB_PATH.read_text())
        except Exception as e:
            logger.warning(f"Could not load fallback vuln DB: {e}")


def is_kev(cve_id: str) -> bool:
    """Return True if cve_id is in the CISA Known Exploited Vulnerabilities catalog."""
    _load_kev()
    return cve_id in _kev_cache


def get_kev_entry(cve_id: str) -> Optional[dict]:
    """Return KEV entry dict for a CVE ID, or None."""
    _load_kev()
    return _kev_cache.get(cve_id)


def get_cvss_score(cve_id: str) -> Optional[float]:
    """Return CVSS v3 score, falling back to v2. Returns None if not found."""
    _init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT cvss_v3_score, cvss_v2_score FROM nvd_cves WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
    if row:
        return row["cvss_v3_score"] or row["cvss_v2_score"]
    _load_fallback_db()
    entry = _fallback_db.get(cve_id)
    return (entry.get("cvss_v3_score") or entry.get("cvss_v2_score")) if entry else None


def format_cvss_severity(score: Optional[float]) -> str:
    """Return CRITICAL / HIGH / MEDIUM / LOW / INFO based on CVSS score."""
    if score is None:
        return "INFO"
    if score >= CVSS_CRITICAL:
        return "CRITICAL"
    if score >= CVSS_HIGH:
        return "HIGH"
    if score >= CVSS_MEDIUM:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def get_db_stats() -> dict:
    """Return DB stats: CVE count, KEV count, last update timestamps."""
    _init_db()
    with _conn() as c:
        nvd_count = c.execute("SELECT COUNT(*) FROM nvd_cves").fetchone()[0]
        kev_count = c.execute("SELECT COUNT(*) FROM kev_catalog").fetchone()[0]
        osv_count = c.execute("SELECT COUNT(*) FROM osv_entries").fetchone()[0]
    stats = _load_stats()
    nvd_last = stats.get("nvd_last_updated", "")
    last_updated_ts = None
    if nvd_last:
        try:
            last_updated_ts = datetime.fromisoformat(nvd_last).timestamp()
        except Exception:
            pass
    return {
        # Keys used by update-vuln-db.py _print_stats()
        "cve_count":        nvd_count,
        "kev_count":        kev_count,
        "osv_count":        osv_count,
        "last_updated":     last_updated_ts,
        "stale":            is_db_stale(),
        "kev_last_modified":stats.get("kev_last_updated", ""),
        "db_path":          str(DB_PATH),
        # Full detail keys (web dashboard etc.)
        "nvd_cve_count":    nvd_count,
        "kev_cve_count":    kev_count,
        "osv_entry_count":  osv_count,
        "nvd_last_updated": stats.get("nvd_last_updated", "never"),
        "kev_last_updated": stats.get("kev_last_updated", "never"),
        "osv_last_updated": stats.get("osv_last_updated", "never"),
        "nvd_cache_path":   str(DB_PATH),
        "kev_cache_path":   str(DB_PATH),
    }


def is_db_stale(max_age_days: int = 7) -> bool:
    """Return True if NVD data is older than max_age_days or missing."""
    stats = _load_stats()
    last_updated = stats.get("nvd_last_updated")
    if not last_updated:
        return True
    try:
        last_dt = datetime.fromisoformat(last_updated).replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - last_dt).days >= max_age_days
    except Exception:
        return True
