#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
vuln_db.py - Local Vulnerability Database Cache

Manages local NVD/KEV/OSV caches for offline CVE correlation.
Supports incremental NVD updates, CISA KEV catalog, and OSV lookup.
"""

import gzip
import io
import json
import logging
import os
import time
import urllib.parse
import urllib.request
import urllib.error
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────────────
VULN_DB_DIR = Path("/opt/risk-scanner/data/vuln-db")
NVD_CACHE_PATH = VULN_DB_DIR / "nvd-cache.json"
KEV_CACHE_PATH = VULN_DB_DIR / "kev-catalog.json"
OSV_CACHE_PATH = VULN_DB_DIR / "osv-cache.json"
DB_STATS_PATH  = VULN_DB_DIR / "db-stats.json"

# Fallback ships with the tool for offline use (first 200 most common CVEs)
FALLBACK_DB_PATH = Path(__file__).parent.parent / "data" / "vuln-db" / "vuln-db-fallback.json"

# ── NVD API ────────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Without API key: 5 req / 30s rolling window.  With key: 50 req / 30s.
NVD_RATE_LIMIT_ANON_DELAY = 6.5  # seconds between requests without key
NVD_RATE_LIMIT_KEY_DELAY  = 0.6  # seconds between requests with key
NVD_PAGE_SIZE = 2000              # max results per API call

# ── KEV API ────────────────────────────────────────────────────────────────
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ── OSV API ────────────────────────────────────────────────────────────────
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_GCS_BASE  = "https://osv-vulnerabilities.storage.googleapis.com"

# ── Severity thresholds ────────────────────────────────────────────────────
CVSS_CRITICAL = 9.0
CVSS_HIGH     = 7.0
CVSS_MEDIUM   = 4.0


# ── In-memory caches (loaded lazily) ──────────────────────────────────────
_nvd_cache: dict = {}
_kev_cache: dict = {}
_osv_cache: dict = {}
_fallback_db: dict = {}
_caches_loaded = False


def _ensure_db_dir():
    VULN_DB_DIR.mkdir(parents=True, exist_ok=True)


def _load_caches():
    global _nvd_cache, _kev_cache, _osv_cache, _fallback_db, _caches_loaded
    if _caches_loaded:
        return
    _caches_loaded = True

    # NVD cache
    if NVD_CACHE_PATH.exists():
        try:
            _nvd_cache = json.loads(NVD_CACHE_PATH.read_text())
            logger.debug(f"NVD cache loaded: {len(_nvd_cache)} entries")
        except Exception as e:
            logger.warning(f"Could not load NVD cache: {e}")

    # KEV catalog
    if KEV_CACHE_PATH.exists():
        try:
            _kev_cache = json.loads(KEV_CACHE_PATH.read_text())
            logger.debug(f"KEV catalog loaded: {len(_kev_cache)} entries")
        except Exception as e:
            logger.warning(f"Could not load KEV catalog: {e}")

    # OSV cache
    if OSV_CACHE_PATH.exists():
        try:
            _osv_cache = json.loads(OSV_CACHE_PATH.read_text())
            logger.debug(f"OSV cache loaded: {len(_osv_cache)} entries")
        except Exception as e:
            logger.warning(f"Could not load OSV cache: {e}")

    # Fallback DB
    if FALLBACK_DB_PATH.exists():
        try:
            _fallback_db = json.loads(FALLBACK_DB_PATH.read_text())
            logger.debug(f"Fallback vuln DB loaded: {len(_fallback_db)} entries")
        except Exception as e:
            logger.warning(f"Could not load fallback vuln DB: {e}")


def _save_stats(stats: dict):
    _ensure_db_dir()
    try:
        DB_STATS_PATH.write_text(json.dumps(stats, indent=2))
    except Exception as e:
        logger.warning(f"Could not save DB stats: {e}")


def _load_stats() -> dict:
    if DB_STATS_PATH.exists():
        try:
            return json.loads(DB_STATS_PATH.read_text())
        except Exception:
            pass
    return {}


# ── NVD Update ─────────────────────────────────────────────────────────────

def update_nvd_cache(api_key: str = None, max_age_years: int = 5, force_full: bool = False) -> int:
    """
    Fetch CVEs from NVD 2.0 REST API and update local cache.

    - Without api_key: 5 req/30s limit — incremental updates use 1-2 requests.
    - With api_key: 50 req/30s — faster initial seed.
    - filter: only CVEs published/modified within last max_age_years years.
    - Returns number of new/updated CVEs written.
    """
    _ensure_db_dir()
    global _nvd_cache

    stats = _load_stats()
    now_utc = datetime.now(timezone.utc)
    delay = NVD_RATE_LIMIT_KEY_DELAY if api_key else NVD_RATE_LIMIT_ANON_DELAY

    # Determine date range for incremental update
    if force_full or not stats.get("nvd_last_updated"):
        # Full fetch: last max_age_years years
        full_start = now_utc - timedelta(days=365 * max_age_years)
        # Resume: if a previous --init was interrupted, skip already-done windows
        resume_from = stats.get("nvd_init_window_start")
        if resume_from and not force_full:
            try:
                start_date = datetime.fromisoformat(resume_from).replace(tzinfo=timezone.utc)
                logger.info(f"NVD: Resuming full fetch from {start_date.date()} (interrupted earlier)...")
            except Exception:
                start_date = full_start
                logger.info(f"NVD: Full fetch from {start_date.date()} (last {max_age_years} years)...")
        else:
            start_date = full_start
            logger.info(f"NVD: Full fetch from {start_date.date()} (last {max_age_years} years)...")
    else:
        # Incremental: 1 day overlap to catch any late edits
        last_updated = datetime.fromisoformat(stats["nvd_last_updated"]).replace(tzinfo=timezone.utc)
        start_date = last_updated - timedelta(days=1)
        logger.info(f"NVD: Incremental update from {start_date.date()}...")

    end_date = now_utc

    # Load existing cache
    if NVD_CACHE_PATH.exists():
        try:
            _nvd_cache = json.loads(NVD_CACHE_PATH.read_text())
        except Exception:
            _nvd_cache = {}
    else:
        _nvd_cache = {}

    headers = {"User-Agent": "YeylandWutani-RiskScanner/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    new_count = 0
    # NVD API enforces a maximum date range of 120 days per request.
    # Split the full range into 119-day windows and paginate each.
    NVD_WINDOW_DAYS = 119
    window_start = start_date

    while window_start < end_date:
        window_end = min(window_start + timedelta(days=NVD_WINDOW_DAYS), end_date)
        win_start_str = window_start.strftime("%Y-%m-%dT%H:%M:%S.000")
        win_end_str   = window_end.strftime("%Y-%m-%dT%H:%M:%S.000")
        logger.info(f"NVD: window {win_start_str[:10]} → {win_end_str[:10]}")

        start_index = 0
        while True:
            # NVD API requires colons to be literal in date strings (not %3A)
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
            total_results = data.get("totalResults", 0)

            for vuln_wrapper in vulnerabilities:
                cve = vuln_wrapper.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                # Extract CVSS scores
                metrics = cve.get("metrics", {})
                cvss_v3_score = None
                cvss_v3_vector = None
                cvss_v3_severity = None
                cvss_v2_score = None

                # CVSSv3.1 preferred, then v3.0
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        cvss_v3_score = m.get("baseScore")
                        cvss_v3_vector = m.get("vectorString")
                        cvss_v3_severity = m.get("baseSeverity")
                        break
                if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    m = metrics["cvssMetricV2"][0].get("cvssData", {})
                    cvss_v2_score = m.get("baseScore")

                # Description (English preferred)
                descriptions = cve.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    descriptions[0]["value"] if descriptions else "",
                )

                # CPE matches for affected products
                affected_cpe = []
                for config in cve.get("configurations", []):
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            if cpe_match.get("vulnerable"):
                                cpe = cpe_match.get("criteria", "")
                                if cpe:
                                    affected_cpe.append(cpe)

                # References
                references = [r.get("url", "") for r in cve.get("references", [])[:5]]

                entry = {
                    "cve_id": cve_id,
                    "description": description[:500],
                    "cvss_v3_score": cvss_v3_score,
                    "cvss_v3_vector": cvss_v3_vector,
                    "cvss_v3_severity": cvss_v3_severity,
                    "cvss_v2_score": cvss_v2_score,
                    "affected_cpe": affected_cpe[:20],
                    "published": cve.get("published", ""),
                    "last_modified": cve.get("lastModified", ""),
                    "references": references,
                }
                _nvd_cache[cve_id] = entry
                new_count += 1

            logger.info(
                f"NVD: fetched {len(vulnerabilities)} CVEs "
                f"(index {start_index}/{total_results}, window {win_start_str[:10]})"
            )

            start_index += len(vulnerabilities)
            if start_index >= total_results or not vulnerabilities:
                break

            time.sleep(delay)

        # Checkpoint: save cache and record next window start so a re-run can resume
        NVD_CACHE_PATH.write_text(json.dumps(_nvd_cache))
        next_window = window_end + timedelta(seconds=1)
        stats["nvd_init_window_start"] = next_window.isoformat()
        stats["nvd_cve_count"] = len(_nvd_cache)
        _save_stats(stats)
        window_start = next_window

    # Also do incremental update for lastModStartDate
    # Run same fetch for lastModStartDate to catch edited CVEs
    if not force_full and stats.get("nvd_last_updated"):
        _fetch_modified_nvd(api_key, start_date, end_date, delay)

    stats["nvd_last_updated"] = now_utc.isoformat()
    stats["nvd_cve_count"] = len(_nvd_cache)
    stats.pop("nvd_init_window_start", None)  # clear resume marker on success
    _save_stats(stats)

    logger.info(f"NVD update complete: {new_count} CVEs processed, {len(_nvd_cache)} total in cache")
    return new_count


def _fetch_modified_nvd(api_key, start_date, end_date, delay):
    """Fetch CVEs modified since last update (separate from published date range)."""
    global _nvd_cache

    start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str   = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    headers = {"User-Agent": "YeylandWutani-RiskScanner/1.0"}
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
        count = 0
        for vuln_wrapper in data.get("vulnerabilities", []):
            cve = vuln_wrapper.get("cve", {})
            cve_id = cve.get("id", "")
            if cve_id and cve_id in _nvd_cache:
                # Update last_modified field
                _nvd_cache[cve_id]["last_modified"] = cve.get("lastModified", "")
                count += 1
        if count:
            logger.debug(f"NVD: updated last_modified for {count} existing CVEs")
    except Exception as e:
        logger.debug(f"NVD modified fetch failed (non-critical): {e}")


# ── KEV Update ─────────────────────────────────────────────────────────────

def update_kev_catalog() -> int:
    """
    Fetch CISA Known Exploited Vulnerabilities catalog.
    Returns number of KEV entries written.
    """
    _ensure_db_dir()
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

    _kev_cache = {}
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue
        _kev_cache[cve_id] = {
            "cve_id": cve_id,
            "product": vuln.get("product", ""),
            "vendor": vuln.get("vendorProject", ""),
            "short_description": vuln.get("shortDescription", ""),
            "required_action": vuln.get("requiredAction", ""),
            "due_date": vuln.get("dueDate", ""),
            "date_added": vuln.get("dateAdded", ""),
        }

    KEV_CACHE_PATH.write_text(json.dumps(_kev_cache, indent=2))

    stats = _load_stats()
    stats["kev_last_updated"] = datetime.now(timezone.utc).isoformat()
    stats["kev_cve_count"] = len(_kev_cache)
    _save_stats(stats)

    logger.info(f"KEV: catalog updated — {len(_kev_cache)} known exploited CVEs")
    return len(_kev_cache)


# ── OSV Update ─────────────────────────────────────────────────────────────

def update_osv_cache(ecosystems: list = None) -> int:
    """
    Fetch OSV (Open Source Vulnerabilities) via GCS bulk download.
    Uses https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip
    Results keyed by 'package:version'.
    Returns number of OSV package/version entries written.
    """
    if ecosystems is None:
        ecosystems = ["PyPI", "npm"]

    _ensure_db_dir()
    global _osv_cache

    if OSV_CACHE_PATH.exists():
        try:
            _osv_cache = json.loads(OSV_CACHE_PATH.read_text())
        except Exception:
            _osv_cache = {}

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
                        pkg = affected.get("package", {})
                        pkg_name = pkg.get("name", "")
                        if not pkg_name:
                            continue
                        for version in affected.get("versions", []):
                            key = f"{pkg_name}:{version}"
                            if key not in _osv_cache:
                                _osv_cache[key] = []
                            if osv_id not in _osv_cache[key]:
                                _osv_cache[key].append(osv_id)
                            new_count += 1

            logger.info(f"OSV: {ecosystem} — {new_count} entries so far")
        except Exception as e:
            logger.warning(f"OSV: {ecosystem} bulk download failed: {e}")

    OSV_CACHE_PATH.write_text(json.dumps(_osv_cache))

    stats = _load_stats()
    stats["osv_last_updated"] = datetime.now(timezone.utc).isoformat()
    stats["osv_entry_count"] = len(_osv_cache)
    _save_stats(stats)

    logger.info(f"OSV: cache updated — {new_count} package/version entries, {len(_osv_cache)} unique keys")
    return new_count


# ── Lookup Functions ───────────────────────────────────────────────────────

def lookup_cves(vendor: str, product: str, version: str = None) -> list:
    """
    Query local NVD cache for CVEs matching vendor/product/version.
    Uses CPE string matching with fuzzy version comparison.
    Returns list of CVE dicts sorted by CVSS score descending.
    """
    _load_caches()
    if not vendor and not product:
        return []

    vendor_l = vendor.lower().strip()
    product_l = product.lower().strip()
    version_l = (version or "").lower().strip()

    results = []
    seen = set()

    # Search NVD cache
    for cve_id, entry in _nvd_cache.items():
        if cve_id in seen:
            continue
        matched = False
        for cpe in entry.get("affected_cpe", []):
            cpe_l = cpe.lower()

            # Parse individual CPE fields so we match against vendor/product/version
            # slots rather than doing substring search on the full CPE string.
            # CPE 2.3: cpe:2.3:<type>:<vendor>:<product>:<version>:...
            # CPE 2.2: cpe:/<type>:<vendor>:<product>:<version>:...
            cpe_parts = cpe_l.split(":")
            if cpe_l.startswith("cpe:2.3:") and len(cpe_parts) >= 6:
                cpe_vendor_f  = cpe_parts[3]
                cpe_product_f = cpe_parts[4]
                cpe_version_f = cpe_parts[5]
            elif len(cpe_parts) >= 5:
                cpe_vendor_f  = cpe_parts[2]
                cpe_product_f = cpe_parts[3]
                cpe_version_f = cpe_parts[4]
            else:
                continue

            # Normalize spaces → underscores to match CPE encoding
            prod_norm = product_l.replace(" ", "_")
            vend_norm = vendor_l.replace(" ", "_")

            # Product field: bidirectional substring with a minimum-length guard
            # to prevent very short CPE product tokens matching long query names.
            prod_match = (
                prod_norm in cpe_product_f
                or (len(cpe_product_f) >= 5 and cpe_product_f in prod_norm)
            )
            if not prod_match:
                continue

            # Vendor match when a vendor was supplied (skip check when empty)
            if vendor_l and vend_norm not in cpe_vendor_f and vendor_l not in cpe_vendor_f:
                continue

            # Version: inspect the CPE version *field* only.
            # "*" or "-" in that field means "all versions affected".
            # Checking "*" in the full CPE string was wrong — it always matched
            # because CPE strings end with multiple wildcard components.
            if version_l:
                if cpe_version_f in ("*", "-"):
                    matched = True
                elif version_l in cpe_version_f or cpe_version_f in version_l:
                    matched = True
            else:
                matched = True
        if matched:
            results.append(entry)
            seen.add(cve_id)

    # Search fallback DB if NVD cache is empty
    if not results and _fallback_db:
        for cve_id, entry in _fallback_db.items():
            if cve_id in seen:
                continue
            for cpe in entry.get("affected_cpe", []):
                cpe_l = cpe.lower()
                if product_l in cpe_l:
                    results.append(entry)
                    seen.add(cve_id)
                    break

    # Sort by CVSS v3 score descending, fallback to v2
    results.sort(
        key=lambda x: (x.get("cvss_v3_score") or x.get("cvss_v2_score") or 0),
        reverse=True,
    )
    return results


def lookup_cpe(cpe_string: str) -> list:
    """CPE-based lookup. Returns list of matching CVE dicts."""
    _load_caches()
    cpe_l = cpe_string.lower()
    results = []
    for cve_id, entry in _nvd_cache.items():
        for cpe in entry.get("affected_cpe", []):
            if cpe.lower() == cpe_l or cpe_string in cpe:
                results.append(entry)
                break
    results.sort(
        key=lambda x: (x.get("cvss_v3_score") or x.get("cvss_v2_score") or 0),
        reverse=True,
    )
    return results


def is_kev(cve_id: str) -> bool:
    """Return True if cve_id is in the CISA Known Exploited Vulnerabilities catalog."""
    _load_caches()
    return cve_id in _kev_cache


def get_kev_entry(cve_id: str) -> Optional[dict]:
    """Return KEV entry dict for a CVE ID, or None."""
    _load_caches()
    return _kev_cache.get(cve_id)


def get_cvss_score(cve_id: str) -> Optional[float]:
    """Return CVSS v3 score, falling back to v2. Returns None if not found."""
    _load_caches()
    entry = _nvd_cache.get(cve_id) or _fallback_db.get(cve_id)
    if not entry:
        return None
    return entry.get("cvss_v3_score") or entry.get("cvss_v2_score")


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
    _load_caches()
    stats = _load_stats()
    nvd_last = stats.get("nvd_last_updated")
    last_updated_ts = None
    if nvd_last:
        try:
            last_updated_ts = datetime.fromisoformat(nvd_last).timestamp()
        except Exception:
            pass
    stale = is_db_stale()
    return {
        # Keys used by update-vuln-db.py _print_stats()
        "cve_count": len(_nvd_cache),
        "kev_count": len(_kev_cache),
        "osv_count": len(_osv_cache),
        "last_updated": last_updated_ts,
        "stale": stale,
        "kev_last_modified": stats.get("kev_last_updated", ""),
        "db_path": str(VULN_DB_DIR),
        # Full detail keys
        "nvd_cve_count": len(_nvd_cache),
        "kev_cve_count": len(_kev_cache),
        "osv_entry_count": len(_osv_cache),
        "fallback_entry_count": len(_fallback_db),
        "nvd_last_updated": stats.get("nvd_last_updated", "never"),
        "kev_last_updated": stats.get("kev_last_updated", "never"),
        "osv_last_updated": stats.get("osv_last_updated", "never"),
        "nvd_cache_path": str(NVD_CACHE_PATH),
        "kev_cache_path": str(KEV_CACHE_PATH),
    }


def is_db_stale(max_age_days: int = 7) -> bool:
    """Return True if NVD cache is older than max_age_days or missing."""
    stats = _load_stats()
    last_updated = stats.get("nvd_last_updated")
    if not last_updated:
        return True
    try:
        last_dt = datetime.fromisoformat(last_updated).replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - last_dt).days >= max_age_days
    except Exception:
        return True
