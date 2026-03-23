#!/usr/bin/env python3
"""
Plugin: CVE Correlation  (Phase 7)
Cross-reference discovered packages/software with NVD, CISA KEV, and OSV
vulnerability databases to produce per-host CVE findings.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_CVE

log = logging.getLogger("plugin.cve_correlation")

# Data-file paths (relative to data_dir)
_NVD_CACHE   = "nvd_cache.json"
_KEV_CACHE   = "kev_cache.json"
_OSV_CACHE   = "osv_cache.json"

# CVSS severity thresholds
_SEVERITY = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0,  8.9),
    "MEDIUM":   (4.0,  6.9),
    "LOW":      (0.1,  3.9),
    "NONE":     (0.0,  0.0),
}


def _cvss_to_severity(score: float) -> str:
    for sev, (lo, hi) in _SEVERITY.items():
        if lo <= score <= hi:
            return sev
    return "NONE"


# ── Local cache helpers ───────────────────────────────────────────────────

def _load_json_cache(data_dir: str, filename: str) -> dict | list:
    path = os.path.join(data_dir, filename)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        log.warning(f"Failed to load cache {filename}: {exc}")
        return {}


# ── KEV lookup ───────────────────────────────────────────────────────────

def _build_kev_set(data_dir: str) -> set[str]:
    """Return a set of CVE IDs that appear in the CISA KEV catalogue."""
    raw = _load_json_cache(data_dir, _KEV_CACHE)
    if isinstance(raw, dict):
        vulns = raw.get("vulnerabilities", [])
    elif isinstance(raw, list):
        vulns = raw
    else:
        vulns = []
    return {v.get("cveID", "") for v in vulns if v.get("cveID")}


# ── NVD package-name lookup ──────────────────────────────────────────────

def _build_nvd_index(data_dir: str) -> dict[str, list[dict]]:
    """
    Build a {pkg_name_lower: [cve_dict, ...]} index from the NVD cache.
    NVD cache is expected to be a list of CVE items (NVD 2.0 format).
    """
    raw = _load_json_cache(data_dir, _NVD_CACHE)
    items: list = []
    if isinstance(raw, dict):
        items = raw.get("vulnerabilities", raw.get("CVE_Items", []))
    elif isinstance(raw, list):
        items = raw

    index: dict[str, list[dict]] = {}
    for item in items:
        # NVD 2.0
        cve_data = item.get("cve", item)
        cve_id   = cve_data.get("id") or cve_data.get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue

        # CVSS score
        metrics  = cve_data.get("metrics", {})
        cvss3    = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        cvss2    = metrics.get("cvssMetricV2") or []
        score    = 0.0
        if cvss3:
            score = float(cvss3[0].get("cvssData", {}).get("baseScore", 0))
        elif cvss2:
            score = float(cvss2[0].get("cvssData", {}).get("baseScore", 0))

        # Description
        descs = cve_data.get("descriptions", cve_data.get("description", {}).get("description_data", []))
        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        # Affected CPE products
        configs  = cve_data.get("configurations", [])
        products: set[str] = set()
        for cfg in (configs if isinstance(configs, list) else []):
            for node in cfg.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    uri = cpe.get("criteria", "")
                    parts = uri.split(":")
                    if len(parts) > 4:
                        products.add(parts[4].lower())  # product field

        cve_dict = {
            "cve_id":   cve_id,
            "score":    score,
            "severity": _cvss_to_severity(score),
            "description": desc[:500],
            "kev":      False,  # filled in later
            "products": list(products),
        }
        for prod in products:
            index.setdefault(prod, []).append(cve_dict)

    log.info(f"NVD index built: {len(index)} product entries, {len(items)} CVEs total.")
    return index


# ── Per-host correlation ────────────────────────────────────────────────────

def _correlate_host(host: dict, nvd_index: dict, kev_set: set) -> list[dict]:
    """
    Return a list of matched CVE dicts for this host by checking
    SSH packages, WMI installed_software, and SNMP software lists.
    """
    # Collect all package/software names from the host
    pkg_names: set[str] = set()

    for pkg in host.get("ssh", {}).get("packages", []):
        name = pkg.get("name", "").lower().strip()
        if name:
            pkg_names.add(name)

    for sw in host.get("wmi", {}).get("installed_software", []):
        name = (sw.get("DisplayName") or "").lower().strip()
        if name:
            # Normalise: take first word of display name
            pkg_names.add(name.split()[0] if name.split() else name)

    for sw in host.get("snmp", {}).get("software", []):
        name = sw.lower().strip()
        if name:
            pkg_names.add(name.split()[0] if name.split() else name)

    if not pkg_names:
        return []

    cve_map: dict[str, dict] = {}
    for pkg in pkg_names:
        for cve in nvd_index.get(pkg, []):
            cid = cve["cve_id"]
            if cid not in cve_map:
                entry = dict(cve)
                entry["kev"] = cid in kev_set
                entry["matched_package"] = pkg
                cve_map[cid] = entry

    # Sort by score descending
    return sorted(cve_map.values(), key=lambda c: c["score"], reverse=True)


class CVECorrelationPlugin(ScanPlugin):
    plugin_id   = "cve_correlation"
    name        = "CVE Correlation"
    category    = CAT_CVE
    phase       = 7
    description = (
        "Match discovered packages and software against NVD / CISA KEV / OSV "
        "databases to produce per-host CVE findings with CVSS scores."
    )
    version     = "1.0.0"
    author      = "AWN"
    requires    = ["host_discovery"]

    def run(self, ctx: PluginContext) -> None:
        if not ctx.hosts:
            log.warning("No hosts — skipping CVE correlation.")
            return

        log.info("Building NVD index and KEV set from local cache...")
        t0        = time.monotonic()
        nvd_index = _build_nvd_index(ctx.data_dir)
        kev_set   = _build_kev_set(ctx.data_dir)
        log.info(f"Cache loaded in {time.monotonic()-t0:.2f}s | KEV entries: {len(kev_set)}")

        if not nvd_index and not kev_set:
            log.warning(
                "NVD/KEV caches are empty. Run bin/update-vuln-db.py to download "
                "vulnerability databases before scanning."
            )

        total_cves = 0
        kev_hits   = 0
        critical   = 0

        for host in ctx.hosts:
            cves = _correlate_host(host, nvd_index, kev_set)
            host["cves"] = cves
            total_cves += len(cves)
            kev_hits   += sum(1 for c in cves if c.get("kev"))
            critical   += sum(1 for c in cves if c.get("severity") == "CRITICAL")

        ctx.scan_results["vuln_db_stats"] = {
            "nvd_products_indexed": len(nvd_index),
            "kev_entries":          len(kev_set),
            "total_cves_matched":   total_cves,
            "kev_hits":             kev_hits,
            "critical_findings":    critical,
        }

        ctx.sync_hosts()
        log.info(
            f"CVE correlation complete: {total_cves} total CVE matches, "
            f"{kev_hits} KEV hits, {critical} CRITICAL findings."
        )
