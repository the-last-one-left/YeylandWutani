"""
Tests for lib/vuln_db.py

Covers: is_kev, get_cvss_score, format_cvss_severity, lookup_cves,
        get_db_stats, is_db_stale.
All external API calls (NVD, KEV, OSV) are mocked.
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Add lib/ to path ──────────────────────────────────────────────────────
_TEST_DIR = Path(__file__).resolve().parent
_LIB_DIR  = _TEST_DIR.parent / "lib"
sys.path.insert(0, str(_LIB_DIR))

import vuln_db


# ── Helpers ───────────────────────────────────────────────────────────────

def _make_nvd_entry(cve_id: str, score: float, severity: str, vendor: str,
                    product: str) -> dict:
    return {
        "cve_id":          cve_id,
        "description":     f"Test CVE {cve_id}",
        "cvss_v3_score":   score,
        "cvss_v3_severity": severity,
        "cvss_v2_score":   None,
        "affected_cpe":    [f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"],
        "published":       "2023-01-01",
        "last_modified":   "2023-06-01",
        "references":      [],
    }


def _make_kev_entry(cve_id: str) -> dict:
    return {
        "cve_id":           cve_id,
        "product":          "TestProduct",
        "vendor":           "TestVendor",
        "short_description": f"Test KEV {cve_id}",
        "required_action":  "Apply patch immediately.",
        "due_date":         "2023-12-31",
        "date_added":       "2023-01-01",
    }


class TestVulnDb(unittest.TestCase):

    def setUp(self):
        """Reset module-level caches before every test."""
        vuln_db._nvd_cache    = {}
        vuln_db._kev_cache    = {}
        vuln_db._osv_cache    = {}
        vuln_db._fallback_db  = {}
        vuln_db._caches_loaded = False

    # ── test_is_kev_true ─────────────────────────────────────────────────

    def test_is_kev_true(self):
        """A CVE ID present in the KEV cache should return True."""
        vuln_db._kev_cache    = {"CVE-2021-44228": _make_kev_entry("CVE-2021-44228")}
        vuln_db._caches_loaded = True
        self.assertTrue(vuln_db.is_kev("CVE-2021-44228"))

    # ── test_is_kev_false ────────────────────────────────────────────────

    def test_is_kev_false(self):
        """A CVE ID not in the KEV cache should return False."""
        vuln_db._kev_cache    = {"CVE-2021-44228": _make_kev_entry("CVE-2021-44228")}
        vuln_db._caches_loaded = True
        self.assertFalse(vuln_db.is_kev("CVE-9999-99999"))

    # ── test_get_cvss_score ──────────────────────────────────────────────

    def test_get_cvss_score(self):
        """get_cvss_score should return a float for a known CVE."""
        vuln_db._nvd_cache    = {
            "CVE-2021-44228": _make_nvd_entry(
                "CVE-2021-44228", 10.0, "CRITICAL", "apache", "log4j"
            )
        }
        vuln_db._caches_loaded = True
        score = vuln_db.get_cvss_score("CVE-2021-44228")
        self.assertIsInstance(score, float)
        self.assertAlmostEqual(score, 10.0)

    def test_get_cvss_score_unknown_returns_none(self):
        """get_cvss_score should return None for an unknown CVE."""
        vuln_db._nvd_cache    = {}
        vuln_db._fallback_db  = {}
        vuln_db._caches_loaded = True
        self.assertIsNone(vuln_db.get_cvss_score("CVE-0000-00000"))

    # ── test_format_cvss_severity_critical ───────────────────────────────

    def test_format_cvss_severity_critical(self):
        """CVSS score 9.5 should map to CRITICAL."""
        self.assertEqual(vuln_db.format_cvss_severity(9.5), "CRITICAL")

    def test_format_cvss_severity_critical_exact(self):
        """CVSS score 9.0 should map to CRITICAL (boundary)."""
        self.assertEqual(vuln_db.format_cvss_severity(9.0), "CRITICAL")

    # ── test_format_cvss_severity_high ───────────────────────────────────

    def test_format_cvss_severity_high(self):
        """CVSS score 7.5 should map to HIGH."""
        self.assertEqual(vuln_db.format_cvss_severity(7.5), "HIGH")

    def test_format_cvss_severity_high_boundary(self):
        """CVSS score 7.0 should map to HIGH (boundary)."""
        self.assertEqual(vuln_db.format_cvss_severity(7.0), "HIGH")

    def test_format_cvss_severity_medium(self):
        """CVSS score 5.0 should map to MEDIUM."""
        self.assertEqual(vuln_db.format_cvss_severity(5.0), "MEDIUM")

    def test_format_cvss_severity_low(self):
        """CVSS score 2.0 should map to LOW."""
        self.assertEqual(vuln_db.format_cvss_severity(2.0), "LOW")

    def test_format_cvss_severity_none(self):
        """None CVSS score should map to INFO."""
        self.assertEqual(vuln_db.format_cvss_severity(None), "INFO")

    def test_format_cvss_severity_zero(self):
        """CVSS score 0 should map to INFO."""
        self.assertEqual(vuln_db.format_cvss_severity(0), "INFO")

    # ── test_lookup_cves_vendor_product ──────────────────────────────────

    def test_lookup_cves_vendor_product(self):
        """lookup_cves should return matching entries for a known vendor/product."""
        vuln_db._nvd_cache = {
            "CVE-2021-44228": _make_nvd_entry(
                "CVE-2021-44228", 10.0, "CRITICAL", "apache", "log4j"
            ),
            "CVE-2023-99999": _make_nvd_entry(
                "CVE-2023-99999", 5.0, "MEDIUM", "nginx", "nginx"
            ),
        }
        vuln_db._caches_loaded = True

        results = vuln_db.lookup_cves("apache", "log4j")
        cve_ids = [r["cve_id"] for r in results]
        self.assertIn("CVE-2021-44228", cve_ids)
        self.assertNotIn("CVE-2023-99999", cve_ids)

    def test_lookup_cves_empty_returns_empty(self):
        """lookup_cves with no matching entries should return empty list."""
        vuln_db._nvd_cache    = {}
        vuln_db._fallback_db  = {}
        vuln_db._caches_loaded = True
        results = vuln_db.lookup_cves("nonexistent_vendor", "nonexistent_product")
        self.assertEqual(results, [])

    def test_lookup_cves_sorted_by_cvss(self):
        """lookup_cves results should be sorted by CVSS descending."""
        vuln_db._nvd_cache = {
            "CVE-2023-0001": _make_nvd_entry("CVE-2023-0001", 5.0, "MEDIUM", "apache", "httpd"),
            "CVE-2023-0002": _make_nvd_entry("CVE-2023-0002", 9.8, "CRITICAL", "apache", "httpd"),
            "CVE-2023-0003": _make_nvd_entry("CVE-2023-0003", 7.5, "HIGH",   "apache", "httpd"),
        }
        vuln_db._caches_loaded = True
        results = vuln_db.lookup_cves("apache", "httpd")
        scores = [r["cvss_v3_score"] for r in results]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_lookup_cves_falls_back_to_fallback_db(self):
        """When NVD cache is empty, lookup should check fallback DB."""
        vuln_db._nvd_cache = {}
        vuln_db._fallback_db = {
            "CVE-2021-41773": {
                "cve_id": "CVE-2021-41773",
                "description": "Apache HTTP Server path traversal",
                "cvss_v3_score": 7.5,
                "cvss_v3_severity": "HIGH",
                "affected_cpe": ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
                "kev": True,
                "published": "2021-10-05",
                "fix_available": True,
            }
        }
        vuln_db._caches_loaded = True
        results = vuln_db.lookup_cves("apache", "http_server")
        self.assertTrue(len(results) >= 1)

    # ── test_get_db_stats_structure ──────────────────────────────────────

    def test_get_db_stats_structure(self):
        """get_db_stats should return a dict with the required keys."""
        vuln_db._nvd_cache    = {"CVE-2021-44228": {}}
        vuln_db._kev_cache    = {"CVE-2021-44228": {}}
        vuln_db._osv_cache    = {}
        vuln_db._fallback_db  = {}
        vuln_db._caches_loaded = True

        with patch.object(vuln_db, "_load_stats", return_value={
            "nvd_last_updated": "2024-01-01T00:00:00+00:00",
            "kev_last_updated": "2024-01-01T00:00:00+00:00",
        }):
            stats = vuln_db.get_db_stats()

        self.assertIn("nvd_cve_count",      stats)
        self.assertIn("kev_cve_count",      stats)
        self.assertIn("osv_entry_count",    stats)
        self.assertIn("nvd_last_updated",   stats)
        self.assertIn("kev_last_updated",   stats)
        self.assertIsInstance(stats["nvd_cve_count"], int)
        self.assertEqual(stats["nvd_cve_count"], 1)
        self.assertEqual(stats["kev_cve_count"], 1)

    # ── test_is_db_stale ─────────────────────────────────────────────────

    def test_is_db_stale_old_mtime(self):
        """is_db_stale should return True when last_updated is older than max_age_days."""
        old_date = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        with patch.object(vuln_db, "_load_stats",
                          return_value={"nvd_last_updated": old_date}):
            self.assertTrue(vuln_db.is_db_stale(max_age_days=7))

    def test_is_db_stale_fresh(self):
        """is_db_stale should return False when last_updated is recent."""
        fresh_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        with patch.object(vuln_db, "_load_stats",
                          return_value={"nvd_last_updated": fresh_date}):
            self.assertFalse(vuln_db.is_db_stale(max_age_days=7))

    def test_is_db_stale_missing_key(self):
        """is_db_stale should return True when nvd_last_updated is missing."""
        with patch.object(vuln_db, "_load_stats", return_value={}):
            self.assertTrue(vuln_db.is_db_stale())

    def test_is_db_stale_invalid_date(self):
        """is_db_stale should return True when nvd_last_updated is unparseable."""
        with patch.object(vuln_db, "_load_stats",
                          return_value={"nvd_last_updated": "not-a-date"}):
            self.assertTrue(vuln_db.is_db_stale())

    # ── NVD/KEV API mocking ───────────────────────────────────────────────

    @patch("urllib.request.urlopen")
    def test_update_kev_catalog_mocked(self, mock_urlopen):
        """update_kev_catalog should parse KEV JSON and populate _kev_cache."""
        fake_kev_payload = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "product": "Log4j2",
                    "vendorProject": "Apache",
                    "shortDescription": "Log4Shell RCE",
                    "requiredAction": "Apply patch.",
                    "dueDate": "2021-12-24",
                    "dateAdded": "2021-12-10",
                }
            ]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_kev_payload).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        with tempfile.TemporaryDirectory() as tmpdir:
            old_kev_path   = vuln_db.KEV_CACHE_PATH
            old_stats_path = vuln_db.DB_STATS_PATH
            old_db_dir     = vuln_db.VULN_DB_DIR
            try:
                vuln_db.VULN_DB_DIR    = Path(tmpdir)
                vuln_db.KEV_CACHE_PATH = Path(tmpdir) / "kev-catalog.json"
                vuln_db.DB_STATS_PATH  = Path(tmpdir) / "db-stats.json"

                count = vuln_db.update_kev_catalog()
                self.assertEqual(count, 1)
                self.assertTrue(vuln_db.is_kev("CVE-2021-44228"))
            finally:
                vuln_db.VULN_DB_DIR    = old_db_dir
                vuln_db.KEV_CACHE_PATH = old_kev_path
                vuln_db.DB_STATS_PATH  = old_stats_path


if __name__ == "__main__":
    unittest.main()
