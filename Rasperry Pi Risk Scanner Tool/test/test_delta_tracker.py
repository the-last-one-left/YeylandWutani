"""
Tests for lib/delta_tracker.py

Covers: compute_delta, format_delta_summary, _extract_host_findings.
No filesystem I/O is required — all data is passed in-memory.
"""

import sys
import unittest
from pathlib import Path

# ── Add lib/ to path ──────────────────────────────────────────────────────
_TEST_DIR = Path(__file__).resolve().parent
_LIB_DIR  = _TEST_DIR.parent / "lib"
sys.path.insert(0, str(_LIB_DIR))

import delta_tracker


# ── Helpers ───────────────────────────────────────────────────────────────

def _scan(hosts: list, env_score: int = 50) -> dict:
    """Build a minimal scan_results dict."""
    return {
        "hosts": hosts,
        "risk": {"environment_score": env_score},
    }


def _host(
    ip: str,
    hostname: str = "",
    risk_score: int = 0,
    cve_matches: list = None,
    security_flags: list = None,
    ssh_config: dict = None,
    patch_status: dict = None,
    windows_firewall: dict = None,
    antivirus: dict = None,
) -> dict:
    return {
        "ip":               ip,
        "hostname":         hostname,
        "risk_score":       risk_score,
        "cve_matches":      cve_matches       or [],
        "security_flags":   security_flags    or [],
        "ssh_config_audit": ssh_config        or {},
        "patch_status":     patch_status      or {},
        "windows_firewall": windows_firewall  or {},
        "antivirus":        antivirus         or {},
    }


def _cve(cve_id: str, kev: bool = False) -> dict:
    return {
        "cve_id":          cve_id,
        "cvss_v3_score":   9.8 if kev else 5.0,
        "kev":             kev,
        "kev_required_action": "Patch immediately." if kev else "",
        "product":         "TestProduct",
    }


def _flag(type_: str, desc: str, severity: str = "HIGH") -> dict:
    return {
        "type":        type_,
        "description": desc,
        "severity":    severity,
    }


# ── Tests ─────────────────────────────────────────────────────────────────

class TestComputeDelta(unittest.TestCase):

    # ── test_compute_delta_new_host ───────────────────────────────────────

    def test_compute_delta_new_host(self):
        """A host in current scan but not in previous should appear in new_hosts."""
        prev = _scan([_host("192.168.1.1")])
        curr = _scan([_host("192.168.1.1"), _host("192.168.1.50")])
        delta = delta_tracker.compute_delta(curr, prev)
        self.assertIn("192.168.1.50", delta["new_hosts"])
        self.assertNotIn("192.168.1.50", delta["removed_hosts"])

    def test_compute_delta_new_host_empty_previous(self):
        """With no previous scan, compute_delta returns has_previous=False."""
        curr = _scan([_host("10.0.0.1")])
        delta = delta_tracker.compute_delta(curr, None)
        self.assertFalse(delta["has_previous"])
        self.assertEqual(delta["new_hosts"], [])

    # ── test_compute_delta_removed_host ──────────────────────────────────

    def test_compute_delta_removed_host(self):
        """A host in previous but not current should appear in removed_hosts."""
        prev = _scan([_host("192.168.1.1"), _host("192.168.1.99")])
        curr = _scan([_host("192.168.1.1")])
        delta = delta_tracker.compute_delta(curr, prev)
        self.assertIn("192.168.1.99", delta["removed_hosts"])
        self.assertNotIn("192.168.1.99", delta["new_hosts"])

    def test_compute_delta_removed_host_findings_in_resolved(self):
        """Findings on a removed host should appear in resolved_findings."""
        removed = _host(
            "192.168.1.99",
            cve_matches=[_cve("CVE-2021-44228", kev=True)]
        )
        prev  = _scan([removed])
        curr  = _scan([])
        delta = delta_tracker.compute_delta(curr, prev)
        self.assertIn("192.168.1.99", delta["resolved_findings"])

    # ── test_compute_delta_new_finding ───────────────────────────────────

    def test_compute_delta_new_finding(self):
        """A security flag present in current but not previous should be new."""
        prev_host = _host("10.0.0.5")
        curr_host = _host(
            "10.0.0.5",
            security_flags=[_flag("telnet_open", "Telnet port 23 is open")]
        )
        prev  = _scan([prev_host])
        curr  = _scan([curr_host])
        delta = delta_tracker.compute_delta(curr, prev)
        self.assertIn("10.0.0.5", delta["new_findings"])
        new_f = delta["new_findings"]["10.0.0.5"]
        self.assertTrue(any("Telnet" in f for f in new_f))

    def test_compute_delta_new_cve(self):
        """A CVE in current scan but absent from previous should be a new finding."""
        prev_host = _host("10.0.0.5")
        curr_host = _host("10.0.0.5", cve_matches=[_cve("CVE-2021-44228")])
        delta = delta_tracker.compute_delta(_scan([curr_host]), _scan([prev_host]))
        self.assertIn("10.0.0.5", delta["new_findings"])
        new_f = delta["new_findings"]["10.0.0.5"]
        self.assertTrue(any("CVE-2021-44228" in f for f in new_f))

    # ── test_compute_delta_resolved_finding ──────────────────────────────

    def test_compute_delta_resolved_finding(self):
        """A security flag in previous but not current should be resolved."""
        prev_host = _host(
            "10.0.0.5",
            security_flags=[_flag("telnet_open", "Telnet port 23 is open")]
        )
        curr_host = _host("10.0.0.5")  # flag gone
        delta = delta_tracker.compute_delta(
            _scan([curr_host]), _scan([prev_host])
        )
        self.assertIn("10.0.0.5", delta["resolved_findings"])
        resolved_f = delta["resolved_findings"]["10.0.0.5"]
        self.assertTrue(any("Telnet" in f for f in resolved_f))

    def test_compute_delta_resolved_cve(self):
        """A CVE patched between scans should appear in resolved_findings."""
        prev_host = _host("10.0.0.5", cve_matches=[_cve("CVE-2021-44228")])
        curr_host = _host("10.0.0.5")  # CVE patched
        delta = delta_tracker.compute_delta(
            _scan([curr_host]), _scan([prev_host])
        )
        self.assertIn("10.0.0.5", delta["resolved_findings"])

    # ── test_compute_delta_recurring ─────────────────────────────────────

    def test_compute_delta_recurring(self):
        """A finding present in both scans should appear in recurring_findings."""
        flag = _flag("ssh_root", "SSH PermitRootLogin is enabled")
        prev_host = _host("10.0.0.5", security_flags=[flag])
        curr_host = _host("10.0.0.5", security_flags=[flag])
        delta = delta_tracker.compute_delta(
            _scan([curr_host]), _scan([prev_host])
        )
        self.assertIn("10.0.0.5", delta["recurring_findings"])

    def test_compute_delta_recurring_cve(self):
        """A CVE present in both scans is a recurring finding."""
        cve = _cve("CVE-2020-1472")
        prev_host = _host("10.0.0.5", cve_matches=[cve])
        curr_host = _host("10.0.0.5", cve_matches=[cve])
        delta = delta_tracker.compute_delta(
            _scan([curr_host]), _scan([prev_host])
        )
        self.assertIn("10.0.0.5", delta["recurring_findings"])

    # ── test_compute_delta_risk_score_delta ──────────────────────────────

    def test_compute_delta_risk_score_delta_positive(self):
        """risk_score_delta should be positive when environment score increased."""
        prev = _scan([], env_score=40)
        curr = _scan([], env_score=70)
        delta = delta_tracker.compute_delta(curr, prev)
        self.assertEqual(delta["risk_score_delta"], 30)

    def test_compute_delta_risk_score_delta_negative(self):
        """risk_score_delta should be negative when environment score decreased."""
        prev = _scan([], env_score=80)
        curr = _scan([], env_score=50)
        delta = delta_tracker.compute_delta(curr, prev)
        self.assertEqual(delta["risk_score_delta"], -30)

    def test_compute_delta_risk_score_delta_zero(self):
        """risk_score_delta should be 0 when environment score is unchanged."""
        prev = _scan([], env_score=55)
        curr = _scan([], env_score=55)
        delta = delta_tracker.compute_delta(curr, prev)
        self.assertEqual(delta["risk_score_delta"], 0)

    # ── test_compute_delta_new_kev ────────────────────────────────────────

    def test_compute_delta_new_kev_cves(self):
        """New KEV CVE match not in previous scan should appear in new_kev_cves."""
        prev_host = _host("10.0.0.5")
        curr_host = _host("10.0.0.5", cve_matches=[_cve("CVE-2021-44228", kev=True)])
        delta = delta_tracker.compute_delta(
            _scan([curr_host]), _scan([prev_host])
        )
        kev_ids = [k["cve_id"] for k in delta["new_kev_cves"]]
        self.assertIn("CVE-2021-44228", kev_ids)

    def test_compute_delta_no_new_kev_when_already_present(self):
        """A KEV CVE present in both scans should NOT appear in new_kev_cves."""
        kev_cve = _cve("CVE-2021-44228", kev=True)
        prev_host = _host("10.0.0.5", cve_matches=[kev_cve])
        curr_host = _host("10.0.0.5", cve_matches=[kev_cve])
        delta = delta_tracker.compute_delta(
            _scan([curr_host]), _scan([prev_host])
        )
        self.assertEqual(len(delta["new_kev_cves"]), 0)

    # ── Misc ──────────────────────────────────────────────────────────────

    def test_compute_delta_has_previous_flag(self):
        """has_previous should be True when previous scan is provided."""
        curr = _scan([_host("10.0.0.1")])
        prev = _scan([_host("10.0.0.1")])
        delta = delta_tracker.compute_delta(curr, prev)
        self.assertTrue(delta["has_previous"])

    def test_compute_delta_no_previous_defaults(self):
        """With no previous scan, all findings lists should be empty."""
        curr  = _scan([_host("10.0.0.1")])
        delta = delta_tracker.compute_delta(curr, None)
        self.assertEqual(delta["new_hosts"],      [])
        self.assertEqual(delta["removed_hosts"],  [])
        self.assertEqual(delta["new_kev_cves"],   [])
        self.assertEqual(delta["risk_score_delta"], 0)


class TestFormatDeltaSummary(unittest.TestCase):

    # ── test_format_delta_summary ────────────────────────────────────────

    def test_format_delta_summary_no_previous(self):
        """Summary for first-scan delta should be a non-empty string."""
        delta  = delta_tracker.compute_delta(_scan([_host("10.0.0.1")]), None)
        result = delta_tracker.format_delta_summary(delta)
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_format_delta_summary_with_changes(self):
        """Summary with new findings should mention issues."""
        prev  = _scan([_host("10.0.0.1")])
        curr  = _scan([
            _host("10.0.0.1", security_flags=[_flag("telnet", "Telnet open")]),
            _host("10.0.0.99"),
        ])
        delta  = delta_tracker.compute_delta(curr, prev)
        result = delta_tracker.format_delta_summary(delta)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)
        # Should mention new issue or new host
        self.assertTrue(
            any(kw in result for kw in ("issue", "host", "finding", "KEV"))
        )

    def test_format_delta_summary_no_changes(self):
        """Summary with no changes should indicate no changes."""
        host  = _host("10.0.0.1")
        prev  = _scan([host])
        curr  = _scan([host])
        delta = delta_tracker.compute_delta(curr, prev)
        result = delta_tracker.format_delta_summary(delta)
        self.assertIn("No changes", result)

    def test_format_delta_summary_kev_mentioned(self):
        """Summary should mention KEV when new KEV CVEs are present."""
        prev_host = _host("10.0.0.1")
        curr_host = _host("10.0.0.1", cve_matches=[_cve("CVE-2021-44228", kev=True)])
        delta = delta_tracker.compute_delta(
            _scan([curr_host]), _scan([prev_host])
        )
        result = delta_tracker.format_delta_summary(delta)
        self.assertIn("KEV", result)

    def test_format_delta_summary_risk_delta_shown(self):
        """Summary should show risk score change when delta >= 5."""
        prev  = _scan([], env_score=30)
        curr  = _scan([], env_score=60)
        delta = delta_tracker.compute_delta(curr, prev)
        result = delta_tracker.format_delta_summary(delta)
        # Risk arrow should appear
        self.assertTrue("risk" in result or "↑" in result or "↓" in result)


class TestExtractHostFindings(unittest.TestCase):

    def test_ssh_permit_root_login(self):
        """permit_root_login=True should add SSH:permit_root_login to findings."""
        host = _host("10.0.0.1", ssh_config={"permit_root_login": True})
        findings = delta_tracker._extract_host_findings(host)
        self.assertIn("SSH:permit_root_login", findings)

    def test_ssh_password_auth(self):
        """password_auth=True should add SSH:password_auth_enabled."""
        host = _host("10.0.0.1", ssh_config={"password_auth": True})
        findings = delta_tracker._extract_host_findings(host)
        self.assertIn("SSH:password_auth_enabled", findings)

    def test_patch_stale_90d(self):
        """days_since_update > 90 should add PATCH:stale_90d."""
        host = _host("10.0.0.1", patch_status={"days_since_update": 120})
        findings = delta_tracker._extract_host_findings(host)
        self.assertIn("PATCH:stale_90d", findings)

    def test_patch_not_stale(self):
        """days_since_update <= 90 should not add PATCH:stale_90d."""
        host = _host("10.0.0.1", patch_status={"days_since_update": 45})
        findings = delta_tracker._extract_host_findings(host)
        self.assertNotIn("PATCH:stale_90d", findings)

    def test_cve_findings_added(self):
        """CVE matches should be included as CVE:<id> findings."""
        host = _host("10.0.0.1", cve_matches=[_cve("CVE-2021-44228")])
        findings = delta_tracker._extract_host_findings(host)
        self.assertIn("CVE:CVE-2021-44228", findings)

    def test_empty_host_returns_empty_set(self):
        """Empty host dict should yield an empty findings set."""
        findings = delta_tracker._extract_host_findings({})
        self.assertEqual(len(findings), 0)

    def test_firewall_disabled(self):
        """A disabled firewall profile should be recorded as FIREWALL:*_disabled."""
        host = _host("10.0.0.1", windows_firewall={"Domain": "disabled"})
        findings = delta_tracker._extract_host_findings(host)
        self.assertTrue(any("FIREWALL:" in f for f in findings))

    def test_av_missing(self):
        """AV status missing should add AV:missing."""
        host = _host("10.0.0.1", antivirus={"status": "missing"})
        findings = delta_tracker._extract_host_findings(host)
        self.assertIn("AV:missing", findings)


if __name__ == "__main__":
    unittest.main()
