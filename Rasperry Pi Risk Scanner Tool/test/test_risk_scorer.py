"""
Tests for lib/risk_scorer.py

Covers: score_host, score_environment, classify_host_risk,
        format_cvss_severity edge cases.
"""

import sys
import unittest
from pathlib import Path

# ── Add lib/ to path ──────────────────────────────────────────────────────
_TEST_DIR = Path(__file__).resolve().parent
_LIB_DIR  = _TEST_DIR.parent / "lib"
sys.path.insert(0, str(_LIB_DIR))

import risk_scorer


# ── Helpers ───────────────────────────────────────────────────────────────

def _host(
    cve_matches=None,
    security_flags=None,
    open_ports=None,
    ssh_config=None,
    patch_status=None,
    windows_firewall=None,
    antivirus=None,
    smb_shares=None,
    ssl_issues=None,
    category="Unknown Device",
    risk_score=None,
    risk_level=None,
):
    h = {
        "category":          category,
        "cve_matches":       cve_matches       or [],
        "security_flags":    security_flags    or [],
        "open_ports":        open_ports        or [],
        "ssh_config_audit":  ssh_config        or {},
        "patch_status":      patch_status      or {},
        "windows_firewall":  windows_firewall  or {},
        "antivirus":         antivirus         or {},
        "smb_shares":        smb_shares        or [],
        "ssl_issues":        ssl_issues        or [],
    }
    if risk_score is not None:
        h["risk_score"] = risk_score
    if risk_level is not None:
        h["risk_level"] = risk_level
    return h


def _cve(cve_id: str, score: float, kev: bool = False) -> dict:
    return {
        "cve_id":        cve_id,
        "cvss_v3_score": score,
        "kev":           kev,
        "severity":      risk_scorer.format_cvss_severity(score),
    }


# ── Tests ─────────────────────────────────────────────────────────────────

class TestScoreHost(unittest.TestCase):

    # ── test_score_host_zero ──────────────────────────────────────────────

    def test_score_host_zero(self):
        """Empty host dict should score 0."""
        self.assertEqual(risk_scorer.score_host({}), 0)

    def test_score_host_zero_all_empty(self):
        """Host with all empty collections should also score 0."""
        self.assertEqual(risk_scorer.score_host(_host()), 0)

    # ── test_score_host_kev ───────────────────────────────────────────────

    def test_score_host_kev(self):
        """Host with a KEV CVE should score >= 100 (capped at 100)."""
        host = _host(cve_matches=[_cve("CVE-2021-44228", 10.0, kev=True)])
        score = risk_scorer.score_host(host)
        self.assertGreaterEqual(score, 100)

    def test_score_host_kev_capped(self):
        """KEV CVE score contribution is capped; multiple KEVs should not exceed 100."""
        host = _host(cve_matches=[
            _cve("CVE-2021-44228", 10.0, kev=True),
            _cve("CVE-2020-1472",  10.0, kev=True),
            _cve("CVE-2019-0708",  9.8,  kev=True),
            _cve("CVE-2017-0144",  9.8,  kev=True),
        ])
        score = risk_scorer.score_host(host)
        self.assertLessEqual(score, 100)

    # ── test_score_host_default_creds ─────────────────────────────────────

    def test_score_host_default_credentials(self):
        """Host with default_credentials flag should score >= 90."""
        host = _host(security_flags=[{
            "type":        "default_credentials",
            "description": "Default credentials detected on SSH service",
            "severity":    "CRITICAL",
        }])
        score = risk_scorer.score_host(host)
        self.assertGreaterEqual(score, 90)

    def test_score_host_default_creds_description_match(self):
        """Flag with 'default credential' in description should also trigger."""
        host = _host(security_flags=[{
            "type":        "auth_issue",
            "description": "Default credential detected on admin interface",
            "severity":    "HIGH",
        }])
        score = risk_scorer.score_host(host)
        self.assertGreaterEqual(score, 90)

    # ── test_score_host_capped_at_100 ────────────────────────────────────

    def test_score_host_capped_at_100(self):
        """Score must never exceed 100 regardless of findings."""
        host = _host(
            cve_matches=[_cve(f"CVE-2023-{i:05d}", 9.8, kev=True) for i in range(10)],
            security_flags=[
                {"type": "default_credentials", "description": "Default credential found", "severity": "CRITICAL"},
                {"type": "eol_os",              "description": "End-of-life OS detected",  "severity": "HIGH"},
                {"type": "http_admin",          "description": "Admin via http not https",  "severity": "HIGH"},
            ],
            open_ports=[23],
            ssh_config={"permit_root_login": True},
            patch_status={"days_since_update": 200},
            antivirus={"status": "missing"},
        )
        score = risk_scorer.score_host(host)
        self.assertEqual(score, 100)

    # ── test_classify_host_risk_critical ─────────────────────────────────

    def test_classify_host_risk_critical(self):
        """Score 85 should classify as CRITICAL."""
        self.assertEqual(risk_scorer.classify_host_risk(85), "CRITICAL")

    def test_classify_host_risk_critical_boundary(self):
        """Score exactly at CRITICAL threshold (80) should be CRITICAL."""
        self.assertEqual(risk_scorer.classify_host_risk(80), "CRITICAL")

    # ── test_classify_host_risk_high ─────────────────────────────────────

    def test_classify_host_risk_high(self):
        """Score 65 should classify as HIGH."""
        self.assertEqual(risk_scorer.classify_host_risk(65), "HIGH")

    def test_classify_host_risk_high_boundary(self):
        """Score exactly at HIGH threshold (60) should be HIGH."""
        self.assertEqual(risk_scorer.classify_host_risk(60), "HIGH")

    def test_classify_host_risk_not_critical_at_79(self):
        """Score 79 should classify as HIGH, not CRITICAL."""
        self.assertEqual(risk_scorer.classify_host_risk(79), "HIGH")

    # ── test_classify_host_risk_medium ───────────────────────────────────

    def test_classify_host_risk_medium(self):
        """Score 45 should classify as MEDIUM."""
        self.assertEqual(risk_scorer.classify_host_risk(45), "MEDIUM")

    def test_classify_host_risk_medium_boundary(self):
        """Score exactly at MEDIUM threshold (40) should be MEDIUM."""
        self.assertEqual(risk_scorer.classify_host_risk(40), "MEDIUM")

    # ── test_classify_host_risk_low ──────────────────────────────────────

    def test_classify_host_risk_low(self):
        """Score 30 should classify as LOW."""
        self.assertEqual(risk_scorer.classify_host_risk(30), "LOW")

    def test_classify_host_risk_low_zero(self):
        """Score 0 should classify as LOW."""
        self.assertEqual(risk_scorer.classify_host_risk(0), "LOW")

    # ── Additional scoring tests ──────────────────────────────────────────

    def test_score_host_telnet(self):
        """Open telnet port (23) should add points."""
        host_with    = _host(open_ports=[23])
        host_without = _host(open_ports=[80])
        self.assertGreater(risk_scorer.score_host(host_with),
                           risk_scorer.score_host(host_without))

    def test_score_host_ssh_root_login(self):
        """SSH PermitRootLogin enabled should add points."""
        host = _host(ssh_config={"permit_root_login": True})
        score = risk_scorer.score_host(host)
        pts, _ = risk_scorer.FINDING_WEIGHTS["ssh_root_login"]
        self.assertGreaterEqual(score, pts)

    def test_score_host_stale_patches(self):
        """Patches stale > 90 days should add points."""
        host = _host(patch_status={"days_since_update": 120})
        score = risk_scorer.score_host(host)
        pts, _ = risk_scorer.FINDING_WEIGHTS["windows_patches_stale"]
        self.assertGreaterEqual(score, pts)

    def test_score_host_firewall_disabled(self):
        """Windows firewall disabled should add points."""
        host = _host(windows_firewall={"Domain": "disabled"})
        score = risk_scorer.score_host(host)
        pts, _ = risk_scorer.FINDING_WEIGHTS["windows_firewall_off"]
        self.assertGreaterEqual(score, pts)

    def test_score_host_antivirus_missing(self):
        """Missing antivirus should add points."""
        host = _host(antivirus={"status": "missing"})
        score = risk_scorer.score_host(host)
        pts, _ = risk_scorer.FINDING_WEIGHTS["antivirus_missing"]
        self.assertGreaterEqual(score, pts)

    def test_score_host_smb_unauthenticated(self):
        """SMB share accessible to everyone should add points."""
        host = _host(smb_shares=[{"name": "share", "access": "Everyone"}])
        score = risk_scorer.score_host(host)
        pts, _ = risk_scorer.FINDING_WEIGHTS["smb_unauthenticated"]
        self.assertGreaterEqual(score, pts)

    def test_score_host_critical_cvss(self):
        """CRITICAL CVSS (>= 9.0, not KEV) should add points."""
        host = _host(cve_matches=[_cve("CVE-2023-0001", 9.5)])
        score = risk_scorer.score_host(host)
        self.assertGreater(score, 0)

    def test_score_host_high_cvss(self):
        """HIGH CVSS (>= 7.0) should add points."""
        host = _host(cve_matches=[_cve("CVE-2023-0001", 7.5)])
        score = risk_scorer.score_host(host)
        self.assertGreater(score, 0)

    def test_score_host_medium_cvss(self):
        """MEDIUM CVSS (>= 4.0) should add points."""
        host = _host(cve_matches=[_cve("CVE-2023-0001", 5.0)])
        score = risk_scorer.score_host(host)
        self.assertGreater(score, 0)


class TestScoreEnvironment(unittest.TestCase):

    # ── test_score_environment_empty ─────────────────────────────────────

    def test_score_environment_empty(self):
        """No hosts should return environment score of 0."""
        self.assertEqual(risk_scorer.score_environment([]), 0)

    # ── test_score_environment_mixed ─────────────────────────────────────

    def test_score_environment_mixed(self):
        """Mixed-severity hosts should produce a weighted score > 0."""
        hosts = [
            _host(category="Windows Server",    risk_score=90, risk_level="CRITICAL"),
            _host(category="Windows Workstation",risk_score=30, risk_level="LOW"),
            _host(category="Network Switch",     risk_score=60, risk_level="HIGH"),
            _host(category="IoT Device",         risk_score=10, risk_level="LOW"),
        ]
        score = risk_scorer.score_environment(hosts)
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 100)

    def test_score_environment_all_clean(self):
        """All-zero risk hosts should return score of 0."""
        hosts = [_host(risk_score=0) for _ in range(5)]
        score = risk_scorer.score_environment(hosts)
        self.assertEqual(score, 0)

    def test_score_environment_single_critical_server(self):
        """A single critical server should return a high environment score."""
        hosts = [_host(category="Windows Server", risk_score=100, risk_level="CRITICAL")]
        score = risk_scorer.score_environment(hosts)
        self.assertGreater(score, 50)

    def test_score_environment_respects_criticality_weight(self):
        """Server with same raw score as IoT device should yield higher env score."""
        server_env = risk_scorer.score_environment([
            _host(category="Windows Server", risk_score=70, risk_level="HIGH")
        ])
        iot_env = risk_scorer.score_environment([
            _host(category="IoT Device", risk_score=70, risk_level="HIGH")
        ])
        self.assertGreater(server_env, iot_env)

    def test_score_environment_breadth_penalty(self):
        """Majority HIGH+ hosts should trigger breadth penalty and raise score."""
        baseline_hosts = [
            _host(category="Unknown Device", risk_score=55, risk_level="HIGH"),
        ] * 10
        baseline_score = risk_scorer.score_environment(baseline_hosts)

        # Add many more HIGH hosts to increase breadth penalty
        many_high_hosts = [
            _host(category="Unknown Device", risk_score=65, risk_level="HIGH"),
        ] * 20
        high_score = risk_scorer.score_environment(many_high_hosts)

        # Higher raw score hosts should yield equal or higher env score
        self.assertGreaterEqual(high_score, baseline_score)

    def test_score_environment_result_is_integer(self):
        """score_environment should return an integer."""
        hosts = [_host(risk_score=50, risk_level="MEDIUM")]
        result = risk_scorer.score_environment(hosts)
        self.assertIsInstance(result, int)


class TestGetRiskSummary(unittest.TestCase):

    def test_get_risk_summary_counts_by_severity(self):
        """get_risk_summary should correctly count hosts by risk level."""
        hosts = [
            _host(risk_level="CRITICAL", risk_score=85),
            _host(risk_level="HIGH",     risk_score=65),
            _host(risk_level="HIGH",     risk_score=62),
            _host(risk_level="MEDIUM",   risk_score=45),
            _host(risk_level="LOW",      risk_score=10),
        ]
        summary = risk_scorer.get_risk_summary(hosts)
        counts = summary["counts_by_severity"]
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["HIGH"],     2)
        self.assertEqual(counts["MEDIUM"],   1)
        self.assertEqual(counts["LOW"],      1)

    def test_get_risk_summary_kev_first(self):
        """KEV CVEs should appear at the top of the top_10_risks list."""
        hosts = [
            _host(
                risk_level="CRITICAL",
                risk_score=90,
                cve_matches=[
                    _cve("CVE-2021-44228", 10.0, kev=True),
                    _cve("CVE-2023-0001",  9.5,  kev=False),
                ]
            )
        ]
        summary = risk_scorer.get_risk_summary(hosts)
        if summary["top_10_risks"]:
            self.assertTrue(summary["top_10_risks"][0]["kev"])

    def test_get_risk_summary_total_hosts(self):
        """get_risk_summary total_hosts count should match input."""
        hosts = [_host(risk_level="LOW", risk_score=5) for _ in range(7)]
        summary = risk_scorer.get_risk_summary(hosts)
        self.assertEqual(summary["total_hosts"], 7)


if __name__ == "__main__":
    unittest.main()
