"""
Tests for lib/hatz_ai.py

Covers: get_risk_insights, get_host_narrative, _build_risk_summary_text.
All HTTP calls are mocked — no network access required.
"""

import json
import sys
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Add lib/ to path ──────────────────────────────────────────────────────
_TEST_DIR = Path(__file__).resolve().parent
_LIB_DIR  = _TEST_DIR.parent / "lib"
sys.path.insert(0, str(_LIB_DIR))

import hatz_ai


# ── Helpers ───────────────────────────────────────────────────────────────

_MOCK_API_KEY = "test-api-key-12345"

_MOCK_INSIGHTS_TEXT = (
    "## Executive Summary\nSecurity posture is critical.\n\n"
    "## Critical Actions (This Week)\n1. Patch CVE-2021-44228 immediately.\n"
)

_MOCK_HOST_NARRATIVE_TEXT = (
    "Host 192.168.1.10 runs Windows Server 2019 and carries CVE-2021-44228 "
    "(KEV). Patch Log4j2 immediately."
)


def _mock_http_200(body_text: str):
    """Return a mock urllib response that yields an OpenAI-format JSON response."""
    response_payload = {
        "choices": [{"message": {"content": body_text}}]
    }
    raw = json.dumps(response_payload).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = raw
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _mock_http_error(code: int):
    """Return a mock that raises urllib.error.HTTPError with given code."""
    import urllib.error
    err = urllib.error.HTTPError(
        url="https://ai.hatz.ai/v1/chat/completions",
        code=code,
        msg=f"HTTP Error {code}",
        hdrs=MagicMock(),
        fp=BytesIO(b"Internal Server Error"),
    )
    return err


def _sample_scan_results(with_kev: bool = False) -> dict:
    cve_list = []
    if with_kev:
        cve_list = [{
            "cve_id":     "CVE-2021-44228",
            "cvss_score": 10.0,
            "severity":   "CRITICAL",
            "kev":        True,
            "description": "Apache Log4j2 JNDI injection (Log4Shell)",
        }]
    return {
        "hosts": [
            {
                "ip":           "192.168.1.10",
                "hostname":     "WIN-SERVER-01",
                "risk_level":   "CRITICAL",
                "risk_score":   95,
                "vulnerabilities": cve_list,
                "security_flags": [
                    {"severity": "CRITICAL", "description": "Default credentials detected"}
                ],
            }
        ],
        "environment_risk": {"score": 90, "level": "CRITICAL"},
        "summary": {
            "total_hosts":          1,
            "credentialed_hosts":   1,
            "uncredentialed_hosts": 0,
        },
        "trend_data": [],
    }


def _sample_host_data(with_kev: bool = True) -> dict:
    return {
        "ip":         "192.168.1.10",
        "hostname":   "WIN-SERVER-01",
        "os_guess":   "Windows Server 2019",
        "risk_score": 95,
        "risk_level": "CRITICAL",
        "vulnerabilities": [
            {
                "cve_id":     "CVE-2021-44228",
                "cvss_score": 10.0,
                "severity":   "CRITICAL",
                "kev":        with_kev,
                "description": "Apache Log4j2 JNDI injection RCE",
            }
        ],
        "security_flags": [
            {"severity": "CRITICAL", "description": "Default credentials on admin web UI"}
        ],
    }


# ── Tests ─────────────────────────────────────────────────────────────────

class TestGetRiskInsights(unittest.TestCase):

    # ── test_get_risk_insights_no_api_key ─────────────────────────────────

    def test_get_risk_insights_no_api_key_empty_string(self):
        """Empty api_key should immediately return None without HTTP call."""
        result = hatz_ai.get_risk_insights(_sample_scan_results(), None, "")
        self.assertIsNone(result)

    def test_get_risk_insights_no_api_key_none(self):
        """None api_key should immediately return None."""
        result = hatz_ai.get_risk_insights(_sample_scan_results(), None, None)
        self.assertIsNone(result)

    def test_get_risk_insights_no_api_key_whitespace(self):
        """Whitespace-only api_key should be treated as missing and return None."""
        result = hatz_ai.get_risk_insights(_sample_scan_results(), None, "   ")
        self.assertIsNone(result)

    # ── test_get_risk_insights_success ────────────────────────────────────

    @patch("urllib.request.urlopen")
    def test_get_risk_insights_success(self, mock_urlopen):
        """Mock HTTP 200 should return the AI insights string."""
        mock_urlopen.return_value = _mock_http_200(_MOCK_INSIGHTS_TEXT)

        result = hatz_ai.get_risk_insights(
            _sample_scan_results(),
            None,
            _MOCK_API_KEY,
        )
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)
        self.assertIn("Executive Summary", result)

    @patch("urllib.request.urlopen")
    def test_get_risk_insights_success_with_delta(self, mock_urlopen):
        """Mock HTTP 200 with delta dict should still return insights."""
        mock_urlopen.return_value = _mock_http_200(_MOCK_INSIGHTS_TEXT)
        delta = {
            "has_previous":    True,
            "risk_score_delta": 15,
            "new_hosts":       [],
            "removed_hosts":   [],
            "new_findings":    {"192.168.1.10": ["CVE:CVE-2021-44228"]},
            "resolved_findings": {},
            "recurring_findings": {},
            "new_kev_cves":    [{"cve_id": "CVE-2021-44228", "ip": "192.168.1.10"}],
        }
        result = hatz_ai.get_risk_insights(
            _sample_scan_results(with_kev=True),
            delta,
            _MOCK_API_KEY,
        )
        self.assertIsNotNone(result)

    # ── test_get_risk_insights_http_error ─────────────────────────────────

    @patch("urllib.request.urlopen")
    def test_get_risk_insights_http_error_500(self, mock_urlopen):
        """HTTP 500 error should return None gracefully."""
        mock_urlopen.side_effect = _mock_http_error(500)
        result = hatz_ai.get_risk_insights(
            _sample_scan_results(), None, _MOCK_API_KEY
        )
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_get_risk_insights_http_error_401(self, mock_urlopen):
        """HTTP 401 (bad API key) should return None gracefully."""
        mock_urlopen.side_effect = _mock_http_error(401)
        result = hatz_ai.get_risk_insights(
            _sample_scan_results(), None, _MOCK_API_KEY
        )
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_get_risk_insights_http_error_429(self, mock_urlopen):
        """HTTP 429 (rate limit) should return None gracefully."""
        mock_urlopen.side_effect = _mock_http_error(429)
        result = hatz_ai.get_risk_insights(
            _sample_scan_results(), None, _MOCK_API_KEY
        )
        self.assertIsNone(result)

    # ── test_get_risk_insights_network_error ──────────────────────────────

    @patch("urllib.request.urlopen")
    def test_get_risk_insights_network_error(self, mock_urlopen):
        """URLError (network failure) should return None gracefully."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        result = hatz_ai.get_risk_insights(
            _sample_scan_results(), None, _MOCK_API_KEY
        )
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_get_risk_insights_timeout_error(self, mock_urlopen):
        """Timeout (generic exception) should return None gracefully."""
        mock_urlopen.side_effect = TimeoutError("Request timed out")
        result = hatz_ai.get_risk_insights(
            _sample_scan_results(), None, _MOCK_API_KEY
        )
        self.assertIsNone(result)


class TestGetHostNarrative(unittest.TestCase):

    # ── test_get_host_narrative_no_key ────────────────────────────────────

    def test_get_host_narrative_no_key(self):
        """No api_key should return None immediately."""
        result = hatz_ai.get_host_narrative(_sample_host_data(), "")
        self.assertIsNone(result)

    def test_get_host_narrative_no_key_none(self):
        """None api_key should return None."""
        result = hatz_ai.get_host_narrative(_sample_host_data(), None)
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_get_host_narrative_success(self, mock_urlopen):
        """Mock HTTP 200 should return the host narrative string."""
        mock_urlopen.return_value = _mock_http_200(_MOCK_HOST_NARRATIVE_TEXT)
        result = hatz_ai.get_host_narrative(_sample_host_data(), _MOCK_API_KEY)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    @patch("urllib.request.urlopen")
    def test_get_host_narrative_http_error(self, mock_urlopen):
        """HTTP error in host narrative should return None gracefully."""
        mock_urlopen.side_effect = _mock_http_error(503)
        result = hatz_ai.get_host_narrative(_sample_host_data(), _MOCK_API_KEY)
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_get_host_narrative_network_error(self, mock_urlopen):
        """Network error in host narrative should return None gracefully."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Network unreachable")
        result = hatz_ai.get_host_narrative(_sample_host_data(), _MOCK_API_KEY)
        self.assertIsNone(result)


class TestBuildRiskSummaryText(unittest.TestCase):

    # ── test_build_risk_summary_includes_kev ─────────────────────────────

    def test_build_risk_summary_includes_kev(self):
        """Scan data with a KEV CVE should include KEV marker text in the prompt."""
        scan_results = _sample_scan_results(with_kev=True)
        text = hatz_ai._build_risk_summary_text(scan_results, delta=None)
        self.assertIsInstance(text, str)
        self.assertTrue(len(text) > 0)
        # KEV marker should appear somewhere in the summary text
        self.assertTrue(
            "KEV" in text or "ACTIVELY EXPLOITED" in text or "CVE-2021-44228" in text,
            "Expected KEV reference in risk summary text"
        )

    def test_build_risk_summary_includes_environment_score(self):
        """Summary text should reference the environment risk score."""
        scan_results = _sample_scan_results()
        text = hatz_ai._build_risk_summary_text(scan_results, delta=None)
        self.assertIn("90", text)

    def test_build_risk_summary_includes_host_count(self):
        """Summary text should mention total hosts scanned."""
        scan_results = _sample_scan_results()
        text = hatz_ai._build_risk_summary_text(scan_results, delta=None)
        self.assertTrue("1" in text)

    def test_build_risk_summary_includes_delta(self):
        """When delta is provided, summary text should include delta section."""
        scan_results = _sample_scan_results()
        delta = {
            "has_previous":    True,
            "risk_score_delta": 20,
            "new_hosts":       ["10.0.0.2"],
            "removed_hosts":   [],
            "new_findings":    {"10.0.0.2": ["CVE:CVE-2021-44228"]},
            "resolved_findings": {},
            "recurring_findings": {},
            "new_kev_cves":    [],
        }
        text = hatz_ai._build_risk_summary_text(scan_results, delta=delta)
        self.assertIn("DELTA", text)

    def test_build_risk_summary_truncates_large_input(self):
        """Very large scan data should be truncated to _MAX_CHARS."""
        # Generate hosts with many CVEs
        hosts = [
            {
                "ip":           f"10.0.{i}.{j}",
                "hostname":     f"host-{i}-{j}",
                "risk_level":   "HIGH",
                "risk_score":   70,
                "vulnerabilities": [
                    {
                        "cve_id":      f"CVE-2023-{i:04d}{j:04d}",
                        "cvss_score":  7.5,
                        "severity":    "HIGH",
                        "kev":         False,
                        "description": "x" * 200,
                    }
                    for _ in range(20)
                ],
                "security_flags": [],
            }
            for i in range(10) for j in range(10)
        ]
        big_scan = {
            "hosts":            hosts,
            "environment_risk": {"score": 85, "level": "HIGH"},
            "summary":          {"total_hosts": len(hosts),
                                 "credentialed_hosts":   len(hosts),
                                 "uncredentialed_hosts": 0},
            "trend_data":       [],
        }
        text = hatz_ai._build_risk_summary_text(big_scan, delta=None)
        self.assertLessEqual(len(text), hatz_ai._MAX_CHARS + 100)

    def test_build_risk_summary_no_hosts(self):
        """Empty host list should still produce a non-empty summary string."""
        scan_results = {
            "hosts":            [],
            "environment_risk": {"score": 0, "level": "LOW"},
            "summary":          {"total_hosts": 0,
                                 "credentialed_hosts":   0,
                                 "uncredentialed_hosts": 0},
            "trend_data":       [],
        }
        text = hatz_ai._build_risk_summary_text(scan_results, delta=None)
        self.assertIsInstance(text, str)
        self.assertGreater(len(text), 0)


class TestSummarizeHost(unittest.TestCase):

    def test_summarize_host_includes_ip_hostname(self):
        """_summarize_host should include IP and hostname in output."""
        text = hatz_ai._summarize_host(_sample_host_data())
        self.assertIn("192.168.1.10", text)
        self.assertIn("WIN-SERVER-01", text)

    def test_summarize_host_includes_kev_tag(self):
        """_summarize_host should tag KEV CVEs with [KEV-ACTIVELY EXPLOITED]."""
        text = hatz_ai._summarize_host(_sample_host_data(with_kev=True))
        self.assertIn("KEV-ACTIVELY EXPLOITED", text)

    def test_summarize_host_no_kev_no_tag(self):
        """_summarize_host without KEV CVEs should not include KEV tag."""
        text = hatz_ai._summarize_host(_sample_host_data(with_kev=False))
        self.assertNotIn("KEV-ACTIVELY EXPLOITED", text)


class TestCallHatzApi(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_call_hatz_api_parses_response(self, mock_urlopen):
        """_call_hatz_api should extract content from the choices[0].message.content path."""
        mock_urlopen.return_value = _mock_http_200("Test narrative output")
        body = {
            "model":    hatz_ai.HATZ_MODEL,
            "messages": [{"role": "user", "content": "Test prompt"}],
            "stream":   False,
        }
        result = hatz_ai._call_hatz_api(body, "test context", _MOCK_API_KEY)
        self.assertEqual(result, "Test narrative output")

    @patch("urllib.request.urlopen")
    def test_call_hatz_api_uses_correct_api_key_header(self, mock_urlopen):
        """The HTTP request should include the X-API-Key header with the api_key."""
        mock_urlopen.return_value = _mock_http_200("OK")
        body = {
            "model":    hatz_ai.HATZ_MODEL,
            "messages": [],
            "stream":   False,
        }
        hatz_ai._call_hatz_api(body, "test", _MOCK_API_KEY)
        # Verify urlopen was called (request was made)
        mock_urlopen.assert_called_once()
        # Inspect the Request object
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertEqual(req.get_header("X-api-key"), _MOCK_API_KEY)

    @patch("urllib.request.urlopen")
    def test_call_hatz_api_posts_to_correct_url(self, mock_urlopen):
        """The HTTP request should POST to HATZ_API_URL."""
        mock_urlopen.return_value = _mock_http_200("OK")
        body = {"model": hatz_ai.HATZ_MODEL, "messages": [], "stream": False}
        hatz_ai._call_hatz_api(body, "test", _MOCK_API_KEY)
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertEqual(req.full_url, hatz_ai.HATZ_API_URL)
        self.assertEqual(req.method, "POST")


if __name__ == "__main__":
    unittest.main()
