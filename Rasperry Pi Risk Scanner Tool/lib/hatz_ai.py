#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Pi
hatz_ai.py - Hatz AI API Integration (Risk-Focused)

Sends vulnerability scan data to the Hatz AI API for risk-focused insights.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Optional

logger = logging.getLogger(__name__)

HATZ_API_URL = "https://ai.hatz.ai/v1/chat/completions"
HATZ_MODEL = "anthropic.claude-opus-4-6"

_MAX_CHARS = 50000

RISK_SYSTEM_PROMPT = (
    "You are a senior cybersecurity engineer performing a credentialed vulnerability assessment "
    "for a managed services client. Analyze the provided risk scan data and produce a concise, "
    "actionable AI Insights summary for the weekly security report.\n\n"
    "Structure your response with these sections (use markdown headers):\n\n"
    "## Executive Summary\n"
    "2-3 sentence non-technical overview suitable for a business owner. Summarize the overall "
    "security posture and the single most important issue requiring attention.\n\n"
    "## Critical Actions (This Week)\n"
    "Numbered list of the most critical remediation steps, ordered by risk. Reference actual "
    "CVE IDs, IP addresses, hostnames, and service names from the data. CISA KEV CVEs must "
    "appear first — these are actively exploited in the wild.\n\n"
    "## Risk Trend\n"
    "1-2 sentences on whether the security posture is improving or worsening compared to "
    "previous scans. Reference the risk score delta and counts of new vs. resolved findings.\n\n"
    "## Positive Security Controls\n"
    "Brief note on what the environment is doing well (1-3 items). Acknowledge any resolved "
    "findings or improved posture.\n\n"
    "Keep the total response under 700 words. Be specific — reference actual CVE IDs, IPs, "
    "hostnames, and service names from the data. Avoid generic advice that does not apply to "
    "the specific findings shown. If CISA KEV CVEs are present, treat them as the highest "
    "priority regardless of CVSS score."
)

HOST_NARRATIVE_PROMPT = (
    "You are a senior cybersecurity engineer writing a per-host risk narrative for a technical "
    "security report. Given the vulnerability and configuration findings for a single host, "
    "write a concise 2-4 sentence technical narrative explaining:\n"
    "1. What the host is and what risk it represents\n"
    "2. The most critical specific findings (CVE IDs, misconfigurations)\n"
    "3. The recommended immediate action\n\n"
    "Be direct and technical. Reference actual CVE IDs and specific findings. "
    "Keep the response under 100 words."
)


def _build_risk_summary_text(scan_results: dict, delta: Optional[dict] = None) -> str:
    """Summarize scan_results + delta into compact text for the AI prompt."""
    summary = scan_results.get("summary", {})
    hosts = scan_results.get("hosts", [])
    env_risk = scan_results.get("environment_risk", {})

    lines = []

    # Environment overview
    lines.append("=== ENVIRONMENT RISK OVERVIEW ===")
    lines.append(f"Environment risk score: {env_risk.get('score', 'N/A')}/100")
    lines.append(f"Risk level: {env_risk.get('level', 'N/A')}")
    lines.append(f"Total hosts scanned: {summary.get('total_hosts', len(hosts))}")
    lines.append(f"Credential coverage: {summary.get('credentialed_hosts', 0)} credentialed, "
                 f"{summary.get('uncredentialed_hosts', 0)} uncredentialed")

    # Delta context
    if delta:
        lines.append("\n=== SCAN DELTA (CHANGES SINCE LAST SCAN) ===")
        lines.append(f"Risk score change: {delta.get('risk_score_delta', 0):+d} points")
        lines.append(f"New hosts discovered: {len(delta.get('new_hosts', []))}")
        lines.append(f"Hosts removed: {len(delta.get('removed_hosts', []))}")
        lines.append(f"New findings: {len(delta.get('new_findings', []))}")
        lines.append(f"Resolved findings: {len(delta.get('resolved_findings', []))}")
        lines.append(f"Recurring (unaddressed) findings: {len(delta.get('recurring_findings', []))}")
        kev_new = delta.get("new_kev_cves", [])
        if kev_new:
            lines.append(f"NEW CISA KEV CVEs matched: {len(kev_new)}")
            for cve_id in kev_new[:5]:
                lines.append(f"  !!! ACTIVELY EXPLOITED: {cve_id}")

    # CISA KEV matches
    kev_matches = [
        h for h in hosts
        if any(f.get("kev") for f in h.get("vulnerabilities", []))
    ]
    if kev_matches:
        lines.append("\n=== CISA KEV (ACTIVELY EXPLOITED) MATCHES ===")
        for host in kev_matches[:10]:
            kev_vulns = [v for v in host.get("vulnerabilities", []) if v.get("kev")]
            for v in kev_vulns[:3]:
                lines.append(
                    f"  !!! {host.get('ip', '?')} ({host.get('hostname', '')}) — "
                    f"{v.get('cve_id', '?')} CVSS:{v.get('cvss_score', '?')} — "
                    f"{v.get('description', '')[:120]}"
                )

    # Top CVEs by CVSS score
    all_cves = []
    for host in hosts:
        for v in host.get("vulnerabilities", []):
            score = v.get("cvss_score") or 0
            all_cves.append({
                "ip": host.get("ip", "?"),
                "hostname": host.get("hostname", ""),
                "cve_id": v.get("cve_id", ""),
                "cvss_score": score,
                "severity": v.get("severity", ""),
                "description": v.get("description", "")[:120],
                "kev": v.get("kev", False),
            })
    all_cves.sort(key=lambda x: (x["kev"], x["cvss_score"]), reverse=True)

    lines.append(f"\n=== TOP CVEs BY SEVERITY ===")
    for cve in all_cves[:20]:
        kev_tag = " [KEV]" if cve["kev"] else ""
        lines.append(
            f"  {cve['cve_id']}{kev_tag} CVSS:{cve['cvss_score']} "
            f"@ {cve['ip']} ({cve['hostname']}) — {cve['description']}"
        )

    # Host risk breakdown
    lines.append(f"\n=== HOST RISK BREAKDOWN ===")
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for host in hosts:
        level = host.get("risk_level", "LOW")
        risk_counts[level] = risk_counts.get(level, 0) + 1
    for level, count in risk_counts.items():
        lines.append(f"  {level}: {count} hosts")

    # Critical/High hosts
    critical_hosts = [h for h in hosts if h.get("risk_level") in ("CRITICAL", "HIGH")]
    if critical_hosts:
        lines.append(f"\n=== CRITICAL/HIGH RISK HOSTS ===")
        for host in critical_hosts[:15]:
            findings = host.get("security_flags", [])
            top_flags = [f.get("description", "") for f in findings[:3]]
            lines.append(
                f"  [{host.get('risk_level')}] {host.get('ip', '?')} "
                f"({host.get('hostname', 'unknown')}) score:{host.get('risk_score', '?')} — "
                + "; ".join(top_flags)
            )

    # Trend data if available
    trend = scan_results.get("trend_data", [])
    if trend:
        lines.append(f"\n=== RISK SCORE TREND (LAST {len(trend)} WEEKS) ===")
        for entry in trend[-8:]:
            lines.append(
                f"  {entry.get('date', '?')}: score={entry.get('risk_score', '?')} "
                f"CRIT={entry.get('critical_count', 0)} HIGH={entry.get('high_count', 0)}"
            )

    text = "\n".join(lines)
    if len(text) > _MAX_CHARS:
        text = text[:_MAX_CHARS] + "\n[... data truncated to fit context limit ...]"
    return text


def get_risk_insights(
    scan_results: dict,
    delta: Optional[dict],
    api_key: str,
) -> Optional[str]:
    """
    Send risk scan data to Hatz AI and return markdown insights string.

    Returns None if API key is missing or the call fails.
    """
    if not api_key or not api_key.strip():
        logger.info("Hatz AI: no API key configured — skipping AI insights.")
        return None

    scan_text = _build_risk_summary_text(scan_results, delta)
    logger.info(
        f"Hatz AI: sending {len(scan_text):,} chars of scan data to {HATZ_MODEL}"
    )

    body = {
        "model": HATZ_MODEL,
        "messages": [
            {"role": "system", "content": RISK_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Analyze this vulnerability scan and provide AI insights "
                    "for the weekly security report:\n\n" + scan_text
                ),
            },
        ],
        "stream": False,
        "temperature": 0.3,
    }

    return _call_hatz_api(body, "risk insights", api_key)


def get_host_narrative(host_data: dict, api_key: str) -> Optional[str]:
    """
    Generate a per-host risk narrative for high-risk hosts in the detail PDF.
    Only called when enable_per_host_narrative is true.
    """
    if not api_key or not api_key.strip():
        return None

    host_text = _summarize_host(host_data)
    body = {
        "model": HATZ_MODEL,
        "messages": [
            {"role": "system", "content": HOST_NARRATIVE_PROMPT},
            {
                "role": "user",
                "content": f"Write a risk narrative for this host:\n\n{host_text}",
            },
        ],
        "stream": False,
        "temperature": 0.2,
    }

    return _call_hatz_api(body, f"host narrative for {host_data.get('ip', '?')}", api_key)


def _summarize_host(host_data: dict) -> str:
    """Compact single-host summary for per-host narrative prompt."""
    lines = [
        f"IP: {host_data.get('ip', '?')}",
        f"Hostname: {host_data.get('hostname', 'unknown')}",
        f"OS: {host_data.get('os_guess', 'unknown')}",
        f"Risk score: {host_data.get('risk_score', '?')}/100",
        f"Risk level: {host_data.get('risk_level', '?')}",
    ]

    vulns = host_data.get("vulnerabilities", [])
    if vulns:
        lines.append("Vulnerabilities:")
        for v in sorted(vulns, key=lambda x: x.get("cvss_score") or 0, reverse=True)[:10]:
            kev_tag = " [KEV-ACTIVELY EXPLOITED]" if v.get("kev") else ""
            lines.append(
                f"  {v.get('cve_id', '?')}{kev_tag} CVSS:{v.get('cvss_score', '?')} — "
                f"{v.get('description', '')[:100]}"
            )

    flags = host_data.get("security_flags", [])
    if flags:
        lines.append("Security findings:")
        for f in flags[:10]:
            lines.append(f"  [{f.get('severity', 'INFO')}] {f.get('description', '')}")

    return "\n".join(lines)


def _call_hatz_api(body: dict, context: str, api_key: str) -> Optional[str]:
    """Make a Hatz AI API call and return the response text."""
    body_bytes = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(
        HATZ_API_URL,
        data=body_bytes,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "X-API-Key": api_key.strip(),
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read().decode("utf-8")
        parsed = json.loads(raw)
        result = parsed["choices"][0]["message"]["content"]
        logger.info(f"Hatz AI: {context} received — {len(result):,} characters.")
        return result
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            err_body = ""
        logger.warning(
            f"Hatz AI: HTTP {e.code} error for {context} — {err_body or e.reason}. "
            "Continuing without AI insights."
        )
        return None
    except urllib.error.URLError as e:
        logger.warning(
            f"Hatz AI: network error for {context} — {e.reason}. "
            "Continuing without AI insights."
        )
        return None
    except Exception as e:
        logger.warning(
            f"Hatz AI: unexpected error for {context} — {e}. "
            "Continuing without AI insights."
        )
        return None
