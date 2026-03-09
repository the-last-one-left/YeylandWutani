#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
hatz_ai.py - Hatz AI API Integration

Sends network scan data to the Hatz AI API (ai.hatz.ai/v1) for an
AI-generated security insights summary to be embedded in the HTML report.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Optional

logger = logging.getLogger(__name__)

HATZ_API_URL = "https://ai.hatz.ai/v1/chat/completions"
HATZ_MODEL = "anthropic.claude-opus-4-6"

# Max characters sent per category of data (keeps payload under ~60 KB)
_MAX_CHARS = 50000


def _build_scan_summary_text(scan_results: dict) -> str:
    """
    Summarise scan_results into a compact text representation for the AI.
    Avoids sending raw binary data or excessively long port lists.
    """
    summary = scan_results.get("summary", {})
    recon = scan_results.get("reconnaissance", {})
    hosts = scan_results.get("hosts", [])

    lines = []

    # Network overview
    lines.append("=== NETWORK OVERVIEW ===")
    lines.append(f"Total hosts: {summary.get('total_hosts', len(hosts))}")
    lines.append(f"Open ports: {summary.get('total_open_ports', 0)}")
    lines.append(f"Security observations: {summary.get('security_observations', 0)}")
    lines.append(f"Subnets scanned: {', '.join(summary.get('subnets_scanned', []))}")
    lines.append(f"Default gateway: {recon.get('default_gateway', 'N/A')}")
    lines.append(f"DNS servers: {', '.join(recon.get('dns_servers', []))}")
    pub_ip = recon.get("public_ip_info", {})
    if pub_ip:
        lines.append(
            f"Public IP: {pub_ip.get('ip', 'N/A')} "
            f"({pub_ip.get('isp', 'N/A')}, {pub_ip.get('country', 'N/A')})"
        )

    # Device breakdown by category
    lines.append("\n=== DEVICE BREAKDOWN ===")
    for cat, count in sorted(summary.get("category_breakdown", {}).items()):
        lines.append(f"  {cat}: {count}")

    # Security flags (most important info)
    lines.append("\n=== SECURITY OBSERVATIONS ===")
    flag_count = 0
    for host in hosts:
        for flag in host.get("security_flags", []):
            if flag_count >= 200:
                lines.append("  [... additional findings truncated ...]")
                break
            sev = flag.get("severity", "INFO")
            desc = flag.get("description", "")
            lines.append(f"  [{sev}] {host.get('ip', '?')} — {desc}")
            flag_count += 1
        if flag_count >= 200:
            break

    # Host inventory (concise)
    lines.append("\n=== HOST INVENTORY ===")
    for host in hosts[:150]:
        parts = [
            host.get("ip", "?"),
            host.get("hostname", ""),
            host.get("device_category", "Unknown"),
            host.get("os_guess", ""),
        ]
        ports = host.get("open_ports", [])
        if ports:
            parts.append(f"ports: {','.join(str(p) for p in ports[:20])}")
        lines.append("  " + "  |  ".join(p for p in parts if p))
    if len(hosts) > 150:
        lines.append(f"  [... {len(hosts) - 150} additional hosts omitted ...]")

    # SSL audit issues
    ssl = scan_results.get("ssl_audit", {})
    if ssl.get("findings"):
        lines.append("\n=== SSL/TLS ISSUES ===")
        for f in ssl["findings"][:30]:
            lines.append(
                f"  [{f.get('severity', 'INFO')}] {f.get('host', '?')} — {f.get('issue', '')}"
            )

    # EOL detection
    eol = scan_results.get("eol_detection", {})
    if eol.get("eol_devices"):
        lines.append("\n=== END-OF-LIFE DEVICES ===")
        for d in eol["eol_devices"][:20]:
            lines.append(
                f"  {d.get('ip', '?')} — {d.get('product', '?')} "
                f"(EOL: {d.get('eol_date', 'unknown')})"
            )

    # OSINT
    osint = scan_results.get("osint", {})
    if osint.get("shodan_results"):
        lines.append("\n=== INTERNET-EXPOSED SERVICES (OSINT) ===")
        for r in osint["shodan_results"][:10]:
            lines.append(
                f"  {r.get('ip', '?')} — {r.get('summary', '')}"
            )

    text = "\n".join(lines)
    if len(text) > _MAX_CHARS:
        text = text[:_MAX_CHARS] + "\n[... data truncated to fit context limit ...]"
    return text


def get_hatz_insights(scan_results: dict, api_key: str) -> Optional[str]:
    """
    Send scan data to Hatz AI and return a markdown-formatted insights string.

    Returns None if the API key is missing, empty, or the call fails
    (failures are logged as warnings and do not abort the main workflow).
    """
    if not api_key or not api_key.strip():
        logger.info("Hatz AI: no API key configured — skipping AI insights.")
        return None

    scan_text = _build_scan_summary_text(scan_results)
    logger.info(
        f"Hatz AI: sending {len(scan_text):,} chars of scan data to {HATZ_MODEL}"
    )

    system_prompt = (
        "You are a senior network security engineer performing an MSP security assessment. "
        "Analyze the provided network discovery scan data and produce a concise, actionable "
        "AI Insights summary for the client report.\n\n"
        "Structure your response with these sections (use markdown headers):\n"
        "## Key Findings\n"
        "Bullet list of the 3-7 most significant security risks or observations.\n\n"
        "## Recommended Actions\n"
        "Numbered list of prioritized remediation steps (most critical first).\n\n"
        "## Positive Observations\n"
        "Brief note on what the network is doing well (1-3 items).\n\n"
        "Keep the total response under 600 words. Be specific — reference actual IPs, "
        "device types, or service names from the data. Avoid generic advice that doesn't "
        "apply to the specific findings."
    )

    body = {
        "model": HATZ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "Analyze this network discovery scan and provide AI insights "
                    "for the security report:\n\n" + scan_text
                ),
            },
        ],
        "stream": False,
        "temperature": 0.3,
    }

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
        insights = parsed["choices"][0]["message"]["content"]
        logger.info(
            f"Hatz AI: insights received — {len(insights):,} characters."
        )
        return insights
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            err_body = ""
        logger.warning(
            f"Hatz AI: HTTP {e.code} error — {err_body or e.reason}. "
            "Report will be generated without AI insights."
        )
        return None
    except urllib.error.URLError as e:
        logger.warning(
            f"Hatz AI: network error — {e.reason}. "
            "Report will be generated without AI insights."
        )
        return None
    except Exception as e:
        logger.warning(
            f"Hatz AI: unexpected error — {e}. "
            "Report will be generated without AI insights."
        )
        return None
