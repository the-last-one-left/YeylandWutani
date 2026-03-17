#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
report_generator.py - Weekly HTML Email Report Builder

Generates a branded weekly risk digest email with all CSS inline
for email client compatibility. Covers: risk score hero, delta summary,
KEV alert block, top 10 risks table, per-host cards, AI insights, inventory.
Limit: ~3 MB total HTML to stay within Graph API limits.
"""

import html
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

MAX_EMAIL_HTML_BYTES = 3 * 1024 * 1024  # 3 MB limit

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#6c757d",
    "INFO":     "#17a2b8",
}

RISK_LEVEL_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#28a745",
}


def _e(v) -> str:
    """HTML-escape a value."""
    return html.escape(str(v)) if v is not None else ""


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), "#6c757d")
    return (
        f'<span style="display:inline-block;padding:2px 7px;border-radius:3px;'
        f'background:{color};color:#fff;font-size:11px;font-weight:bold;">'
        f'{_e(severity)}</span>'
    )


def _risk_badge(level: str) -> str:
    color = RISK_LEVEL_COLORS.get(level.upper(), "#6c757d")
    return (
        f'<span style="display:inline-block;padding:3px 9px;border-radius:3px;'
        f'background:{color};color:#fff;font-size:12px;font-weight:bold;">'
        f'{_e(level)}</span>'
    )


def _kev_badge() -> str:
    return (
        '<span style="display:inline-block;padding:2px 6px;border-radius:3px;'
        'background:#dc3545;color:#fff;font-size:10px;font-weight:bold;'
        'letter-spacing:0.5px;">KEV</span>'
    )


def _new_badge() -> str:
    return (
        '<span style="display:inline-block;padding:2px 6px;border-radius:3px;'
        'background:#17a2b8;color:#fff;font-size:10px;font-weight:bold;">'
        'NEW</span>'
    )


def _section_header(title: str, company_color: str) -> str:
    return (
        f'<h2 style="color:{company_color};font-size:16px;margin:24px 0 10px 0;'
        f'border-bottom:2px solid {company_color};padding-bottom:6px;">'
        f'{_e(title)}</h2>\n'
    )


def build_html_report(scan_results: dict, config: dict) -> str:
    """
    Build the complete weekly risk report HTML.
    Returns HTML string.
    """
    rep = config.get("reporting", {})
    company_name = rep.get("company_name", "Yeyland Wutani LLC")
    company_color = rep.get("company_color", "#FF6600")
    tagline = rep.get("tagline", "Building Better Systems")
    client_name = rep.get("client_name", "")

    scan_start = scan_results.get("scan_start", "")
    scan_end = scan_results.get("scan_end", "")
    hosts = scan_results.get("hosts", [])
    risk = scan_results.get("risk", {})
    delta = scan_results.get("delta", {})
    ai_insights = scan_results.get("ai_insights")
    vuln_db_stats = scan_results.get("vuln_db_stats", {})
    credential_coverage = scan_results.get("credential_coverage", {})
    summary = scan_results.get("summary", {})

    env_score = risk.get("environment_score", 0)
    env_level = _score_to_level(env_score)
    score_color = RISK_LEVEL_COLORS.get(env_level, "#6c757d")

    # Date range display
    try:
        start_dt = datetime.fromisoformat(scan_start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(scan_end.replace("Z", "+00:00"))
        date_range = f"{start_dt.strftime('%b %d')} \u2013 {end_dt.strftime('%b %d, %Y')}"
        scan_duration = f"{int((end_dt - start_dt).total_seconds() / 60)} min"
    except Exception:
        date_range = scan_start[:10] if scan_start else "N/A"
        scan_duration = "N/A"

    report_title = f"Weekly Cyber Risk Report \u2014 {_e(client_name)}" if client_name else "Weekly Cyber Risk Report"

    # Build sections
    sections = []

    # --- Risk Score Hero ---
    delta_score = delta.get("risk_score_delta", 0) if delta.get("has_previous") else 0
    if delta_score > 5:
        delta_arrow = f'<span style="color:#dc3545;font-size:28px;">&#8593;</span>'
        delta_text = f'<span style="color:#dc3545;font-size:14px;">+{delta_score} from last scan (worse)</span>'
    elif delta_score < -5:
        delta_arrow = f'<span style="color:#28a745;font-size:28px;">&#8595;</span>'
        delta_text = f'<span style="color:#28a745;font-size:14px;">{delta_score} from last scan (improving)</span>'
    else:
        delta_arrow = '<span style="color:#6c757d;font-size:28px;">&#8594;</span>'
        delta_text = '<span style="color:#6c757d;font-size:14px;">Stable since last scan</span>'

    sections.append(f'''
<table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
  <tr>
    <td align="center" style="background:{score_color};border-radius:8px;padding:24px;width:180px;">
      <div style="color:#fff;font-size:13px;font-weight:bold;letter-spacing:1px;text-transform:uppercase;">Environment Risk Score</div>
      <div style="color:#fff;font-size:64px;font-weight:bold;line-height:1.1;">{env_score}</div>
      <div style="color:rgba(255,255,255,0.9);font-size:16px;font-weight:bold;">{_e(env_level)}</div>
    </td>
    <td style="padding:0 0 0 24px;vertical-align:middle;">
      <div>{delta_arrow} {delta_text}</div>
      <div style="margin-top:12px;color:#555;font-size:13px;">
        <strong>{len(hosts)}</strong> hosts scanned &bull;
        <strong>{sum(len(h.get("cve_matches",[])) for h in hosts)}</strong> CVEs detected &bull;
        <strong>{sum(1 for h in hosts for c in h.get("cve_matches",[]) if c.get("kev"))}</strong> CISA KEV matches
      </div>
      <div style="margin-top:8px;color:#777;font-size:12px;">
        Scan period: {_e(date_range)} &bull; Duration: {_e(scan_duration)}
      </div>
    </td>
  </tr>
</table>
''')

    # --- Delta Summary Box ---
    if delta.get("has_previous"):
        new_issue_count = sum(len(v) for v in delta.get("new_findings", {}).values())
        resolved_count = sum(len(v) for v in delta.get("resolved_findings", {}).values())
        recurring_count = sum(len(v) for v in delta.get("recurring_findings", {}).values())
        kev_new = len(delta.get("new_kev_cves", []))
        sections.append(f'''
<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 20px 0;border:1px solid #dee2e6;border-radius:4px;">
  <tr>
    <td style="background:#f8f9fa;padding:12px 20px;border-bottom:1px solid #dee2e6;">
      <strong style="font-size:13px;color:#333;">Change Summary Since Last Scan</strong>
    </td>
  </tr>
  <tr>
    <td style="padding:12px 20px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="text-align:center;padding:8px;">
            <div style="font-size:28px;font-weight:bold;color:#dc3545;">{new_issue_count}</div>
            <div style="font-size:11px;color:#666;text-transform:uppercase;">New Issues</div>
          </td>
          <td style="text-align:center;padding:8px;">
            <div style="font-size:28px;font-weight:bold;color:#28a745;">{resolved_count}</div>
            <div style="font-size:11px;color:#666;text-transform:uppercase;">Resolved</div>
          </td>
          <td style="text-align:center;padding:8px;">
            <div style="font-size:28px;font-weight:bold;color:#fd7e14;">{recurring_count}</div>
            <div style="font-size:11px;color:#666;text-transform:uppercase;">Recurring</div>
          </td>
          <td style="text-align:center;padding:8px;">
            <div style="font-size:28px;font-weight:bold;color:#dc3545;">{kev_new}</div>
            <div style="font-size:11px;color:#666;text-transform:uppercase;">New KEV CVEs</div>
          </td>
          <td style="text-align:center;padding:8px;">
            <div style="font-size:28px;font-weight:bold;color:#17a2b8;">{len(delta.get("new_hosts",[]))}</div>
            <div style="font-size:11px;color:#666;text-transform:uppercase;">New Hosts</div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
''')

    # --- CISA KEV Alert Block ---
    new_kev = delta.get("new_kev_cves", []) if delta.get("has_previous") else []
    if not new_kev:
        # Show all current KEV matches if no delta
        for h in hosts:
            for cve in h.get("cve_matches", []):
                if cve.get("kev"):
                    new_kev.append({
                        "ip": h.get("ip", ""),
                        "hostname": h.get("hostname", ""),
                        "cve_id": cve.get("cve_id", ""),
                        "product": cve.get("product", ""),
                        "required_action": cve.get("kev_required_action", ""),
                    })

    if new_kev:
        kev_rows = ""
        for kev in new_kev[:20]:
            hostname = kev.get("hostname") or kev.get("ip", "")
            kev_rows += f'''
<tr>
  <td style="padding:6px 10px;border-bottom:1px solid #f5c6cb;font-size:12px;font-weight:bold;color:#dc3545;">{_e(kev.get("cve_id",""))}</td>
  <td style="padding:6px 10px;border-bottom:1px solid #f5c6cb;font-size:12px;">{_e(hostname)}</td>
  <td style="padding:6px 10px;border-bottom:1px solid #f5c6cb;font-size:12px;">{_e(kev.get("product",""))}</td>
  <td style="padding:6px 10px;border-bottom:1px solid #f5c6cb;font-size:12px;">{_e(kev.get("required_action","")[:100])}</td>
</tr>'''
        sections.append(f'''
<div style="background:#fff5f5;border:2px solid #dc3545;border-radius:4px;padding:16px;margin:0 0 20px 0;">
  <div style="color:#dc3545;font-size:14px;font-weight:bold;margin-bottom:10px;">
    &#9888; CISA Known Exploited Vulnerabilities (KEV) \u2014 Immediate Action Required
  </div>
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr style="background:#dc3545;color:#fff;">
      <th style="padding:6px 10px;text-align:left;font-size:11px;">CVE ID</th>
      <th style="padding:6px 10px;text-align:left;font-size:11px;">Host</th>
      <th style="padding:6px 10px;text-align:left;font-size:11px;">Affected Product</th>
      <th style="padding:6px 10px;text-align:left;font-size:11px;">CISA Required Action</th>
    </tr>
    {kev_rows}
  </table>
</div>
''')

    # --- Top 10 Risks Table ---
    risk_summary = risk.get("top_10_risks", [])
    if risk_summary:
        sections.append(_section_header("Top 10 Security Risks", company_color))
        rows = ""
        # Build set of new findings for badge
        new_finding_keys = set()
        if delta.get("has_previous"):
            for ip_findings in delta.get("new_findings", {}).values():
                new_finding_keys.update(ip_findings)

        for i, item in enumerate(risk_summary, 1):
            cve_id = item.get("detail", "")
            is_new = f"CVE:{cve_id}" in new_finding_keys or f"FLAG::{cve_id[:80]}" in new_finding_keys
            new_col = _new_badge() if is_new else ""
            kev_col = _kev_badge() if item.get("kev") else ""
            cvss = item.get("score", "")
            cvss_str = f"{cvss:.1f}" if isinstance(cvss, float) else str(cvss)
            rows += f'''
<tr style="{'background:#f8f9fa;' if i % 2 == 0 else ''}">
  <td style="padding:7px 10px;font-size:12px;color:#777;">{i}</td>
  <td style="padding:7px 10px;font-size:12px;font-weight:bold;">{_e(item.get("host",""))}</td>
  <td style="padding:7px 10px;font-size:12px;">{_e(cve_id)} {new_col}</td>
  <td style="padding:7px 10px;font-size:12px;">{_e(cvss_str)}</td>
  <td style="padding:7px 10px;">{_severity_badge(item.get("severity","INFO"))}</td>
  <td style="padding:7px 10px;">{kev_col}</td>
</tr>'''
        sections.append(f'''
<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:0 0 20px 0;">
  <tr style="background:{company_color};color:#fff;">
    <th style="padding:8px 10px;text-align:left;font-size:11px;">#</th>
    <th style="padding:8px 10px;text-align:left;font-size:11px;">Host</th>
    <th style="padding:8px 10px;text-align:left;font-size:11px;">Finding / CVE ID</th>
    <th style="padding:8px 10px;text-align:left;font-size:11px;">CVSS</th>
    <th style="padding:8px 10px;text-align:left;font-size:11px;">Severity</th>
    <th style="padding:8px 10px;text-align:left;font-size:11px;">KEV</th>
  </tr>
  {rows}
</table>
''')

    # --- Critical & High Host Cards ---
    crit_high = [h for h in hosts if h.get("risk_level") in ("CRITICAL", "HIGH")]
    if crit_high:
        sections.append(_section_header("Critical & High Risk Hosts", company_color))
        cards = ""
        for host in crit_high[:20]:
            ip = host.get("ip", "?")
            hostname = host.get("hostname") or ip
            category = host.get("category", "Unknown")
            score = host.get("risk_score", 0)
            level = host.get("risk_level", "HIGH")
            top_cves = host.get("cve_matches", [])[:3]

            top_items_html = ""
            for cve in top_cves:
                cve_id = cve.get("cve_id", "")
                cvss = cve.get("cvss_v3_score") or cve.get("cvss_v2_score") or 0
                kev = cve.get("kev", False)
                top_items_html += f'<li style="font-size:12px;color:#444;margin:2px 0;">{_e(cve_id)} (CVSS {cvss}) {_kev_badge() if kev else ""}</li>'

            cards += f'''
<table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #dee2e6;border-radius:4px;margin-bottom:10px;">
  <tr>
    <td style="padding:10px 16px;background:#f8f9fa;border-bottom:1px solid #dee2e6;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="font-size:14px;font-weight:bold;color:#333;">{_e(hostname)}</td>
          <td style="color:#777;font-size:12px;">{_e(ip)} &bull; {_e(category)}</td>
          <td align="right">{_risk_badge(level)} <span style="font-size:12px;color:#666;">Score: {score}</span></td>
        </tr>
      </table>
    </td>
  </tr>
  <tr>
    <td style="padding:10px 16px;">
      <ul style="margin:0;padding-left:20px;">{top_items_html}</ul>
    </td>
  </tr>
</table>'''
        sections.append(cards)

    # --- Credential Coverage ---
    if credential_coverage:
        sections.append(_section_header("Credential Coverage", company_color))
        ssh_ok = len(credential_coverage.get("ssh_success", []))
        ssh_fail = len(credential_coverage.get("ssh_failed", []))
        wmi_ok = len(credential_coverage.get("wmi_success", []))
        wmi_fail = len(credential_coverage.get("wmi_failed", []))
        snmp_ok = len(credential_coverage.get("snmp_success", []))
        no_cred = len(credential_coverage.get("no_credential", []))
        total_hosts = len(hosts)

        sections.append(f'''
<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:0 0 20px 0;">
  <tr style="background:{company_color};color:#fff;">
    <th style="padding:8px 12px;text-align:left;font-size:11px;">Protocol</th>
    <th style="padding:8px 12px;text-align:center;font-size:11px;">&#10003; Success</th>
    <th style="padding:8px 12px;text-align:center;font-size:11px;">&#10007; Failed</th>
    <th style="padding:8px 12px;text-align:center;font-size:11px;">Coverage</th>
  </tr>
  <tr>
    <td style="padding:7px 12px;font-size:13px;">SSH</td>
    <td style="padding:7px 12px;text-align:center;color:#28a745;font-weight:bold;">{ssh_ok}</td>
    <td style="padding:7px 12px;text-align:center;color:#dc3545;">{ssh_fail}</td>
    <td style="padding:7px 12px;text-align:center;font-size:12px;">{int(ssh_ok/max(total_hosts,1)*100)}%</td>
  </tr>
  <tr style="background:#f8f9fa;">
    <td style="padding:7px 12px;font-size:13px;">WMI/WinRM</td>
    <td style="padding:7px 12px;text-align:center;color:#28a745;font-weight:bold;">{wmi_ok}</td>
    <td style="padding:7px 12px;text-align:center;color:#dc3545;">{wmi_fail}</td>
    <td style="padding:7px 12px;text-align:center;font-size:12px;">{int(wmi_ok/max(total_hosts,1)*100)}%</td>
  </tr>
  <tr>
    <td style="padding:7px 12px;font-size:13px;">SNMP</td>
    <td style="padding:7px 12px;text-align:center;color:#28a745;font-weight:bold;">{snmp_ok}</td>
    <td style="padding:7px 12px;text-align:center;color:#dc3545;">\u2014</td>
    <td style="padding:7px 12px;text-align:center;font-size:12px;">{int(snmp_ok/max(total_hosts,1)*100)}%</td>
  </tr>
  <tr style="background:#f8f9fa;">
    <td style="padding:7px 12px;font-size:13px;">No Credential</td>
    <td style="padding:7px 12px;text-align:center;color:#fd7e14;">{no_cred}</td>
    <td style="padding:7px 12px;text-align:center;">\u2014</td>
    <td style="padding:7px 12px;text-align:center;font-size:12px;">{int(no_cred/max(total_hosts,1)*100)}%</td>
  </tr>
</table>
''')

    # --- New Hosts ---
    new_host_ips = delta.get("new_hosts", []) if delta.get("has_previous") else []
    if new_host_ips:
        new_host_items = ""
        for ip in new_host_ips[:20]:
            h = next((h for h in hosts if h.get("ip") == ip), {})
            hostname = h.get("hostname") or ip
            category = h.get("category", "Unknown")
            new_host_items += f'<li style="font-size:13px;color:#444;margin:3px 0;"><strong>{_e(hostname)}</strong> ({_e(ip)}) \u2014 {_e(category)}</li>'

        sections.append(f'''
{_section_header("New Hosts Detected", company_color)}
<div style="background:#f0fff4;border-left:4px solid #28a745;padding:12px 16px;border-radius:0 4px 4px 0;margin-bottom:20px;">
  <ul style="margin:0;padding-left:20px;">{new_host_items}</ul>
</div>
''')

    # --- Resolved Findings ---
    resolved = delta.get("resolved_findings", {}) if delta.get("has_previous") else {}
    if resolved:
        resolved_count = sum(len(v) for v in resolved.values())
        sections.append(f'''
{_section_header("Resolved Since Last Scan", company_color)}
<div style="background:#f0fff4;border-left:4px solid #28a745;padding:12px 16px;border-radius:0 4px 4px 0;margin-bottom:20px;">
  <p style="color:#28a745;font-size:13px;margin:0;">&#10003; {resolved_count} security finding(s) resolved since last scan.</p>
</div>
''')

    # --- AI Insights ---
    if ai_insights:
        sections.append(_section_header("AI Security Insights", company_color))
        ai_html = _markdown_to_simple_html(ai_insights)
        sections.append(f'''
<div style="background:#f8f9fa;border:1px solid #dee2e6;border-radius:4px;padding:16px;margin-bottom:20px;">
  <div style="font-size:11px;color:#888;margin-bottom:8px;">Powered by Hatz AI &bull; For advisory use only &bull; Verify all findings independently</div>
  <div style="font-size:13px;color:#333;line-height:1.7;">{ai_html}</div>
</div>
''')

    # --- Device Inventory Table (first 50, sorted by risk score) ---
    sections.append(_section_header("Device Inventory", company_color))
    inv_rows = ""
    for h in hosts[:50]:
        ip = h.get("ip", "?")
        hostname = h.get("hostname") or "\u2014"
        category = h.get("category", "Unknown")
        os_v = h.get("os_version") or h.get("os_guess") or "\u2014"
        if len(os_v) > 40:
            os_v = os_v[:37] + "..."
        cve_count = len(h.get("cve_matches", []))
        score = h.get("risk_score", 0)
        level = h.get("risk_level", "LOW")
        inv_rows += f'''
<tr>
  <td style="padding:6px 10px;font-size:12px;font-weight:bold;">{_e(ip)}</td>
  <td style="padding:6px 10px;font-size:12px;">{_e(hostname)}</td>
  <td style="padding:6px 10px;font-size:12px;">{_e(category)}</td>
  <td style="padding:6px 10px;font-size:12px;">{_e(os_v)}</td>
  <td style="padding:6px 10px;text-align:center;">{_risk_badge(level)}</td>
  <td style="padding:6px 10px;text-align:center;font-size:12px;">{cve_count}</td>
</tr>'''

    if len(hosts) > 50:
        inv_rows += f'<tr><td colspan="6" style="padding:8px 10px;font-size:12px;color:#888;text-align:center;">... {len(hosts)-50} additional hosts in attached report</td></tr>'

    sections.append(f'''
<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin:0 0 20px 0;">
  <tr style="background:{company_color};color:#fff;">
    <th style="padding:7px 10px;text-align:left;font-size:11px;">IP</th>
    <th style="padding:7px 10px;text-align:left;font-size:11px;">Hostname</th>
    <th style="padding:7px 10px;text-align:left;font-size:11px;">Category</th>
    <th style="padding:7px 10px;text-align:left;font-size:11px;">OS</th>
    <th style="padding:7px 10px;text-align:center;font-size:11px;">Risk</th>
    <th style="padding:7px 10px;text-align:center;font-size:11px;">CVEs</th>
  </tr>
  {inv_rows}
</table>
''')

    # --- Vuln DB Status ---
    if vuln_db_stats:
        sections.append(f'''
{_section_header("Vulnerability Database Status", company_color)}
<table width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 20px 0;">
  <tr>
    <td style="padding:5px 0;color:#555;font-size:13px;width:200px;">NVD CVEs in Cache</td>
    <td style="padding:5px 0;color:#222;font-size:13px;">{_e(vuln_db_stats.get("nvd_cve_count", "N/A"))}</td>
  </tr>
  <tr>
    <td style="padding:5px 0;color:#555;font-size:13px;">CISA KEV Entries</td>
    <td style="padding:5px 0;color:#222;font-size:13px;">{_e(vuln_db_stats.get("kev_cve_count", "N/A"))}</td>
  </tr>
  <tr>
    <td style="padding:5px 0;color:#555;font-size:13px;">NVD Last Updated</td>
    <td style="padding:5px 0;color:#222;font-size:13px;">{_e(vuln_db_stats.get("nvd_last_updated", "N/A"))}</td>
  </tr>
  <tr>
    <td style="padding:5px 0;color:#555;font-size:13px;">KEV Last Updated</td>
    <td style="padding:5px 0;color:#222;font-size:13px;">{_e(vuln_db_stats.get("kev_last_updated", "N/A"))}</td>
  </tr>
</table>
''')

    # Assemble full HTML
    body_content = "\n".join(sections)
    full_html = _wrap_in_email_shell(
        body_content, report_title, company_name, company_color, tagline, date_range
    )

    # Truncate if over limit
    encoded = full_html.encode("utf-8")
    if len(encoded) > MAX_EMAIL_HTML_BYTES:
        logger.warning(
            f"Report HTML {len(encoded)/1024:.0f} KB exceeds limit \u2014 truncating"
        )
        full_html = full_html[: MAX_EMAIL_HTML_BYTES - 500] + "\n...[truncated]</td></tr></table></body></html>"

    logger.info(f"HTML report built: {len(full_html.encode('utf-8'))/1024:.0f} KB")
    return full_html


def _score_to_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _markdown_to_simple_html(text: str) -> str:
    """Convert basic markdown (## headers, bullet lists) to simple HTML."""
    import re
    lines = []
    in_list = False
    for line in text.splitlines():
        line = line.rstrip()
        if line.startswith("## "):
            if in_list:
                lines.append("</ul>")
                in_list = False
            heading = _e(line[3:])
            lines.append(f'<h3 style="color:#333;font-size:14px;margin:16px 0 6px 0;">{heading}</h3>')
        elif line.startswith("- ") or line.startswith("* "):
            if not in_list:
                lines.append('<ul style="margin:6px 0;padding-left:20px;">')
                in_list = True
            lines.append(f'<li style="margin:3px 0;">{_e(line[2:])}</li>')
        elif re.match(r"^\d+\.", line):
            if not in_list:
                lines.append('<ol style="margin:6px 0;padding-left:20px;">')
                in_list = True
            content = re.sub(r"^\d+\.\s*", "", line)
            lines.append(f'<li style="margin:3px 0;">{_e(content)}</li>')
        else:
            if in_list:
                lines.append("</ul>")
                in_list = False
            if line:
                lines.append(f'<p style="margin:6px 0;">{_e(line)}</p>')
    if in_list:
        lines.append("</ul>")
    return "\n".join(lines)


def _wrap_in_email_shell(
    body_content: str,
    title: str,
    company_name: str,
    company_color: str,
    tagline: str,
    date_range: str,
) -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_e(title)}</title>
</head>
<body style="margin:0;padding:0;background:#f4f4f4;font-family:Arial,Helvetica,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:20px 0;">
    <tr>
      <td align="center">
        <table width="680" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:4px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1);">

          <!-- Header -->
          <tr>
            <td style="background:{company_color};padding:24px 32px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td>
                    <div style="color:#fff;font-size:20px;font-weight:bold;">{_e(company_name)}</div>
                    <div style="color:rgba(255,255,255,0.85);font-size:13px;margin-top:4px;">{_e(title)}</div>
                  </td>
                  <td align="right" style="vertical-align:middle;">
                    <div style="color:rgba(255,255,255,0.9);font-size:12px;font-style:italic;">{_e(tagline)}</div>
                    <div style="color:rgba(255,255,255,0.7);font-size:11px;margin-top:4px;">{_e(date_range)}</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:24px 32px;">
              {body_content}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f8f8f8;border-top:1px solid #e8e8e8;padding:14px 32px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="color:#888;font-size:11px;">
                    Powered by <strong style="color:{company_color};">Yeyland Wutani</strong> Risk Scanner
                    &bull; {_e(company_name)} &bull; <em>{_e(tagline)}</em>
                  </td>
                  <td align="right" style="color:#bbb;font-size:11px;">{timestamp} &bull; CONFIDENTIAL</td>
                </tr>
              </table>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""
