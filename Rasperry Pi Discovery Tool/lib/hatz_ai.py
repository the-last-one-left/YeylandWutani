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

# Max characters sent per category of data (keeps payload under ~80 KB)
_MAX_CHARS = 70000


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
            host.get("category", "Unknown"),
            host.get("os_guess", ""),
        ]
        ports = host.get("open_ports", [])
        if ports:
            parts.append(f"ports: {','.join(str(p) for p in ports[:20])}")
        lines.append("  " + "  |  ".join(p for p in parts if p))
    if len(hosts) > 150:
        lines.append(f"  [... {len(hosts) - 150} additional hosts omitted ...]")

    # Active Directory enrichment (Phase 24 credentialed scan)
    ad = scan_results.get("ad_enrichment", {})
    if ad.get("available"):
        lines.append("\n=== ACTIVE DIRECTORY ENRICHMENT ===")

        # Domain / forest info
        di = ad.get("domain_info", {})
        if di:
            lines.append(f"  Domain:          {di.get('domain_name', '?')}")
            lines.append(f"  NetBIOS:         {di.get('netbios_name', '?')}")
            lines.append(f"  Domain Mode:     {di.get('domain_mode', '?')}")
            lines.append(f"  Forest Mode:     {di.get('forest_mode', '?')}")
            lines.append(f"  DC Count:        {di.get('domain_controller_count', '?')}")
            lines.append(f"  PDC Emulator:    {di.get('pdc_emulator', '?')}")
            if di.get("sites"):
                lines.append(f"  Sites:           {', '.join(str(s) for s in di['sites'][:6])}")
            dc_list = di.get("domain_controllers", [])
            for dc in dc_list[:4]:
                flags = []
                if dc.get("IsGlobalCatalog"):
                    flags.append("GC")
                if dc.get("IsReadOnly"):
                    flags.append("RODC")
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                lines.append(
                    f"  DC: {dc.get('Name','?')} {dc.get('IPv4Address','')} "
                    f"({dc.get('OperatingSystem', '?')}){flag_str}"
                )

        # Counts
        lines.append(f"  Total users:     {ad.get('user_count', '?')}")
        lines.append(f"  Enabled users:   {ad.get('enabled_user_count', '?')}")
        lines.append(f"  Total computers: {ad.get('computer_count', '?')}")
        lines.append(f"  Servers:         {ad.get('server_count', '?')}")

        # Domain admins
        da = ad.get("domain_admins", [])
        lines.append(f"  Domain Admins ({len(da)}): {', '.join(da[:10])}")

        # Stale / dormant accounts
        stale_u = ad.get("stale_users", [])
        stale_c = ad.get("stale_computers", [])
        nli     = ad.get("never_logged_in", [])
        if stale_u:
            lines.append(f"  Stale users (>90 days, enabled): {len(stale_u)} — {', '.join(stale_u[:6])}")
        if nli:
            lines.append(f"  Never-logged-in user accounts:   {len(nli)}")
        if stale_c:
            lines.append(f"  Stale computer accounts:         {len(stale_c)} — {', '.join(stale_c[:6])}")

        # Password policy
        pp = ad.get("password_policy", {})
        if pp:
            lines.append(
                f"  Password policy: min_length={pp.get('min_password_length','?')}  "
                f"complexity={'Yes' if pp.get('complexity_enabled') else 'No'}  "
                f"lockout_threshold={pp.get('lockout_threshold','?')}  "
                f"max_age_days={pp.get('max_password_age_days','?')}"
            )

        # Service accounts (Kerberoastable)
        sa = ad.get("service_accounts", [])
        if sa:
            lines.append(f"  Kerberoastable SPN accounts ({len(sa)}): {', '.join(sa[:6])}")

        # Passwords never expire
        pne = ad.get("password_never_expires", [])
        if pne:
            lines.append(f"  Passwords never expire: {len(pne)} accounts")

        # AD trusts
        trusts = ad.get("trusts", [])
        if trusts:
            for t in trusts[:5]:
                lines.append(
                    f"  Trust: {t.get('Name','?')}  direction={t.get('Direction','?')}  "
                    f"type={t.get('TrustType','?')}  "
                    f"{'IntraForest' if t.get('IntraForest') else 'External'}"
                )

        # BitLocker status
        bitlocker = ad.get("bitlocker", {})
        if bitlocker:
            lines.append("  BitLocker status:")
            for cname, bl in sorted(bitlocker.items()):
                if bl.get("accessible"):
                    enc = bl.get("encrypted_count", 0)
                    uenc = bl.get("unencrypted_count", 0)
                    lines.append(
                        f"    {cname}: {enc} encrypted vol(s), {uenc} unencrypted"
                    )

        # 3rd-party services per server
        services = ad.get("services", {})
        if services:
            lines.append("  3rd-party auto-start services:")
            for cname, svc_entry in sorted(services.items()):
                if svc_entry.get("accessible") and svc_entry.get("services"):
                    svc_names = [s.get("display_name") or s.get("name", "") for s in svc_entry["services"][:6]]
                    lines.append(f"    {cname}: {', '.join(svc_names)}")

        # SMB shares per server
        shares = ad.get("shares", {})
        if shares:
            lines.append("  Non-admin SMB shares:")
            for cname, sh_entry in sorted(shares.items()):
                if sh_entry.get("accessible"):
                    non_admin = [s for s in sh_entry.get("shares", []) if not s.get("is_admin")]
                    if non_admin:
                        share_names = [f"{s.get('name','?')} ({s.get('path','')})" for s in non_admin[:4]]
                        lines.append(f"    {cname}: {', '.join(share_names)}")

        # Local admins per server
        local_admins = ad.get("local_admins", {})
        if local_admins:
            lines.append("  Local Administrators:")
            for cname, la_entry in sorted(local_admins.items()):
                if la_entry.get("accessible") and la_entry.get("members"):
                    member_names = [m.get("name", "") for m in la_entry["members"][:6]]
                    lines.append(f"    {cname}: {', '.join(member_names)}")

        # GPOs
        gpos = ad.get("gpos", [])
        if gpos:
            lines.append(f"  Group Policy Objects: {len(gpos)} total")
            disabled_gpos = [g.get("DisplayName","?") for g in gpos if g.get("GpoStatus","") not in ("AllSettingsEnabled",)]
            if disabled_gpos:
                lines.append(f"  GPOs not fully enabled: {', '.join(disabled_gpos[:5])}")

        # AD security findings (already summarised by build_ad_summary)
        sec_findings = ad.get("security_findings", [])
        if sec_findings:
            lines.append("  AD Security Findings:")
            for f in sec_findings:
                lines.append(f"    [{f.get('severity','?').upper()}] {f.get('title','')}: {f.get('detail','')[:160]}")

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
        "You are a technical sales consultant at an IT managed services and cybersecurity firm. "
        "A sales engineer has just run an automated network discovery tool at a prospective "
        "client site. Your job is to analyze the scan data and produce a concise briefing that "
        "helps the sales engineer understand the environment and have a confident, informed "
        "conversation with the client's decision maker.\n\n"
        "Frame everything through a business lens — risks are business risks, gaps are "
        "opportunities to add value, and findings should lead naturally toward managed "
        "services, security, or technology refresh conversations.\n\n"
        "Structure your response with these sections (use markdown headers):\n\n"
        "## Environment Snapshot\n"
        "2-4 sentences describing the environment: size, complexity, technology mix, and "
        "notable infrastructure (AD domain, VoIP, wireless, servers, segmented subnets). "
        "This is what the SE says when asked 'what did you find?' — keep it sharp.\n\n"
        "## Technology Gaps & Opportunities\n"
        "Bullet list of 5-8 observations framed as business risk or service opportunity. "
        "Examples: 'End-of-life devices on X nodes create unpatched exposure and a hardware "
        "refresh conversation', 'No visible backup infrastructure — data loss risk', "
        "'Open management ports suggest flat network with no segmentation'. "
        "When Active Directory enrichment data is present, include domain hygiene gaps "
        "(stale accounts, weak password policy, BitLocker gaps, excessive admins) framed "
        "as IT governance and compliance risk.\n\n"
        "## Recommended Services\n"
        "Numbered list of 3-6 service conversations to open, most impactful first. "
        "Map each directly to a gap above. Examples: Managed Security / MDR, Hardware "
        "Refresh, Network Segmentation Design, Backup & DR Assessment, Microsoft 365 "
        "Security Hardening, AD Health & Hygiene Remediation. Be specific enough to be "
        "credible but generic enough to apply to any MSP.\n\n"
        "## What They're Doing Well\n"
        "1-3 genuine positive observations. Credibility with the client depends on "
        "acknowledging what works, not just problems.\n\n"
        "Keep the total response under 650 words. Reference actual IPs, hostnames, "
        "domain names, device counts, or product names from the data — generic statements "
        "that could apply to any network undermine the SE's credibility.\n\n"
        "ACTIVE DIRECTORY DATA GUIDANCE:\n"
        "- If ACTIVE DIRECTORY ENRICHMENT data is present, treat it as authoritative.\n"
        "- Stale accounts (>90 days inactive, still enabled) signal poor IT hygiene — "
        "frame as a compliance and insider risk.\n"
        "- BitLocker off on servers is a data protection gap worth highlighting.\n"
        "- Excessive Domain Admins or Kerberoastable SPNs signal privilege hygiene issues.\n"
        "- Domain functional level below Windows Server 2016 limits modern security "
        "controls — frame as a modernization conversation.\n"
        "- 3rd-party auto-start services reveal the existing toolchain (RMM, AV, backup "
        "agents, LOB apps) — reference when discussing the incumbent vendor landscape.\n\n"
        "IMPORTANT — scan data limitations:\n"
        "- nmap cannot reliably distinguish Windows 10 from Windows 11. Say 'Windows 10/11 "
        "endpoints' unless AD or service banners confirm the version.\n"
        "- Device category (endpoint/server/switch) is more reliable than OS version guesses.\n"
        "- Vendor/OUI identifies NIC manufacturer, not device type — don't over-interpret.\n"
        "- Absence of evidence is not evidence of absence: missing backup ports doesn't "
        "mean no backup exists, it may be agent-based or off-network."
    )

    body = {
        "model": HATZ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "Here is the network discovery scan data from a prospective client site. "
                    "Produce the sales engineer briefing:\n\n" + scan_text
                ),
            },
        ],
        "stream": False,
        "temperature": 0.4,
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


def _build_osint_summary_text(osint_data: dict, recon: dict) -> str:
    """Compact text representation of OSINT data for the enrichment call."""
    lines = []

    pub_ip = osint_data.get("public_ip", "")
    ci     = osint_data.get("company_identification", {})
    whois  = osint_data.get("whois", {})
    dwhois = osint_data.get("domain_whois", {})
    shodan = osint_data.get("shodan", {})
    dns_sec = osint_data.get("dns_security", [])
    crtsh  = osint_data.get("crtsh_subdomains", {})
    ht_hostnames = osint_data.get("hackertarget_hostnames", [])

    lines.append(f"Public IP: {pub_ip}")
    lines.append(f"ISP/Org: {ci.get('isp', 'N/A')}  Location: {ci.get('city', '')}, {ci.get('region', '')}, {ci.get('country', '')}")
    lines.append(f"Domains discovered: {', '.join(ci.get('domains', []))}")

    if ci.get("domain_registrant"):
        lines.append(f"Domain registrant: {ci['domain_registrant']}")
    if ci.get("domain_registrar"):
        lines.append(f"Domain registrar:  {ci['domain_registrar']}")

    if whois:
        lines.append(f"IP WHOIS org: {whois.get('org', whois.get('organization', 'N/A'))}")
        lines.append(f"IP WHOIS netblock: {whois.get('cidr', whois.get('network', 'N/A'))}")

    if dwhois:
        lines.append(f"Domain created: {dwhois.get('created', 'N/A')}  expires: {dwhois.get('expires', 'N/A')}")

    if ht_hostnames:
        lines.append(f"Reverse-IP hostnames ({len(ht_hostnames)}): {', '.join(ht_hostnames[:12])}")

    if shodan:
        ports  = shodan.get("ports", [])
        vulns  = shodan.get("vulns", [])
        tags   = shodan.get("tags", [])
        lines.append(f"Shodan exposed ports: {ports}")
        if vulns:
            lines.append(f"Shodan CVEs: {', '.join(vulns[:10])}")
        if tags:
            lines.append(f"Shodan tags: {', '.join(tags)}")

    if dns_sec:
        lines.append("DNS security checks:")
        for check in dns_sec[:20]:
            status = check.get("status", "")
            name   = check.get("check", check.get("name", ""))
            detail = check.get("detail", check.get("value", ""))
            lines.append(f"  [{status}] {name}: {str(detail)[:120]}")

    if crtsh:
        total_subs = sum(len(v) for v in crtsh.values())
        lines.append(f"Certificate transparency subdomains: {total_subs} across {len(crtsh)} domain(s)")
        for domain, subs in list(crtsh.items())[:3]:
            lines.append(f"  {domain}: {', '.join(list(subs)[:8])}")

    recon_dns = recon.get("dns_servers", [])
    if recon_dns:
        lines.append(f"Internal DNS servers: {', '.join(recon_dns)}")

    return "\n".join(lines)


def get_hatz_osint_enrichment(osint_data: dict, recon: dict, api_key: str) -> Optional[str]:
    """
    Send OSINT scan data to Hatz AI for a focused company profile and internet
    exposure summary.  Called at the end of Phase 13.

    Returns a markdown string with two sections:
      ## Company Profile
      ## Internet Exposure Summary

    Returns None on failure (logged as warning, does not abort workflow).
    """
    if not api_key or not api_key.strip():
        return None

    osint_text = _build_osint_summary_text(osint_data, recon)
    if not osint_text.strip():
        return None

    logger.info(f"Hatz AI: requesting OSINT enrichment ({len(osint_text):,} chars)...")

    system_prompt = (
        "You are a technical sales consultant preparing a brief for a sales engineer "
        "who is about to meet with a prospective client. Based on publicly available "
        "OSINT data gathered about the client's internet presence, produce a concise "
        "intelligence brief with exactly two sections.\n\n"
        "## Company Profile\n"
        "2-3 sentences identifying the organization: who they likely are, what industry "
        "or sector they appear to be in (infer from domain name, registrant, ISP, "
        "and hostnames), approximate size or maturity indicators from their internet "
        "footprint. If you cannot make a confident identification, say so briefly.\n\n"
        "## Internet Exposure Summary\n"
        "Bullet list of 3-6 items covering: externally visible services or ports, "
        "any CVEs or vulnerabilities flagged by Shodan, DNS hygiene gaps (missing SPF, "
        "DMARC, DKIM), certificate transparency findings, and overall exposure risk "
        "level (Low / Medium / High). Frame each item as a talking point the SE can "
        "use in conversation — not raw technical data.\n\n"
        "Keep the total response under 300 words. Be specific and reference actual "
        "domain names, IPs, or service names from the data provided."
    )

    body = {
        "model": HATZ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": "OSINT data for the prospective client:\n\n" + osint_text,
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
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
        parsed      = json.loads(raw)
        enrichment  = parsed["choices"][0]["message"]["content"]
        logger.info(f"Hatz AI: OSINT enrichment received — {len(enrichment):,} chars.")
        return enrichment
    except Exception as e:
        logger.warning(f"Hatz AI: OSINT enrichment failed — {e}. Continuing without it.")
        return None
