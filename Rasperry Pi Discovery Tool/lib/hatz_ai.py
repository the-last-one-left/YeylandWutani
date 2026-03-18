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
        "You are a senior network security engineer performing an MSP security assessment. "
        "Analyze the provided network discovery scan data and produce a concise, actionable "
        "AI Insights summary for the client report.\n\n"
        "Structure your response with these sections (use markdown headers):\n"
        "## Key Findings\n"
        "Bullet list of the 5-8 most significant security risks or observations. "
        "When Active Directory enrichment data is present, integrate it — reference "
        "domain functional level, stale accounts, password policy weaknesses, BitLocker "
        "gaps, unusual local admins, 3rd-party services, trust relationships, and AD "
        "security findings alongside network-level findings.\n\n"
        "## Recommended Actions\n"
        "Numbered list of prioritized remediation steps (most critical first). "
        "Where AD data shows specific gaps (e.g. BitLocker off on a server, "
        "excessive Domain Admins, missing account lockout), include targeted AD "
        "hygiene recommendations alongside network hardening steps.\n\n"
        "## Positive Observations\n"
        "Brief note on what the network is doing well (1-3 items).\n\n"
        "Keep the total response under 700 words. Be specific — reference actual IPs, "
        "hostnames, domain names, account names, device types, or service names from "
        "the data. Avoid generic advice that doesn't apply to the specific findings.\n\n"
        "ACTIVE DIRECTORY DATA GUIDANCE:\n"
        "- If ACTIVE DIRECTORY ENRICHMENT data is present, treat it as authoritative — "
        "it comes from a credentialed scan of the domain controller. Domain mode, user "
        "counts, and security findings are reliable.\n"
        "- Stale accounts (>90 days inactive) represent an attack surface even if they "
        "appear benign — flag them.\n"
        "- If BitLocker is off on any server, this is a HIGH priority finding.\n"
        "- Kerberoastable service accounts should be flagged and tied to an offline "
        "password cracking risk.\n"
        "- Domain functional level below Windows Server 2016 limits modern security "
        "controls (e.g. Protected Users group, Credential Guard).\n"
        "- External AD trusts expand the authentication boundary and should be reviewed.\n"
        "- 3rd-party auto-start services are valuable context for the client — "
        "mention backup agents, AV, RMM tools, or LOB software discovered.\n\n"
        "IMPORTANT — OS fingerprint limitations:\n"
        "- nmap cannot reliably distinguish Windows 10 from Windows 11 via passive TCP/IP "
        "fingerprinting. Phrase as 'Windows 10/11 endpoints' unless AD or service banners "
        "confirm the version.\n"
        "- Windows Server classification from ports is generally reliable but individual "
        "hosts may be misclassified — treat as indicative.\n"
        "- Vendor/OUI data identifies the NIC manufacturer, not necessarily the device "
        "type — do not over-interpret.\n"
        "- Multi-OS nmap guesses (e.g. 'Windows 11 / FreeBSD') are low-confidence; "
        "use device category as authoritative."
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
