#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
client_report.py - Client-Facing PDF Report Generator

Generates professional PDF reports from network scan data in the style of
commercial cybersecurity assessment reports:
  - Summary Report: Executive overview with risk score gauge and key findings
  - Detail Report: Technical deep-dive with per-device findings

Requires: reportlab  (pip install reportlab)
"""

import io
import math
from datetime import datetime
from typing import Optional

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, white, black, Color
    from reportlab.platypus import (
        BaseDocTemplate, Frame, PageTemplate, PageBreak, NextPageTemplate,
        Paragraph, Spacer, Table, TableStyle, KeepTogether,
    )
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus.flowables import Flowable
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ── Page geometry ─────────────────────────────────────────────────────────────

PAGE_W, PAGE_H = 612.0, 792.0   # letter, in points
MARGIN = 0.75 * 72               # 54 pt  (0.75 inch)
CONTENT_W = PAGE_W - 2 * MARGIN  # 504 pt
FOOTER_H = 38                    # height of footer band
CONTENT_H = PAGE_H - MARGIN - FOOTER_H - 18  # usable height on content pages


# ── Colour helpers ────────────────────────────────────────────────────────────

def _hex(s: str, fallback: str = "#FF6600") -> "HexColor":
    try:
        return HexColor(s if s.startswith("#") else f"#{s}")
    except Exception:
        return HexColor(fallback)


RISK_FLAG_COLORS = {
    "HIGH":     "#dc3545",
    "CRITICAL": "#dc3545",
    "MEDIUM":   "#fd7e14",
    "LOW":      "#28a745",
    "INFO":     "#6c757d",
}

RISK_LABEL = {
    "HIGH":     "HIGH RISK",
    "CRITICAL": "CRITICAL RISK",
    "MEDIUM":   "MEDIUM RISK",
    "LOW":      "LOW RISK",
    "INFO":     "INFO",
}


def _score_level(score: int) -> str:
    if score <= 33:
        return "LOW"
    if score <= 66:
        return "MODERATE"
    return "HIGH"


def _score_color(score: int) -> str:
    lvl = _score_level(score)
    return {"LOW": "#28a745", "MODERATE": "#ffc107", "HIGH": "#dc3545"}[lvl]


# ── Risk score ────────────────────────────────────────────────────────────────

def compute_risk_score(scan_results: dict) -> int:
    """Return a 0–100 risk score. Higher = more risk."""
    score = 0
    hosts = scan_results.get("hosts", [])

    flags_by_sev: dict = {"CRITICAL": set(), "HIGH": set(), "MEDIUM": set(), "LOW": set()}
    for host in hosts:
        for flag in host.get("security_flags", []):
            sev = flag.get("severity", "LOW")
            text = (flag.get("flag") or "")[:50]
            if sev in flags_by_sev:
                flags_by_sev[sev].add(text)

    score += min(len(flags_by_sev["CRITICAL"]) * 20, 40)
    score += min(len(flags_by_sev["HIGH"])     * 10, 30)
    score += min(len(flags_by_sev["MEDIUM"])   *  5, 20)
    score += min(len(flags_by_sev["LOW"])      *  2, 10)

    eol = scan_results.get("eol_detection", {}).get("summary", {})
    score += min(eol.get("critical_eol_count", 0) * 10
                 + eol.get("high_eol_count", 0) * 3, 20)

    testssl_findings = scan_results.get("testssl", {}).get("findings", [])
    high_tls = sum(1 for f in testssl_findings
                   if f.get("severity") in ("HIGH", "CRITICAL"))
    score += min(high_tls * 3, 10)

    nikto = scan_results.get("nikto", {}).get("findings", [])
    score += min(len(nikto) * 2, 8)

    return min(score, 100)


# ── Client name inference ─────────────────────────────────────────────────────

def _domain_to_display_name(domain: str) -> str:
    """
    Convert a bare domain into a human-readable org name.
    e.g.  'awesomazing.com'   -> 'Awesomazing'
          'pacific-office.net' -> 'Pacific Office'
          'acme.co.uk'         -> 'Acme'
    """
    if not domain:
        return ""
    # Strip any leading 'www.'
    d = domain.lower()
    if d.startswith("www."):
        d = d[4:]
    # Take only the registered name (everything before the first dot that's a TLD)
    # Simple heuristic: drop the last label(s) that look like TLDs
    parts = d.split(".")
    # Treat the last part as TLD; if second-to-last is also short (co, com, net…) drop both
    if len(parts) >= 3 and len(parts[-2]) <= 3:
        name_part = ".".join(parts[:-2])
    elif len(parts) >= 2:
        name_part = parts[0]
    else:
        name_part = d
    # Replace hyphens/underscores with spaces, title-case
    return " ".join(w.capitalize() for w in name_part.replace("-", " ").replace("_", " ").split())


def infer_client_name(scan_results: dict) -> str:
    """
    Best-effort inference of the prospect/client organization name from scan data.

    Priority order:
    1. OSINT primary_domain  (most reliable — scanner actively resolved this)
    2. DHCP domain pushed by the local DHCP server
    3. SSL cert subject CNs that contain a dot (pick the first non-generic one)
    4. Fall back to "Prospect Network"

    Returns a title-cased display name suitable for report headers.
    """
    # 1. OSINT primary domain
    primary = (
        scan_results
        .get("osint", {})
        .get("company_identification", {})
        .get("primary_domain", "")
    )
    if primary:
        name = _domain_to_display_name(primary)
        if name:
            return name

    # 2. DHCP domain
    dhcp_domain = (
        scan_results
        .get("summary", {})
        .get("dhcp", {})
        .get("domain", "")
    )
    if dhcp_domain:
        name = _domain_to_display_name(dhcp_domain)
        if name:
            return name

    # 3. SSL cert subject CNs — skip generic / infra names
    _generic = {"pi.hole", "localhost", "router", "gateway", "firewall", "switch"}
    for cert in scan_results.get("ssl_audit", {}).get("certificates", []):
        cn = (cert.get("subject_cn") or "").strip().lower()
        if "." in cn and cn not in _generic:
            # Extract the domain portion (rightmost two-ish labels)
            parts = cn.split(".")
            domain_guess = ".".join(parts[-2:]) if len(parts) >= 2 else cn
            if domain_guess not in _generic:
                name = _domain_to_display_name(domain_guess)
                if name:
                    return name

    return "Prospect Network"


# ── Cover page callout items ──────────────────────────────────────────────────

def _build_callouts(scan_results: dict) -> list:
    """Return 4 callout dicts: {count, label, color} for the cover page."""
    hosts = scan_results.get("hosts", [])
    items = []

    # High/Critical risk devices
    crit_hosts = {h["ip"] for h in hosts
                  for f in h.get("security_flags", [])
                  if f.get("severity") in ("CRITICAL", "HIGH")}
    if crit_hosts:
        items.append({"count": str(len(crit_hosts)),
                      "label": "Devices with\nHigh-Risk Findings",
                      "color": "#dc3545"})

    # EOL devices
    eol_devs = scan_results.get("eol_detection", {}).get("eol_devices", [])
    if eol_devs:
        items.append({"count": str(len(eol_devs)),
                      "label": "End-of-Life\nDevices Found",
                      "color": "#fd7e14"})

    # SSL issues
    ssl_s = scan_results.get("ssl_audit", {}).get("summary", {})
    ssl_n = ssl_s.get("self_signed", 0) + ssl_s.get("expired", 0) + ssl_s.get("expiring_7d", 0)
    if ssl_n:
        items.append({"count": str(ssl_n),
                      "label": "SSL Certificate\nIssues Found",
                      "color": "#ffc107"})

    # Exposed management services (RDP, Telnet, FTP, VNC)
    mgmt_hosts = {h["ip"] for h in hosts
                  if set(h.get("open_ports", [])) & {3389, 23, 21, 5900, 5901}}
    if mgmt_hosts:
        items.append({"count": str(len(mgmt_hosts)),
                      "label": "Devices with Exposed\nRemote Access",
                      "color": "#17a2b8"})

    # Pad with total hosts if we have fewer than 4
    while len(items) < 4:
        items.append({"count": str(len(hosts)),
                      "label": "Total Devices\nDiscovered",
                      "color": "#6c757d"})

    return items[:4]


# ── Finding extraction ────────────────────────────────────────────────────────

def _extract_findings(scan_results: dict) -> list:
    """
    Build a list of structured finding dicts from scan_results, sorted by
    severity.  Each dict:
      category     : str  (section header, e.g. "NETWORK SECURITY")
      severity     : str  (HIGH / MEDIUM / LOW)
      title        : str
      description  : str
      table_headers: list[str] | None
      table_rows   : list[list] | None
      remediation  : str
      callout      : str | None   (sidebar note)
    """
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings = []
    hosts = scan_results.get("hosts", [])

    # ── 1. Insecure protocols (Telnet / FTP) ──────────────────────────────
    insecure_rows = []
    for h in hosts:
        ip = h.get("ip", "")
        name = h.get("hostname") or ip
        ports = set(h.get("open_ports", []))
        for proto, port in [("Telnet", 23), ("FTP", 21)]:
            if port in ports:
                insecure_rows.append([ip, name, proto, str(port)])

    if insecure_rows:
        findings.append({
            "category": "NETWORK SECURITY",
            "severity": "HIGH",
            "title": "INSECURE PROTOCOLS DETECTED",
            "description": (
                "Unencrypted protocols transmit data — including usernames and "
                "passwords — in plaintext across the network. Any device on the "
                "same network segment can passively capture this traffic. These "
                "protocols have no encryption whatsoever and should not be in use "
                "in any professional environment."
            ),
            "table_headers": ["IP ADDRESS", "DEVICE", "PROTOCOL", "PORT"],
            "table_rows": insecure_rows[:20],
            "remediation": (
                "Disable Telnet and FTP services on all listed devices immediately. "
                "Replace Telnet with SSH for remote administration. Replace FTP with "
                "SFTP or FTPS for file transfers. If these services cannot be disabled "
                "immediately, restrict access via firewall rules to trusted IP ranges only."
            ),
            "callout": (
                "Attackers intercepting Telnet or FTP "
                "traffic gain credentials and commands "
                "in real time — no exploit required."
            ),
        })

    # ── 2. End-of-life OS / software ──────────────────────────────────────
    eol_data = scan_results.get("eol_detection", {})
    eol_devs = eol_data.get("eol_devices", [])
    approaching = eol_data.get("approaching_eol", [])

    if eol_devs:
        rows = [[e.get("ip", ""), e.get("hostname", ""),
                 e.get("product", ""), str(e.get("eol_date", ""))]
                for e in eol_devs[:20]]
        findings.append({
            "category": "PATCHES",
            "severity": "HIGH",
            "title": "END-OF-LIFE DEVICES DETECTED",
            "description": (
                "End-of-life (EOL) operating systems and software no longer receive "
                "security updates from vendors. Attackers actively maintain exploit "
                "databases targeting known unpatched vulnerabilities in these products. "
                "Running EOL software significantly increases the probability of a "
                "successful cyberattack and may violate cyber insurance requirements."
            ),
            "table_headers": ["IP ADDRESS", "DEVICE", "PRODUCT", "EOL DATE"],
            "table_rows": rows,
            "remediation": (
                "Plan immediate upgrades for all end-of-life operating systems and "
                "software. Until upgrades are completed, isolate EOL devices on a "
                "restricted network segment and implement compensating controls such "
                "as application whitelisting and enhanced monitoring. Verify that "
                "EOL software is covered by your cyber insurance policy."
            ),
            "callout": (
                "Hackers maintain active exploit toolkits "
                "targeting EOL products. A single unpatched "
                "device can be the entry point for a full "
                "network compromise."
            ),
        })
    elif approaching:
        rows = [[e.get("ip", ""), e.get("hostname", ""),
                 e.get("product", ""), str(e.get("eol_date", ""))]
                for e in approaching[:15]]
        findings.append({
            "category": "PATCHES",
            "severity": "MEDIUM",
            "title": "SOFTWARE APPROACHING END-OF-LIFE",
            "description": (
                "Several products in the environment are approaching their end-of-life "
                "date and will soon stop receiving security updates. Proactive planning "
                "is required before these devices become security liabilities."
            ),
            "table_headers": ["IP ADDRESS", "DEVICE", "PRODUCT", "EOL DATE"],
            "table_rows": rows,
            "remediation": (
                "Begin planning and budgeting for upgrades to all software and operating "
                "systems approaching EOL. Establish a patch management program to ensure "
                "updates are applied before EOL deadlines are reached."
            ),
            "callout": None,
        })

    # ── 3. SSL / TLS issues ────────────────────────────────────────────────
    ssl_audit = scan_results.get("ssl_audit", {})
    ssl_certs = ssl_audit.get("certificates", [])
    testssl   = scan_results.get("testssl", {})
    testssl_findings = testssl.get("findings", [])

    expired  = [c for c in ssl_certs if (c.get("days_remaining") or 999) < 0]
    expiring = [c for c in ssl_certs if 0 <= (c.get("days_remaining") or 999) <= 30]
    selfsign = [c for c in ssl_certs if c.get("is_self_signed")]

    tssl_rows = [[f.get("ip", ""), str(f.get("port", "")),
                  (f.get("finding") or "")[:70], f.get("severity", "")]
                 for f in testssl_findings[:15]]
    cert_rows = []
    for c in (expired + expiring + selfsign)[:15]:
        dr = c.get("days_remaining")
        if dr is not None and dr < 0:
            status = "EXPIRED"
        elif dr is not None and dr <= 30:
            status = f"Expires in {dr} days"
        else:
            status = "Self-Signed"
        cert_rows.append([c.get("ip", ""), c.get("hostname") or "N/A",
                          f"Port {c.get('port', '')}", status])

    if testssl_findings or expired or expiring or selfsign:
        has_high = any(f.get("severity") in ("HIGH", "CRITICAL") for f in testssl_findings)
        sev = "HIGH" if (expired or has_high) else "MEDIUM"
        rows = tssl_rows or cert_rows
        hdrs = (["IP ADDRESS", "PORT", "FINDING", "SEVERITY"] if tssl_rows
                else ["IP ADDRESS", "DEVICE", "PORT", "STATUS"])
        findings.append({
            "category": "ENCRYPTION",
            "severity": sev,
            "title": "SSL/TLS SECURITY VULNERABILITIES",
            "description": (
                "Weak or misconfigured SSL/TLS encryption exposes network communications "
                "to interception. Deprecated protocol versions (TLS 1.0, TLS 1.1) contain "
                "known vulnerabilities and are no longer considered secure. Expired or "
                "self-signed certificates provide no identity assurance and are often "
                "ignored by monitoring tools, creating blind spots for attackers."
            ),
            "table_headers": hdrs,
            "table_rows": rows[:15],
            "remediation": (
                "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 at minimum (TLS 1.3 "
                "preferred). Renew all expired SSL certificates immediately. Replace "
                "self-signed certificates with certificates from a trusted Certificate "
                "Authority. Remove weak cipher suites (RC4, DES, 3DES, EXPORT). "
                "Establish automated certificate expiry monitoring and renewal."
            ),
            "callout": (
                "Weak encryption allows attackers to decrypt "
                "HTTPS traffic and capture passwords, session "
                "tokens, and confidential data."
            ),
        })

    # ── 4. Web application vulnerabilities (Nikto) ────────────────────────
    nikto = scan_results.get("nikto", {})
    nikto_findings = nikto.get("findings", [])
    if nikto_findings:
        rows = [[f.get("ip", ""), str(f.get("port", "")),
                 (f.get("finding") or "")[:80], f.get("severity", "MEDIUM")]
                for f in nikto_findings[:20]]
        has_high = any(f.get("severity") == "HIGH" for f in nikto_findings)
        findings.append({
            "category": "WEB SECURITY",
            "severity": "HIGH" if has_high else "MEDIUM",
            "title": "WEB APPLICATION VULNERABILITIES DETECTED",
            "description": (
                "Automated web application scanning identified security issues in web "
                "servers accessible on the network. Web application vulnerabilities can "
                "allow attackers to gain unauthorized access, exfiltrate data, or use "
                "internal web servers as pivot points for deeper network compromise."
            ),
            "table_headers": ["IP ADDRESS", "PORT", "FINDING", "SEVERITY"],
            "table_rows": rows,
            "remediation": (
                "Review and remediate each finding listed above. Update web server "
                "software to current supported versions. Remove or restrict access to "
                "unnecessary web interfaces and admin pages. Implement a Web Application "
                "Firewall (WAF) where applicable. Conduct regular web application "
                "vulnerability assessments."
            ),
            "callout": None,
        })

    # ── 5. Exposed management services ────────────────────────────────────
    mgmt_rows = []
    for h in hosts:
        ip = h.get("ip", "")
        name = h.get("hostname") or ip
        ports = set(h.get("open_ports", []))
        for proto, port in [("RDP", 3389), ("VNC", 5900), ("SMB", 445),
                             ("SNMP", 161), ("SSH", 22)]:
            if port in ports:
                mgmt_rows.append([ip, name, proto, str(port)])

    if mgmt_rows:
        has_critical = any(r[2] in ("RDP", "SMB") for r in mgmt_rows)
        findings.append({
            "category": "NETWORK SECURITY",
            "severity": "HIGH" if has_critical else "MEDIUM",
            "title": "MANAGEMENT SERVICES EXPOSED ON NETWORK",
            "description": (
                "Network management interfaces are accessible across the network without "
                "restriction. Services such as RDP and SMB are the primary targets for "
                "brute-force attacks, credential stuffing, and known exploits. SMB is "
                "the principal propagation mechanism for ransomware. Exposure of these "
                "services increases the blast radius of any successful breach."
            ),
            "table_headers": ["IP ADDRESS", "DEVICE", "SERVICE", "PORT"],
            "table_rows": mgmt_rows[:25],
            "remediation": (
                "Restrict RDP access to authorized management workstations using firewall "
                "rules or network segmentation. Disable SMB v1 on all devices; restrict "
                "SMB traffic with host-based firewall rules. Require multi-factor "
                "authentication (MFA) for all remote access services. Consider a VPN or "
                "zero-trust architecture to eliminate direct exposure of management "
                "interfaces."
            ),
            "callout": (
                "SMB (port 445) is the primary propagation "
                "vector for ransomware. One exposed SMB host "
                "can allow ransomware to spread to every "
                "device on the network within minutes."
            ),
        })

    # ── 6. Wireless security ──────────────────────────────────────────────
    wifi = scan_results.get("wifi", {})
    networks = wifi.get("networks", [])
    open_nets = [n for n in networks
                 if not n.get("security") or n.get("security", "").upper() in ("OPEN", "NONE")]
    weak_nets = [n for n in networks
                 if any(kw in (n.get("security") or "").upper()
                        for kw in ("WEP", "TKIP"))]

    if open_nets or weak_nets:
        rows = [[n.get("ssid", "(hidden)"), n.get("bssid", ""),
                 n.get("security") or "OPEN", str(n.get("signal_dbm", ""))]
                for n in (open_nets + weak_nets)[:15]]
        findings.append({
            "category": "WIRELESS SECURITY",
            "severity": "HIGH" if open_nets else "MEDIUM",
            "title": "INSECURE WIRELESS NETWORKS DETECTED",
            "description": (
                "Open or weakly-encrypted wireless networks were detected in the "
                "environment. Open networks allow any device to connect without "
                "authentication and gain access to network resources. WEP encryption "
                "is cryptographically broken and can be cracked in under a minute "
                "with freely available tools. Anyone within wireless range — in a "
                "parking lot, neighboring office, or public space — can connect."
            ),
            "table_headers": ["SSID", "BSSID", "SECURITY", "SIGNAL (dBm)"],
            "table_rows": rows,
            "remediation": (
                "Disable open wireless networks immediately. Replace WEP with WPA3 "
                "(preferred) or WPA2-AES as a minimum. Implement a separate isolated "
                "guest WiFi network. Consider 802.1X enterprise authentication for "
                "corporate WiFi. Regularly audit wireless networks for unauthorized "
                "access points (rogue APs)."
            ),
            "callout": (
                "An open wireless network is the equivalent "
                "of an unlocked front door. No credentials "
                "are required for an attacker to gain "
                "full network access."
            ),
        })

    # ── 7. NSE CVE findings ────────────────────────────────────────────────
    cve_rows = []
    seen_cves: set = set()
    for h in hosts:
        ip = h.get("ip", "")
        name = h.get("hostname") or ip
        for flag in h.get("security_flags", []):
            text = flag.get("flag", "")
            sev  = flag.get("severity", "")
            if "CVE-" in text and sev in ("CRITICAL", "HIGH"):
                cve_key = text[:50]
                if cve_key not in seen_cves:
                    seen_cves.add(cve_key)
                    cve_rows.append([ip, name, text[:80], sev])

    if cve_rows:
        findings.append({
            "category": "PATCHES",
            "severity": "CRITICAL" if any(r[3] == "CRITICAL" for r in cve_rows) else "HIGH",
            "title": "KNOWN VULNERABILITIES (CVEs) DETECTED",
            "description": (
                "Network service scanning identified devices running software with "
                "publicly-known vulnerabilities (CVEs). These vulnerabilities have "
                "documented exploits available in tools like Metasploit. Attackers "
                "actively scan the internet and internal networks for these exposures "
                "using automated tooling."
            ),
            "table_headers": ["IP ADDRESS", "DEVICE", "VULNERABILITY", "SEVERITY"],
            "table_rows": cve_rows[:20],
            "remediation": (
                "Apply vendor security patches for all CVEs identified above. Where "
                "patches are not yet available, implement compensating controls: "
                "restrict network access to affected services, enable IDS/IPS rules "
                "for known exploit signatures, and monitor affected hosts for signs "
                "of compromise. Prioritize CRITICAL and CVSS ≥9.0 vulnerabilities first."
            ),
            "callout": (
                "Public CVE databases provide step-by-step "
                "exploit guides. Unpatched CVEs are among "
                "the most common breach entry points."
            ),
        })

    # ── 8. Unknown / unidentified devices ─────────────────────────────────
    unknown = [h for h in hosts
               if h.get("category", "") in ("Unknown Device", "")
               and h.get("vendor", "") in ("", "Unknown")
               and len(h.get("open_ports", [])) >= 2]
    if unknown:
        rows = [[h.get("ip", ""), h.get("mac", ""),
                 h.get("os_guess") or "Unknown",
                 ", ".join(str(p) for p in sorted(h.get("open_ports", []))[:8])]
                for h in unknown[:15]]
        findings.append({
            "category": "SURVEILLANCE",
            "severity": "MEDIUM",
            "title": "UNIDENTIFIED DEVICES ON NETWORK",
            "description": (
                "Devices with no recognized ownership or purpose were found operating "
                "on the network. Unrecognized devices may represent unauthorized "
                "equipment connected by employees or visitors, or persistent attacker "
                "footholds used for reconnaissance and data exfiltration."
            ),
            "table_headers": ["IP ADDRESS", "MAC ADDRESS", "OS GUESS", "OPEN PORTS"],
            "table_rows": rows,
            "remediation": (
                "Investigate all unidentified devices and confirm their legitimacy. "
                "Implement Network Access Control (NAC) to require device registration "
                "before granting network access. Deploy network segmentation to limit "
                "what unrecognized devices can reach. Maintain an up-to-date asset "
                "inventory and audit it regularly against active network devices."
            ),
            "callout": None,
        })

    # ── 9. Backup posture ──────────────────────────────────────────────────
    backup = scan_results.get("backup_posture", {})
    bp_software = backup.get("backup_software", [])
    bp_obs = backup.get("observations", [])
    no_offsite = any("no offsite" in o.lower() or "not detected" in o.lower()
                     for o in bp_obs)

    if not bp_software:
        findings.append({
            "category": "BACKUPS",
            "severity": "MEDIUM",
            "title": "BACKUP INFRASTRUCTURE NOT IDENTIFIED",
            "description": (
                "No dedicated backup software or infrastructure was identified during "
                "the network scan. Without verifiable backup solutions in place, the "
                "organization is at significant risk from ransomware, hardware failure, "
                "or accidental deletion. The absence of detected systems does not "
                "guarantee backups are absent, but warrants immediate verification."
            ),
            "table_headers": None,
            "table_rows": None,
            "remediation": (
                "Verify a backup solution is actively protecting all critical systems "
                "and data. Implement the 3-2-1 rule: 3 copies of data, on 2 different "
                "media types, with 1 copy offsite or in the cloud. Test backup "
                "restoration at least monthly — without test restores there is no "
                "assurance data can be recovered. Consider a managed backup solution "
                "with automated verification and alerting."
            ),
            "callout": (
                "Ransomware attacks destroy local backups "
                "first. Without tested offsite backups, a "
                "ransomware attack may result in permanent, "
                "unrecoverable data loss."
            ),
        })
    elif no_offsite:
        findings.append({
            "category": "BACKUPS",
            "severity": "MEDIUM",
            "title": "NO OFFSITE BACKUP REPLICATION DETECTED",
            "description": (
                f"Backup software was detected ({', '.join(b.get('product', '') for b in bp_software[:3])}), "
                "however no offsite or cloud replication was identified. On-site backups "
                "are vulnerable to the same physical disasters (fire, flood, theft) and "
                "ransomware attacks that affect the primary environment."
            ),
            "table_headers": None,
            "table_rows": None,
            "remediation": (
                "Implement offsite or cloud-based backup replication for all critical "
                "data. Verify that backup copies are stored in a geographically separate "
                "location. Test restore procedures from offsite backups at least quarterly."
            ),
            "callout": None,
        })

    # ── 10. High port exposure ─────────────────────────────────────────────
    high_exp = [h for h in hosts if len(h.get("open_ports", [])) > 15]
    if high_exp:
        rows = []
        for h in sorted(high_exp, key=lambda x: len(x.get("open_ports", [])),
                        reverse=True)[:10]:
            ports = sorted(h.get("open_ports", []))
            sample = ", ".join(str(p) for p in ports[:10])
            if len(ports) > 10:
                sample += " ..."
            rows.append([h.get("ip", ""), h.get("hostname") or h.get("category", ""),
                         str(len(ports)), sample])
        findings.append({
            "category": "FIREWALLS",
            "severity": "MEDIUM",
            "title": "EXCESSIVE OPEN PORTS — HOST FIREWALL GAP",
            "description": (
                "Several devices have an unusually high number of open network ports, "
                "suggesting that host-based firewall rules are absent or overly "
                "permissive. Each open port represents a potential attack surface. "
                "Devices with many exposed ports are significantly easier to exploit "
                "during attacker reconnaissance and lateral movement."
            ),
            "table_headers": ["IP ADDRESS", "DEVICE TYPE", "OPEN PORTS", "SAMPLE PORTS"],
            "table_rows": rows,
            "remediation": (
                "Review and tighten host-based firewall rules on all listed devices. "
                "Close or restrict access to any ports not required for legitimate "
                "business functions. Implement network segmentation to limit "
                "device-to-device communication. Conduct regular port scan audits "
                "to identify newly exposed services."
            ),
            "callout": None,
        })

    # Sort by severity then by category
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "LOW"), 9))
    return findings


# ── Canvas drawing helpers ────────────────────────────────────────────────────

def _draw_gauge(c, cx: float, cy_base: float, r: float, score: int) -> None:
    """Draw a semicircular risk gauge using canvas primitives."""
    track_r = r * 0.82
    arc_w   = r * 0.26
    bb = (cx - track_r, cy_base - track_r, cx + track_r, cy_base + track_r)

    # Background track
    c.setLineWidth(arc_w + 6)
    c.setStrokeColor(_hex("#e9ecef"))
    c.arc(*bb, 0, 180)

    c.setLineWidth(arc_w)
    # GREEN: score 0-33 → angles 180°→120°
    c.setStrokeColor(_hex("#28a745"))
    c.arc(*bb, 120, 60)
    # YELLOW: score 33-66 → angles 120°→60°
    c.setStrokeColor(_hex("#ffc107"))
    c.arc(*bb, 60, 60)
    # RED: score 66-100 → angles 60°→0°
    c.setStrokeColor(_hex("#dc3545"))
    c.arc(*bb, 0, 60)

    # Needle
    angle_rad = math.radians(180.0 - score * 180.0 / 100.0)
    nl = track_r * 0.82
    nx = cx + nl * math.cos(angle_rad)
    ny = cy_base + nl * math.sin(angle_rad)
    c.setStrokeColor(_hex("#343a40"))
    c.setLineWidth(3)
    c.line(cx, cy_base, nx, ny)

    # Center cap
    c.setFillColor(_hex("#343a40"))
    c.setStrokeColor(white)
    c.setLineWidth(2)
    c.circle(cx, cy_base, 8, fill=1, stroke=1)

    # Score number
    c.setFillColor(_hex("#212529"))
    c.setFont("Helvetica-Bold", 44)
    c.drawCentredString(cx, cy_base - 52, str(score))

    # Level label
    lvl = _score_level(score)
    c.setFillColor(_hex(_score_color(score)))
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(cx, cy_base - 70, f"{lvl} RISK")


def _draw_cover(c, pw: float, ph: float, client_name: str, scan_date: str,
                risk_score: int, callouts: list, company_color: str,
                brand_name: str, brand_tagline: str) -> None:
    """Draw entire cover page (page origin at bottom-left)."""
    col = _hex(company_color)

    # ── Header band ────────────────────────────────────────────────────────
    header_h = 82
    c.setFillColor(col)
    c.rect(0, ph - header_h, pw, header_h, fill=1, stroke=0)

    # "CREATED FOR" micro label
    c.setFillColor(_hex("#ffffff99"))
    c.setFont("Helvetica", 8)
    c.drawString(MARGIN, ph - 22, "CREATED FOR")
    c.drawRightString(pw - MARGIN, ph - 22, "DATE")

    # Client name
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(MARGIN, ph - 46, client_name[:48])

    # "Cyber Risk Assessment" subtitle
    c.setFont("Helvetica", 11)
    c.setFillColor(_hex("#ffffffcc"))
    c.drawString(MARGIN, ph - 64, "Cyber Risk Assessment")

    # Date
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 12)
    c.drawRightString(pw - MARGIN, ph - 46, scan_date)

    # ── "Cyber Risk" section title ─────────────────────────────────────────
    title_y = ph - header_h - 38
    c.setFillColor(_hex("#343a40"))
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(pw / 2, title_y, "Cyber Risk")

    # LOW / MODERATE / HIGH badge row
    badge_labels = [("LOW", "#28a745"), ("MODERATE", "#ffc107"), ("HIGH", "#dc3545")]
    bw, bh, bg = 72, 18, 6
    total_bw = len(badge_labels) * bw + (len(badge_labels) - 1) * bg
    bx_start = pw / 2 - total_bw / 2
    by = title_y - 28
    for i, (lbl, clr) in enumerate(badge_labels):
        bx = bx_start + i * (bw + bg)
        c.setFillColor(_hex(clr))
        c.roundRect(bx, by, bw, bh, 3, fill=1, stroke=0)
        c.setFillColor(white)
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(bx + bw / 2, by + 5, lbl)

    # ── Risk gauge ─────────────────────────────────────────────────────────
    gauge_cy = by - 150    # base of semicircle
    gauge_r  = 110
    _draw_gauge(c, pw / 2, gauge_cy, gauge_r, risk_score)

    # ── "Contributing Cybersecurity Risks" header ──────────────────────────
    contrib_y = gauge_cy - 90
    c.setFillColor(_hex("#f8f9fa"))
    c.rect(MARGIN, contrib_y - 6, CONTENT_W, 28, fill=1, stroke=0)
    c.setFillColor(_hex("#343a40"))
    c.setFont("Helvetica-Bold", 11)
    c.drawString(MARGIN + 10, contrib_y + 6, "Contributing Cybersecurity Risks")
    c.setFont("Helvetica", 9)
    c.setFillColor(_hex("#555555"))
    c.drawString(MARGIN + 10, contrib_y - 4,
                 "Our team identified issues in the following areas of your network.")

    # ── Callout boxes (2×2) ────────────────────────────────────────────────
    box_h    = 108
    box_gap  = 12
    box_w_cb = (CONTENT_W - box_gap) / 2

    for i, item in enumerate(callouts[:4]):
        col_idx = i % 2
        row_idx = i // 2
        bx = MARGIN + col_idx * (box_w_cb + box_gap)
        by = contrib_y - box_gap - (row_idx + 1) * box_h - row_idx * box_gap

        item_col = _hex(item["color"])

        # White card with colored border
        c.setFillColor(white)
        c.setStrokeColor(item_col)
        c.setLineWidth(1.5)
        c.roundRect(bx, by, box_w_cb, box_h, 4, fill=1, stroke=1)

        # Colored accent bar at top
        c.setFillColor(item_col)
        c.rect(bx + 2, by + box_h - 22, box_w_cb - 4, 20, fill=1, stroke=0)

        # Large count
        c.setFillColor(_hex("#212529"))
        c.setFont("Helvetica-Bold", 32)
        c.drawCentredString(bx + box_w_cb * 0.3, by + box_h * 0.32, item["count"])

        # Label (may have \n)
        c.setFont("Helvetica", 9)
        c.setFillColor(_hex("#444444"))
        label_lines = item["label"].split("\n")
        ly = by + box_h * 0.60
        for line in label_lines:
            c.drawString(bx + box_w_cb * 0.55, ly, line)
            ly -= 13

    # ── Footer ─────────────────────────────────────────────────────────────
    c.setFillColor(_hex("#343a40"))
    c.rect(0, 0, pw, FOOTER_H, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica", 8)
    c.drawCentredString(pw / 2, FOOTER_H - 16,
                        f"CONFIDENTIAL  |  (c) {datetime.now().year} "
                        f"{brand_name}  |  {brand_tagline}")
    c.setFillColor(_hex("#aaaaaa"))
    c.setFont("Helvetica", 7)
    c.drawCentredString(pw / 2, FOOTER_H - 28, f"Analyzed {scan_date}")


def _draw_methods_page(c, pw: float, ph: float, scan_results: dict,
                       company_color: str, brand_name: str, scan_date: str) -> None:
    """Draw the methods page."""
    col = _hex(company_color)
    hosts = scan_results.get("hosts", [])
    recon = scan_results.get("reconnaissance", {})
    summary = scan_results.get("summary", {})

    # Header band
    c.setFillColor(col)
    c.rect(0, ph - 60, pw, 60, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(MARGIN, ph - 38, "METHODS")
    c.setFont("Helvetica", 10)
    c.setFillColor(_hex("#ffffffcc"))
    c.drawRightString(pw - MARGIN, ph - 38, f"Analyzed {scan_date}")

    # Body
    y = ph - 90
    def _section(title: str):
        nonlocal y
        c.setFillColor(col)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(MARGIN, y, title)
        c.setStrokeColor(col)
        c.setLineWidth(0.5)
        c.line(MARGIN, y - 4, pw - MARGIN, y - 4)
        y -= 22

    def _text(text: str, indent: int = 0, bold: bool = False):
        nonlocal y
        font = "Helvetica-Bold" if bold else "Helvetica"
        c.setFillColor(_hex("#333333"))
        c.setFont(font, 10)
        # Simple word wrap
        words = text.split()
        line  = ""
        max_w = CONTENT_W - indent - 10
        for word in words:
            test = f"{line} {word}".strip()
            if c.stringWidth(test, font, 10) > max_w:
                c.drawString(MARGIN + indent, y, line)
                y -= 14
                line = word
            else:
                line = test
        if line:
            c.drawString(MARGIN + indent, y, line)
            y -= 14

    _section("SCAN METHODOLOGY")
    _text(
        "This assessment uses passive and active network scanning techniques to "
        "identify devices, open services, and security vulnerabilities — entirely "
        "from the network perimeter without installing software on any device. "
        "The scanner operates from a dedicated Raspberry Pi appliance placed on "
        "the client network."
    )
    y -= 8

    # Two-column methodology description
    col1_x = MARGIN
    col2_x = pw / 2 + 6
    col_w  = CONTENT_W / 2 - 12

    col1_y = y
    c.setFillColor(col)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(col1_x, col1_y, "INTERNAL SCANNING")
    c.setFont("Helvetica", 9)
    c.setFillColor(_hex("#444444"))
    lines1 = [
        "The scanner performs multi-phase discovery:",
        "  +ARP + ping sweep for host discovery",
        "  +TCP/UDP port scanning (nmap + RustScan)",
        "  +Service version fingerprinting",
        "  +SMB, SNMP, and LDAP enumeration",
        "  +SSL/TLS certificate audit",
        "  +End-of-life OS/software detection",
        "  +Backup & DR posture inference",
        "  +WiFi network enumeration",
        "  +CVE detection via NSE scripts",
    ]
    for ln in lines1:
        c.drawString(col1_x, col1_y - 16, ln)
        col1_y -= 14

    col2_y = y
    c.setFillColor(col)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(col2_x, col2_y, "EXTERNAL SCANNING")
    c.setFont("Helvetica", 9)
    c.setFillColor(_hex("#444444"))
    lines2 = [
        "External posture analysis includes:",
        "  +Public IP / ISP identification",
        "  +External vulnerability scanning (OSINT)",
        "  +Deep TLS analysis (testssl.sh)",
        "  +Web vulnerability scanning (Nikto)",
        "  +Passive OS fingerprinting (p0f)",
        "  +Topology & gateway mapping",
        "  +WAN bandwidth testing",
        "  +Delta reporting (new/removed devices)",
    ]
    for ln in lines2:
        c.drawString(col2_x, col2_y - 16, ln)
        col2_y -= 14

    y = min(col1_y, col2_y) - 20

    _section("ENVIRONMENT SCANNED")
    subnets = summary.get("subnets_scanned", recon.get("subnets", []))
    gateway = recon.get("default_gateway", "N/A")
    dns     = ", ".join(recon.get("dns_servers", [])) or "N/A"
    pub     = recon.get("public_ip_info", {})
    pub_ip  = pub if isinstance(pub, str) else pub.get("public_ip", "N/A")

    # Scan stats table
    stats = [
        ["Devices Discovered", str(len(hosts)),
         "Subnets Scanned", ", ".join(subnets)],
        ["Open Ports Found", str(summary.get("total_open_ports", 0)),
         "Gateway", str(gateway)],
        ["Scan Duration", _fmt_duration(scan_results.get("duration_seconds", 0)),
         "DNS Servers", dns],
        ["Public IP", str(pub_ip),
         "Scanner Device", str(scan_results.get("scanner_host", "Pi"))],
    ]
    tw = CONTENT_W
    cws = [tw * 0.22, tw * 0.22, tw * 0.22, tw * 0.34]
    tbl_style = TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), _hex("#f8f9fa")),
        ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",    (2, 0), (2, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",   (0, 0), (0, -1), col),
        ("TEXTCOLOR",   (2, 0), (2, -1), col),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_hex("#f8f9fa"), white]),
        ("GRID", (0, 0), (-1, -1), 0.5, _hex("#dddddd")),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ])
    from reportlab.platypus import Table as RLTable
    tbl = RLTable(stats, colWidths=cws, style=tbl_style)
    tbl.wrapOn(c, CONTENT_W, 200)
    tbl.drawOn(c, MARGIN, y - tbl._height)
    y -= tbl._height + 20

    _section("DISCLAIMER")
    _text(
        "This assessment is a point-in-time snapshot based on network-visible "
        "data. It does not constitute a comprehensive penetration test and does "
        "not include endpoint agent analysis, password cracking, or social "
        "engineering testing. Findings are based on data observable from the "
        "network at the time of the scan."
    )

    # Footer
    _draw_content_footer(c, pw, scan_date, brand_name)


def _draw_finding_page(c, pw: float, ph: float, finding: dict,
                       company_color: str, brand_name: str, scan_date: str,
                       page_num: int = 0) -> None:
    """Draw a single finding page."""
    col = _hex(company_color)
    sev = finding.get("severity", "MEDIUM")
    sev_col = _hex(RISK_FLAG_COLORS.get(sev, "#fd7e14"))

    # ── Top category band ──────────────────────────────────────────────────
    band_h = 64
    c.setFillColor(_hex("#343a40"))
    c.rect(0, ph - band_h, pw, band_h, fill=1, stroke=0)

    # Category name (left)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(MARGIN, ph - 28, finding.get("category", "SECURITY"))

    # Risk badge (right)
    badge_lbl = RISK_LABEL.get(sev, sev)
    bw = 90
    bx = pw - MARGIN - bw
    by = ph - band_h + 12
    c.setFillColor(sev_col)
    c.roundRect(bx, by, bw, 22, 3, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 9)
    c.drawCentredString(bx + bw / 2, by + 7, badge_lbl)

    # Date right-aligned in band
    c.setFillColor(_hex("#aaaaaa"))
    c.setFont("Helvetica", 8)
    c.drawRightString(pw - MARGIN, ph - band_h + 4, f"Analyzed {scan_date}")

    # ── Finding title ──────────────────────────────────────────────────────
    title_y = ph - band_h - 24
    c.setFillColor(_hex("#212529"))
    c.setFont("Helvetica-Bold", 15)
    c.drawString(MARGIN, title_y, finding.get("title", ""))

    # Thin color underline
    c.setStrokeColor(sev_col)
    c.setLineWidth(2)
    c.line(MARGIN, title_y - 5, pw - MARGIN, title_y - 5)

    # ── Layout: has callout? use two-column description ────────────────────
    callout = finding.get("callout")
    desc_y  = title_y - 24
    has_callout = bool(callout)

    if has_callout:
        desc_w  = CONTENT_W * 0.68
        cb_x    = MARGIN + desc_w + 10
        cb_w    = CONTENT_W * 0.29
    else:
        desc_w = CONTENT_W
        cb_x = cb_w = 0

    # Description text (word-wrap into desc_w)
    desc_text = finding.get("description", "")
    desc_bottom = _draw_wrapped_text(c, desc_text, MARGIN, desc_y, desc_w,
                                     font="Helvetica", size=10, color="#333333",
                                     line_height=14)

    # Callout box
    if has_callout:
        cb_h = 90
        cb_y = desc_y - cb_h
        c.setFillColor(_hex("#fff8f0") if company_color == "#FF6600" else _hex("#f0f8ff"))
        c.setStrokeColor(sev_col)
        c.setLineWidth(3)
        c.rect(cb_x - 2, cb_y, cb_w + 2, cb_h, fill=1, stroke=0)
        c.setStrokeColor(sev_col)
        c.rect(cb_x - 5, cb_y, 3, cb_h, fill=1, stroke=0)  # left accent bar
        _draw_wrapped_text(c, callout, cb_x + 4, desc_y - 8, cb_w - 10,
                           font="Helvetica", size=9, color="#333333", line_height=13)

    # ── Data table ─────────────────────────────────────────────────────────
    table_top = min(desc_bottom, desc_y - (cb_h if has_callout else 0)) - 16
    headers = finding.get("table_headers")
    rows    = finding.get("table_rows") or []

    table_bottom = table_top
    if headers and rows:
        table_bottom = _draw_data_table(c, headers, rows, MARGIN, table_top,
                                        CONTENT_W, col)

    # ── Remediation ────────────────────────────────────────────────────────
    rem_y = table_bottom - 20
    if rem_y < FOOTER_H + 60:
        rem_y = FOOTER_H + 60

    c.setFillColor(col)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(MARGIN, rem_y, "Remediation:")
    rem_text = finding.get("remediation", "")
    _draw_wrapped_text(c, rem_text, MARGIN, rem_y - 16, CONTENT_W,
                       font="Helvetica", size=9, color="#444444", line_height=13)

    # Footer
    _draw_content_footer(c, pw, scan_date, brand_name)


def _draw_wrapped_text(c, text: str, x: float, y: float, max_w: float,
                       font: str = "Helvetica", size: int = 10,
                       color: str = "#333333", line_height: int = 14) -> float:
    """Draw word-wrapped text. Returns bottom Y position."""
    c.setFillColor(_hex(color))
    c.setFont(font, size)
    words = text.split()
    line  = ""
    cur_y = y
    for word in words:
        test = f"{line} {word}".strip()
        if c.stringWidth(test, font, size) > max_w:
            if line:
                c.drawString(x, cur_y, line)
                cur_y -= line_height
            line = word
        else:
            line = test
    if line:
        c.drawString(x, cur_y, line)
        cur_y -= line_height
    return cur_y


def _draw_data_table(c, headers: list, rows: list, x: float, y: float,
                     width: float, accent_col: "HexColor") -> float:
    """Draw a styled data table with word-wrapping cells. Returns bottom Y."""
    from reportlab.platypus import Table as RLTable, Paragraph as RLPara
    from reportlab.lib.styles import ParagraphStyle

    n_cols  = len(headers)
    col_w   = width / n_cols

    hdr_style = ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=8,
                               textColor=white, leading=10)
    cell_style = ParagraphStyle("td", fontName="Helvetica", fontSize=8,
                                textColor=_hex("#333333"), leading=10)

    def _cell(text: str, style) -> RLPara:
        # Escape XML special chars for Paragraph
        safe = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return RLPara(safe, style)

    hdr_row   = [_cell(h, hdr_style) for h in headers]
    data_rows = [[_cell(str(v), cell_style) for v in row] for row in rows]
    all_data  = [hdr_row] + data_rows

    style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), accent_col),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_hex("#f8f9fa"), white]),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.5, _hex("#cccccc")),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ])
    tbl = RLTable(all_data, colWidths=[col_w] * n_cols, style=style, repeatRows=1)
    tbl.wrapOn(c, width, 600)
    draw_y = y - tbl._height
    tbl.drawOn(c, x, draw_y)
    return draw_y


def _fmt_duration(secs: float) -> str:
    s = int(secs)
    return f"{s // 60}m {s % 60}s" if s >= 60 else f"{s}s"


def _draw_inventory_page(c, pw: float, ph: float, hosts: list, summary: dict,
                         company_color: str, brand_name: str, scan_date: str) -> None:
    """Draw the device inventory page."""
    col = _hex(company_color)

    # Header band
    c.setFillColor(col)
    c.rect(0, ph - 60, pw, 60, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(MARGIN, ph - 38, "DEVICE INVENTORY SUMMARY")
    c.setFont("Helvetica", 10)
    c.setFillColor(_hex("#ffffffcc"))
    c.drawRightString(pw - MARGIN, ph - 38, f"{len(hosts)} devices discovered")

    y = ph - 80

    # Category breakdown
    from collections import Counter
    cats = Counter(h.get("category", "Unknown Device") for h in hosts)
    cat_data = [["DEVICE CATEGORY", "COUNT"]] + \
               [[cat, str(cnt)] for cat, cnt in cats.most_common()]

    style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), col),
        ("TEXTCOLOR",     (0, 0), (-1, 0), white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_hex("#f8f9fa"), white]),
        ("GRID",          (0, 0), (-1, -1), 0.5, _hex("#cccccc")),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
    ])
    from reportlab.platypus import Table as RLTable
    cat_tbl = RLTable(cat_data, colWidths=[CONTENT_W * 0.75, CONTENT_W * 0.25],
                      style=style)
    cat_tbl.wrapOn(c, CONTENT_W, 300)
    cat_tbl.drawOn(c, MARGIN, y - cat_tbl._height)
    y -= cat_tbl._height + 20

    # Top devices by port count
    c.setFillColor(col)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(MARGIN, y, "HIGHEST EXPOSURE — DEVICES BY OPEN PORT COUNT")
    c.setStrokeColor(col)
    c.setLineWidth(0.5)
    c.line(MARGIN, y - 4, pw - MARGIN, y - 4)
    y -= 18

    top_hosts = sorted(hosts, key=lambda h: len(h.get("open_ports", [])),
                       reverse=True)[:20]
    host_data = [["IP ADDRESS", "HOSTNAME", "CATEGORY", "OPEN PORTS", "KEY FLAGS"]]
    for h in top_hosts:
        flags = [f["flag"][:30] for f in h.get("security_flags", [])
                 if f.get("severity") in ("CRITICAL", "HIGH")][:2]
        host_data.append([
            h.get("ip", ""),
            (h.get("hostname") or "")[:20],
            h.get("category", "")[:22],
            str(len(h.get("open_ports", []))),
            "; ".join(flags)[:40] if flags else "",
        ])

    h_style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), col),
        ("TEXTCOLOR",     (0, 0), (-1, 0), white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_hex("#f8f9fa"), white]),
        ("GRID",          (0, 0), (-1, -1), 0.5, _hex("#cccccc")),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ])
    cws = [CONTENT_W * p for p in [0.16, 0.18, 0.20, 0.09, 0.37]]
    h_tbl = RLTable(host_data, colWidths=cws, style=h_style, repeatRows=1)
    h_tbl.wrapOn(c, CONTENT_W, 400)
    h_tbl.drawOn(c, MARGIN, y - h_tbl._height)

    _draw_content_footer(c, pw, scan_date, brand_name)


def _draw_final_page(c, pw: float, ph: float, company_color: str,
                     brand_name: str, brand_tagline: str, scan_date: str,
                     client_name: str) -> None:
    """Draw final observations / recommendations page."""
    col = _hex(company_color)

    c.setFillColor(col)
    c.rect(0, ph - 60, pw, 60, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(MARGIN, ph - 38, "FINAL OBSERVATIONS")
    c.setFont("Helvetica", 10)
    c.setFillColor(_hex("#ffffffcc"))
    c.drawRightString(pw - MARGIN, ph - 38, f"Analyzed {scan_date}")

    y = ph - 90

    def _heading(title: str):
        nonlocal y
        c.setFillColor(col)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(MARGIN, y, title)
        y -= 18

    def _para(text: str):
        nonlocal y
        y = _draw_wrapped_text(c, text, MARGIN, y, CONTENT_W,
                               font="Helvetica", size=10, color="#333333",
                               line_height=14)
        y -= 10

    def _bullet(items: list):
        nonlocal y
        for item in items:
            c.setFillColor(col)
            c.circle(MARGIN + 6, y + 4, 3, fill=1, stroke=0)
            y = _draw_wrapped_text(c, item, MARGIN + 16, y, CONTENT_W - 16,
                                   font="Helvetica", size=10, color="#333333",
                                   line_height=14)
        y -= 8

    _heading("CYBER RISK ASSESSMENT AND ASSET PROTECTION")
    _para(
        f"This network-based assessment, conducted across the {client_name} "
        "environment, provided insights into security vulnerabilities and "
        "configuration gaps visible from the network. The findings in this "
        "report reflect real-world risks that are actively exploited by attackers."
    )
    _para(
        "Based on our findings and the ongoing evolution of cyberthreats, we "
        "recommend the following actions to improve your security posture:"
    )
    y -= 4

    _heading("RECOMMENDED NEXT STEPS")
    _bullet([
        "Remediate all HIGH and CRITICAL findings immediately — prioritize EOL "
        "devices, exposed management services, and any CVE findings.",
        "Implement multi-factor authentication (MFA) for all remote access, "
        "email, and cloud services.",
        "Deploy a patch management program to ensure operating systems and "
        "software are updated within 30 days of release.",
        "Segment the network to isolate critical systems, IoT devices, and guest "
        "traffic from the corporate environment.",
        "Verify that backup solutions are tested and that offsite copies are "
        "available and recoverable.",
        "Implement security awareness training to reduce susceptibility to "
        "phishing — the entry point for over 90% of cyberattacks.",
    ])

    _heading("ONGOING ASSESSMENT PROGRAM")
    _para(
        "A single point-in-time assessment is a starting point, not a complete "
        "security program. Networks are constantly changing — new devices are "
        "added, software is updated, and new vulnerabilities are discovered daily. "
        "We recommend a quarterly assessment program to:"
    )
    _bullet([
        "Monitor for newly discovered vulnerabilities in your environment.",
        "Verify that previously identified issues have been remediated.",
        "Detect unauthorized or unrecognized devices added to the network.",
        "Maintain continuous visibility into your security posture for "
        "compliance and cyber insurance purposes.",
    ])

    # Conclusion box
    y -= 10
    box_h = 70
    c.setFillColor(_hex("#f8f9fa"))
    c.setStrokeColor(col)
    c.setLineWidth(1)
    c.roundRect(MARGIN, y - box_h, CONTENT_W, box_h, 4, fill=1, stroke=1)
    c.setFillColor(_hex("#212529"))
    c.setFont("Helvetica-Bold", 10)
    c.drawString(MARGIN + 12, y - 18, "CONCLUSION")
    c.setFont("Helvetica", 9)
    c.setFillColor(_hex("#333333"))
    conclusion = (
        "Protecting your data and minimizing cyber risk requires continuous vigilance. "
        "The findings in this report are actionable steps that, when addressed, "
        "significantly reduce your organization's exposure to cyberattack."
    )
    _draw_wrapped_text(c, conclusion, MARGIN + 12, y - 34, CONTENT_W - 24,
                       font="Helvetica", size=9, color="#333333", line_height=13)

    _draw_content_footer(c, pw, scan_date, brand_name)


def _draw_content_footer(c, pw: float, scan_date: str, brand_name: str) -> None:
    """Draw the standard page footer."""
    c.setFillColor(_hex("#343a40"))
    c.rect(0, 0, pw, FOOTER_H, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica", 8)
    c.drawCentredString(pw / 2, FOOTER_H - 16,
                        f"CONFIDENTIAL  |  (c) {datetime.now().year} "
                        f"{brand_name}")
    c.setFillColor(_hex("#aaaaaa"))
    c.setFont("Helvetica", 7)
    c.drawCentredString(pw / 2, FOOTER_H - 28, f"Analyzed {scan_date}")


# ── Public API ────────────────────────────────────────────────────────────────

def build_client_summary_pdf(scan_results: dict, config: dict) -> bytes:
    """
    Build and return the client-facing Summary Report PDF as bytes.

    Args:
        scan_results : dict from network-scanner.py run_discovery()
        config       : config dict from config.json

    Returns:
        PDF bytes, or raises ImportError if reportlab is not installed.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab is required for PDF reports. "
            "Install it: pip install reportlab"
        )

    from reportlab.pdfgen import canvas as rl_canvas

    reporting     = config.get("reporting", {})
    # brand_name / brand_color / tagline describe the ASSESSOR (Yeyland Wutani)
    brand_name    = reporting.get("company_name", "Yeyland Wutani LLC")
    company_color = reporting.get("company_color", "#FF6600")
    tagline       = reporting.get("tagline", "Building Better Systems")
    # client_name is the PROSPECT being assessed — explicit config override first,
    # otherwise inferred from the scan data (domain, SSL certs, OSINT).
    client_name   = reporting.get("client_name") or infer_client_name(scan_results)

    # Parse scan date
    scan_start = scan_results.get("scan_start", "")
    try:
        dt = datetime.fromisoformat(scan_start)
        scan_date = dt.strftime("%m/%d/%Y")
    except Exception:
        scan_date = datetime.now().strftime("%m/%d/%Y")

    risk_score = compute_risk_score(scan_results)
    callouts   = _build_callouts(scan_results)
    findings   = _extract_findings(scan_results)
    hosts      = scan_results.get("hosts", [])
    summary    = scan_results.get("summary", {})

    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=(PAGE_W, PAGE_H))
    c.setTitle(f"Cyber Risk Assessment — {client_name}")
    c.setAuthor(brand_name)
    c.setSubject("Network Cyber Risk Assessment — Summary Report")

    # ── Page 1: Cover ──────────────────────────────────────────────────────
    _draw_cover(c, PAGE_W, PAGE_H, client_name, scan_date,
                risk_score, callouts, company_color, brand_name, tagline)
    c.showPage()

    # ── Page 2: Methods ────────────────────────────────────────────────────
    _draw_methods_page(c, PAGE_W, PAGE_H, scan_results,
                       company_color, brand_name, scan_date)
    c.showPage()

    # ── Pages 3+: Findings ─────────────────────────────────────────────────
    for finding in findings:
        _draw_finding_page(c, PAGE_W, PAGE_H, finding,
                           company_color, brand_name, scan_date)
        c.showPage()

    # ── Device inventory page ──────────────────────────────────────────────
    _draw_inventory_page(c, PAGE_W, PAGE_H, hosts, summary,
                         company_color, brand_name, scan_date)
    c.showPage()

    # ── Final observations page ────────────────────────────────────────────
    _draw_final_page(c, PAGE_W, PAGE_H, company_color,
                     brand_name, tagline, scan_date, client_name)
    c.showPage()

    c.save()
    return buf.getvalue()


def build_client_detail_pdf(scan_results: dict, config: dict) -> bytes:
    """
    Build and return the client-facing Detail Report PDF as bytes.
    Contains full per-device technical findings.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab is required for PDF reports. "
            "Install it: pip install reportlab"
        )

    from reportlab.pdfgen import canvas as rl_canvas

    reporting     = config.get("reporting", {})
    brand_name    = reporting.get("company_name", "Yeyland Wutani LLC")
    company_color = reporting.get("company_color", "#FF6600")
    client_name   = reporting.get("client_name") or infer_client_name(scan_results)

    scan_start = scan_results.get("scan_start", "")
    try:
        dt = datetime.fromisoformat(scan_start)
        scan_date = dt.strftime("%m/%d/%Y")
    except Exception:
        scan_date = datetime.now().strftime("%m/%d/%Y")

    col   = _hex(company_color)
    hosts = scan_results.get("hosts", [])
    buf   = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=(PAGE_W, PAGE_H))
    c.setTitle(f"Cyber Risk Assessment — Detail Report — {client_name}")
    c.setAuthor(brand_name)

    # ── Cover page (simple) ────────────────────────────────────────────────
    c.setFillColor(col)
    c.rect(0, PAGE_H - 120, PAGE_W, 120, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(PAGE_W / 2, PAGE_H - 56, "DETAIL REPORT")
    c.setFont("Helvetica", 11)
    c.setFillColor(_hex("#ffffffcc"))
    c.drawCentredString(PAGE_W / 2, PAGE_H - 76, "PREPARED FOR")
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(PAGE_W / 2, PAGE_H - 100, client_name)
    _draw_content_footer(c, PAGE_W, scan_date, brand_name)
    c.showPage()

    # ── Device inventory ───────────────────────────────────────────────────
    _draw_detail_device_list(c, PAGE_W, PAGE_H, hosts, scan_results,
                             col, brand_name, scan_date)

    # ── Per-device security details (one page per device with findings) ────
    devices_with_flags = [h for h in hosts if h.get("security_flags")]
    if devices_with_flags:
        _draw_detail_security(c, PAGE_W, PAGE_H, devices_with_flags,
                              col, brand_name, scan_date)

    # ── SSL audit detail ───────────────────────────────────────────────────
    ssl_certs = scan_results.get("ssl_audit", {}).get("certificates", [])
    if ssl_certs:
        _draw_detail_ssl(c, PAGE_W, PAGE_H, ssl_certs, col, brand_name, scan_date)

    # ── WiFi detail ────────────────────────────────────────────────────────
    wifi_nets = scan_results.get("wifi", {}).get("networks", [])
    if wifi_nets:
        _draw_detail_wifi(c, PAGE_W, PAGE_H, wifi_nets, col, brand_name, scan_date)

    c.save()
    return buf.getvalue()


# ── Detail report helpers ─────────────────────────────────────────────────────

def _draw_detail_header(c, pw: float, ph: float, title: str, subtitle: str,
                        col: "HexColor", scan_date: str) -> float:
    """Draw standard detail page header. Returns y below header."""
    c.setFillColor(col)
    c.rect(0, ph - 55, pw, 55, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(MARGIN, ph - 30, "DETAIL REPORT")
    c.setFont("Helvetica", 10)
    c.setFillColor(_hex("#ffffffcc"))
    c.drawString(MARGIN, ph - 46, subtitle)
    c.drawRightString(pw - MARGIN, ph - 30, scan_date)
    return ph - 70


def _draw_detail_device_list(c, pw, ph, hosts, scan_results, col, brand, scan_date):
    """Draw the full device inventory detail pages."""
    y = _draw_detail_header(c, pw, ph, "DETAIL REPORT", "Devices Evaluated", col, scan_date)

    recon = scan_results.get("reconnaissance", {})
    summary = scan_results.get("summary", {})

    # Scan overview
    c.setFillColor(_hex("#212529"))
    c.setFont("Helvetica-Bold", 12)
    c.drawString(MARGIN, y, "Computers and Devices Evaluated")
    c.setFont("Helvetica", 9)
    c.setFillColor(_hex("#555555"))
    c.drawString(MARGIN, y - 14,
                 "The following devices were identified during this network scan.")
    y -= 30

    # Device table
    from reportlab.platypus import Table as RLTable

    rows = [["IP ADDRESS", "HOSTNAME", "MAC ADDRESS", "VENDOR", "CATEGORY", "OPEN PORTS"]]
    for h in sorted(hosts, key=lambda x: x.get("ip", "")):
        rows.append([
            h.get("ip", ""),
            (h.get("hostname") or "N/A")[:20],
            h.get("mac", "")[:17],
            (h.get("vendor") or "Unknown")[:22],
            (h.get("category") or "Unknown")[:22],
            str(len(h.get("open_ports", []))),
        ])

    style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), col),
        ("TEXTCOLOR",     (0, 0), (-1, 0), white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 7.5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_hex("#f8f9fa"), white]),
        ("GRID",          (0, 0), (-1, -1), 0.4, _hex("#cccccc")),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ])
    cws = [CONTENT_W * p for p in [0.15, 0.17, 0.15, 0.20, 0.20, 0.13]]
    tbl = RLTable(rows, colWidths=cws, style=style, repeatRows=1)
    tbl.wrapOn(c, CONTENT_W, ph)

    # Paginate
    row_h = tbl._height / len(rows) if rows else 15
    rows_per_page = int((y - FOOTER_H - 10) / row_h)
    data_chunks = [rows[1:][i:i + rows_per_page]
                   for i in range(0, len(rows) - 1, rows_per_page)]

    for idx, chunk in enumerate(data_chunks):
        if idx > 0:
            _draw_content_footer(c, pw, scan_date, brand)
            c.showPage()
            y = _draw_detail_header(c, pw, ph, "DETAIL REPORT",
                                     "Devices Evaluated (continued)", col, scan_date)
        chunk_tbl = RLTable([rows[0]] + chunk, colWidths=cws, style=style, repeatRows=1)
        chunk_tbl.wrapOn(c, CONTENT_W, ph)
        chunk_tbl.drawOn(c, MARGIN, y - chunk_tbl._height)

    # End the last page cleanly
    _draw_content_footer(c, pw, scan_date, brand)
    c.showPage()


def _draw_detail_security(c, pw, ph, devices, col, brand, scan_date):
    """Draw per-device security flags."""
    from reportlab.platypus import Table as RLTable

    y = _draw_detail_header(c, pw, ph, "DETAIL REPORT", "Security Observations", col, scan_date)

    for host in devices:
        if y < FOOTER_H + 80:
            _draw_content_footer(c, pw, scan_date, brand)
            c.showPage()
            y = _draw_detail_header(c, pw, ph, "DETAIL REPORT",
                                     "Security Observations (continued)", col, scan_date)

        ip = host.get("ip", "")
        name = host.get("hostname") or host.get("category", "Device")
        flags = host.get("security_flags", [])

        c.setFillColor(_hex("#343a40"))
        c.setFont("Helvetica-Bold", 10)
        c.drawString(MARGIN, y, f"{ip}  —  {name}")
        c.setFont("Helvetica", 8)
        c.setFillColor(_hex("#666666"))
        c.drawString(MARGIN, y - 11,
                     f"Category: {host.get('category', 'Unknown')}  |  "
                     f"Open Ports: {len(host.get('open_ports', []))}  |  "
                     f"OS: {host.get('os_guess') or 'Unknown'}")
        y -= 22

        rows = [["SEVERITY", "FINDING"]]
        for f in flags:
            rows.append([f.get("severity", ""), (f.get("flag") or "")[:90]])

        style = TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), col),
            ("TEXTCOLOR",     (0, 0), (-1, 0), white),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_hex("#f8f9fa"), white]),
            ("GRID",          (0, 0), (-1, -1), 0.4, _hex("#cccccc")),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            # Color severity cells
            *[("TEXTCOLOR", (0, i + 1), (0, i + 1),
               _hex(RISK_FLAG_COLORS.get(rows[i + 1][0], "#333333")))
              for i in range(len(rows) - 1)],
            ("FONTNAME",      (0, 1), (0, -1), "Helvetica-Bold"),
        ])
        tbl = RLTable(rows, colWidths=[CONTENT_W * 0.12, CONTENT_W * 0.88],
                      style=style)
        tbl.wrapOn(c, CONTENT_W, 300)
        tbl.drawOn(c, MARGIN, y - tbl._height)
        y -= tbl._height + 14

    _draw_content_footer(c, pw, scan_date, brand)
    c.showPage()


def _draw_detail_ssl(c, pw, ph, certs, col, brand, scan_date):
    """Draw SSL certificate detail page."""
    from reportlab.platypus import Table as RLTable

    y = _draw_detail_header(c, pw, ph, "DETAIL REPORT", "SSL/TLS Certificates", col, scan_date)
    c.setFillColor(_hex("#212529"))
    c.setFont("Helvetica-Bold", 12)
    c.drawString(MARGIN, y, "SSL/TLS Certificate Inventory")
    y -= 20

    rows = [["IP", "HOSTNAME", "PORT", "ISSUER", "DAYS LEFT", "ISSUES"]]
    for cert in certs:
        dr = cert.get("days_remaining")
        if dr is None:
            dr_str = "N/A"
        elif dr < 0:
            dr_str = "EXPIRED"
        else:
            dr_str = str(dr)
        issues = "; ".join(cert.get("issues", []))[:40] or ("Self-Signed" if cert.get("is_self_signed") else "OK")
        rows.append([
            cert.get("ip", ""),
            (cert.get("hostname") or "N/A")[:18],
            str(cert.get("port", "")),
            (cert.get("issuer_org") or cert.get("issuer_cn") or "Unknown")[:22],
            dr_str,
            issues[:40],
        ])

    style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), col),
        ("TEXTCOLOR",     (0, 0), (-1, 0), white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_hex("#f8f9fa"), white]),
        ("GRID",          (0, 0), (-1, -1), 0.4, _hex("#cccccc")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
    ])
    cws = [CONTENT_W * p for p in [0.12, 0.17, 0.07, 0.22, 0.10, 0.32]]
    tbl = RLTable(rows, colWidths=cws, style=style, repeatRows=1)
    tbl.wrapOn(c, CONTENT_W, 400)
    tbl.drawOn(c, MARGIN, y - tbl._height)

    _draw_content_footer(c, pw, scan_date, brand)
    c.showPage()


def _draw_detail_wifi(c, pw, ph, networks, col, brand, scan_date):
    """Draw WiFi networks detail page."""
    from reportlab.platypus import Table as RLTable

    y = _draw_detail_header(c, pw, ph, "DETAIL REPORT", "Wireless Networks", col, scan_date)
    c.setFillColor(_hex("#212529"))
    c.setFont("Helvetica-Bold", 12)
    c.drawString(MARGIN, y, f"Wireless Networks Detected  ({len(networks)} total)")
    y -= 20

    rows = [["SSID", "BSSID", "SECURITY", "SIGNAL (dBm)", "BAND/CHANNEL"]]
    for n in sorted(networks, key=lambda x: x.get("signal_dbm", -100) or -100, reverse=True):
        band = n.get("band", "")
        ch   = n.get("channel", "")
        band_ch = f"{band} / Ch {ch}" if band and ch else (band or ch or "")
        sec = n.get("security") or "OPEN"
        rows.append([
            (n.get("ssid") or "(hidden)")[:30],
            (n.get("bssid") or "")[:17],
            sec[:18],
            str(n.get("signal_dbm", "")),
            band_ch[:16],
        ])

    style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), col),
        ("TEXTCOLOR",     (0, 0), (-1, 0), white),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_hex("#f8f9fa"), white]),
        ("GRID",          (0, 0), (-1, -1), 0.4, _hex("#cccccc")),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
    ])
    cws = [CONTENT_W * p for p in [0.28, 0.20, 0.18, 0.15, 0.19]]
    tbl = RLTable(rows[:50], colWidths=cws, style=style, repeatRows=1)
    tbl.wrapOn(c, CONTENT_W, 400)
    tbl.drawOn(c, MARGIN, y - tbl._height)

    _draw_content_footer(c, pw, scan_date, brand)
    c.showPage()
