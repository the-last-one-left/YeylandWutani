#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
risk_scorer.py - Per-host and environment risk scoring

Scores hosts 0-100 based on security findings.
Scores the overall environment 0-100 using weighted host scores.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Point weights ──────────────────────────────────────────────────────────
# Caps prevent single issue from dominating score

FINDING_WEIGHTS = {
    "kev_cve":              (100, 3),   # (pts each, max count)
    "cvss_critical":        (80, 5),
    "cvss_high":            (50, 10),
    "cvss_medium":          (20, 20),
    "default_credentials":  (90, 1),
    "eol_os":               (60, 1),
    "telnet_open":          (55, 1),
    "http_admin":           (40, 1),
    "ssh_root_login":       (35, 1),
    "windows_patches_stale":(30, 1),
    "smb_unauthenticated":  (30, 1),
    "ssl_expired":          (25, 1),
    "antivirus_missing":    (25, 1),
    "windows_firewall_off": (20, 1),
    "ssl_self_signed":      (15, 1),
}

# Host criticality multipliers for environment scoring
HOST_CRITICALITY = {
    "Windows Server":         3.0,
    "Linux/Unix Server":      3.0,
    "Domain Controller":      3.0,
    "Database Server":        3.0,
    "Hypervisor":             3.0,
    "Server":                 3.0,
    "Firewall":               2.0,
    "Network Switch":         2.0,
    "Network Infrastructure": 2.0,
    "Wireless Access Point":  2.0,
    "NAS / Storage":          2.0,
    "Windows Workstation":    2.0,
    "Windows Device":         2.0,
    "VoIP Phone":             1.0,
    "IP Camera / NVR":        1.0,
    "Printer":                1.0,
    "UPS / Power Device":     1.0,
    "IoT Device":             1.0,
    "Raspberry Pi":           1.0,
    "Apple Device":           1.0,
    "Unknown Device":         1.0,
}

# Risk level thresholds
RISK_CRITICAL_THRESHOLD = 80
RISK_HIGH_THRESHOLD     = 60
RISK_MEDIUM_THRESHOLD   = 40


def score_host(host_data: dict) -> int:
    """
    Score a single host 0-100 based on its security findings.
    Returns integer score (higher = worse risk).
    """
    total_points = 0
    max_points = 100

    cve_matches = host_data.get("cve_matches", [])
    security_flags = host_data.get("security_flags", [])
    open_ports = host_data.get("open_ports", [])
    ssh_config = host_data.get("ssh_config_audit", {})
    patch_status = host_data.get("patch_status", {})
    windows_firewall = host_data.get("windows_firewall", {})
    antivirus = host_data.get("antivirus", {})
    smb_shares = host_data.get("smb_shares", [])

    # ── CVE scoring ────────────────────────────────────────────────────────
    kev_count = 0
    critical_count = 0
    high_count = 0
    medium_count = 0

    for cve in cve_matches:
        score = cve.get("cvss_v3_score") or cve.get("cvss_v2_score") or 0
        if cve.get("kev"):
            kev_count += 1
        elif score >= 9.0:
            critical_count += 1
        elif score >= 7.0:
            high_count += 1
        elif score >= 4.0:
            medium_count += 1

    pts, cap = FINDING_WEIGHTS["kev_cve"]
    total_points += pts * min(kev_count, cap)

    pts, cap = FINDING_WEIGHTS["cvss_critical"]
    total_points += pts * min(critical_count, cap)

    pts, cap = FINDING_WEIGHTS["cvss_high"]
    total_points += pts * min(high_count, cap)

    pts, cap = FINDING_WEIGHTS["cvss_medium"]
    total_points += pts * min(medium_count, cap)

    # ── Port-based flags ───────────────────────────────────────────────────
    ports_set = set(open_ports)

    if 23 in ports_set:
        pts, _ = FINDING_WEIGHTS["telnet_open"]
        total_points += pts

    # ── Security flags from scan engine ───────────────────────────────────
    flag_descriptions = [f.get("description", "").lower() for f in security_flags]
    flag_types = [f.get("type", "").lower() for f in security_flags]

    for flag in security_flags:
        ftype = flag.get("type", "").lower()
        fdesc = flag.get("description", "").lower()

        if "default_credentials" in ftype or "default credential" in fdesc:
            pts, _ = FINDING_WEIGHTS["default_credentials"]
            total_points += pts

        if "eol" in ftype or "end-of-life" in fdesc or "end of life" in fdesc:
            pts, _ = FINDING_WEIGHTS["eol_os"]
            total_points += pts

        if "http_admin" in ftype or ("admin" in fdesc and "http" in fdesc and "https" not in fdesc):
            pts, _ = FINDING_WEIGHTS["http_admin"]
            total_points += pts

    # ── SSH config audit ───────────────────────────────────────────────────
    if ssh_config.get("permit_root_login"):
        pts, _ = FINDING_WEIGHTS["ssh_root_login"]
        total_points += pts

    # ── Windows patch status ───────────────────────────────────────────────
    days_since = patch_status.get("days_since_update", 0) or 0
    if days_since > 90:
        pts, _ = FINDING_WEIGHTS["windows_patches_stale"]
        total_points += pts

    # ── Windows firewall ───────────────────────────────────────────────────
    if windows_firewall:
        for profile_name, state in windows_firewall.items():
            if isinstance(state, str) and "disabled" in state.lower():
                pts, _ = FINDING_WEIGHTS["windows_firewall_off"]
                total_points += pts
                break

    # ── Antivirus ─────────────────────────────────────────────────────────
    if antivirus:
        av_status = antivirus.get("status", "")
        if av_status in ("missing", "stale") or not antivirus.get("product"):
            pts, _ = FINDING_WEIGHTS["antivirus_missing"]
            total_points += pts

    # ── SMB shares (unauthenticated) ───────────────────────────────────────
    for share in smb_shares:
        access = share.get("access", "").lower()
        if "everyone" in access or "unauthenticated" in access or "anonymous" in access:
            pts, _ = FINDING_WEIGHTS["smb_unauthenticated"]
            total_points += pts
            break

    # ── SSL/TLS issues ────────────────────────────────────────────────────
    ssl_issues = host_data.get("ssl_issues", [])
    for issue in ssl_issues:
        itype = issue.get("type", "").lower()
        if "expired" in itype:
            pts, _ = FINDING_WEIGHTS["ssl_expired"]
            total_points += pts
        elif "self_signed" in itype or "self-signed" in itype:
            pts, _ = FINDING_WEIGHTS["ssl_self_signed"]
            total_points += pts

    return min(total_points, max_points)


def score_environment(all_hosts: list) -> int:
    """
    Compute weighted environment risk score 0-100.

    - Each host's score is weighted by its criticality tier.
    - Breadth penalty: % of hosts with at least one HIGH+ finding.
    - Returns 0-100 integer.
    """
    if not all_hosts:
        return 0

    total_weighted_score = 0.0
    total_weight = 0.0
    high_plus_count = 0

    for host in all_hosts:
        risk_score = host.get("risk_score", 0)
        category = host.get("category", "Unknown Device")
        weight = HOST_CRITICALITY.get(category, 1.0)

        total_weighted_score += risk_score * weight
        total_weight += weight

        if risk_score >= RISK_HIGH_THRESHOLD:
            high_plus_count += 1

    if total_weight == 0:
        return 0

    base_score = total_weighted_score / total_weight

    # Breadth penalty: up to +15 pts if >50% of hosts have HIGH+ risk
    breadth_pct = high_plus_count / len(all_hosts)
    breadth_penalty = min(15.0, breadth_pct * 30.0)

    env_score = base_score + breadth_penalty
    return min(int(env_score), 100)


def classify_host_risk(score: int) -> str:
    """Return CRITICAL / HIGH / MEDIUM / LOW based on risk score."""
    if score >= RISK_CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score >= RISK_HIGH_THRESHOLD:
        return "HIGH"
    if score >= RISK_MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def get_risk_summary(all_hosts: list) -> dict:
    """
    Return summary counts by severity and top 10 risk items across environment.
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    top_risks = []

    for host in all_hosts:
        level = host.get("risk_level", classify_host_risk(host.get("risk_score", 0)))
        counts[level] = counts.get(level, 0) + 1

        ip = host.get("ip", "?")
        hostname = host.get("hostname", "")
        label = f"{ip} ({hostname})" if hostname else ip

        for cve in host.get("cve_matches", [])[:3]:
            cve_id = cve.get("cve_id", "?")
            score = cve.get("cvss_v3_score") or cve.get("cvss_v2_score") or 0
            kev = cve.get("kev", False)
            top_risks.append({
                "host": label,
                "type": "CVE",
                "detail": cve_id,
                "score": score,
                "severity": cve.get("severity", format_cvss_severity(score)),
                "kev": kev,
                "host_risk_score": host.get("risk_score", 0),
            })

        for flag in host.get("security_flags", [])[:2]:
            sev = flag.get("severity", "INFO")
            if sev in ("HIGH", "CRITICAL"):
                top_risks.append({
                    "host": label,
                    "type": "Finding",
                    "detail": flag.get("description", ""),
                    "score": {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0}.get(sev, 0),
                    "severity": sev,
                    "kev": False,
                    "host_risk_score": host.get("risk_score", 0),
                })

    # Sort: KEV first, then by CVSS score, then by host risk score
    top_risks.sort(
        key=lambda x: (not x["kev"], -x["score"], -x["host_risk_score"])
    )

    return {
        "counts_by_severity": counts,
        "top_10_risks": top_risks[:10],
        "total_hosts": len(all_hosts),
    }


def format_cvss_severity(score: Optional[float]) -> str:
    """Return CRITICAL / HIGH / MEDIUM / LOW / INFO based on CVSS score."""
    if score is None:
        return "INFO"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"
