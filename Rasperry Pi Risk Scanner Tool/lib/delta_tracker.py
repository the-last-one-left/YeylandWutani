#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
delta_tracker.py - Scan-to-scan diff and trend analysis

Computes differences between consecutive scan results to track
new findings, resolved findings, and recurring issues over time.
"""

import gzip
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

HISTORY_DIR = Path("/opt/risk-scanner/data/history")


def load_previous_scan(data_dir: Path = HISTORY_DIR) -> Optional[dict]:
    """
    Load the most recent scan archive from data/history/ (excluding any
    scan that might be in-progress). Returns None if no prior scan found.
    """
    data_dir = Path(data_dir)
    if not data_dir.exists():
        return None

    scan_files = sorted(data_dir.glob("scan_*.json.gz"))
    if not scan_files:
        return None

    # Load the most recent file
    for path in reversed(scan_files):
        try:
            with gzip.open(path, "rt", encoding="utf-8") as f:
                data = json.load(f)
            logger.info(f"Loaded previous scan: {path.name}")
            return data
        except Exception as e:
            logger.warning(f"Could not load {path.name}: {e}")
            continue

    return None


def _extract_host_findings(host: dict) -> set:
    """
    Return a frozenset of finding identifiers for a host.
    Used to compare findings between scans.
    """
    findings = set()

    # CVE matches
    for cve in host.get("cve_matches", []):
        cve_id = cve.get("cve_id", "")
        if cve_id:
            findings.add(f"CVE:{cve_id}")

    # Security flags — use type+description as key
    for flag in host.get("security_flags", []):
        ftype = flag.get("type", "")
        fdesc = flag.get("description", "")[:80]
        key = f"FLAG:{ftype}:{fdesc}"
        findings.add(key)

    # SSH config issues
    ssh = host.get("ssh_config_audit", {})
    if ssh.get("permit_root_login"):
        findings.add("SSH:permit_root_login")
    if ssh.get("password_auth"):
        findings.add("SSH:password_auth_enabled")
    if ssh.get("weak_ciphers"):
        findings.add("SSH:weak_ciphers")
    if ssh.get("protocol_v1"):
        findings.add("SSH:protocol_v1")

    # Patch staleness
    patch = host.get("patch_status", {})
    days = patch.get("days_since_update", 0) or 0
    if days > 90:
        findings.add("PATCH:stale_90d")

    # Windows firewall disabled
    fw = host.get("windows_firewall", {})
    for profile, state in fw.items():
        if isinstance(state, str) and "disabled" in state.lower():
            findings.add(f"FIREWALL:{profile}_disabled")

    # AV missing/stale
    av = host.get("antivirus", {})
    if av.get("status") in ("missing", "stale"):
        findings.add(f"AV:{av.get('status', 'issue')}")

    return findings


def compute_delta(current_results: dict, previous_results: Optional[dict]) -> dict:
    """
    Compute scan-to-scan diff.
    Returns delta dict with new/resolved/recurring findings, host changes,
    risk score delta, and new KEV CVE matches.
    """
    if not previous_results:
        return {
            "has_previous": False,
            "new_hosts": [],
            "removed_hosts": [],
            "new_findings": {},
            "resolved_findings": {},
            "recurring_findings": {},
            "risk_score_delta": 0,
            "new_kev_cves": [],
            "summary": "First scan — no previous data for comparison.",
        }

    current_hosts = {h["ip"]: h for h in current_results.get("hosts", [])}
    prev_hosts = {h["ip"]: h for h in previous_results.get("hosts", [])}

    current_ips = set(current_hosts.keys())
    prev_ips = set(prev_hosts.keys())

    new_hosts = sorted(current_ips - prev_ips)
    removed_hosts = sorted(prev_ips - current_ips)

    new_findings = {}
    resolved_findings = {}
    recurring_findings = {}
    new_kev_cves = []

    # Per-host finding diff for hosts seen in both scans
    for ip in current_ips & prev_ips:
        curr_findings = _extract_host_findings(current_hosts[ip])
        prev_findings = _extract_host_findings(prev_hosts[ip])

        new_f = curr_findings - prev_findings
        resolved_f = prev_findings - curr_findings
        recurring_f = curr_findings & prev_findings

        if new_f:
            new_findings[ip] = sorted(new_f)
        if resolved_f:
            resolved_findings[ip] = sorted(resolved_f)
        if recurring_f:
            recurring_findings[ip] = sorted(recurring_f)

    # New hosts also contribute new findings
    for ip in new_hosts:
        f = _extract_host_findings(current_hosts[ip])
        if f:
            new_findings[ip] = sorted(f)

    # Removed hosts' findings are "resolved" (host gone offline)
    for ip in removed_hosts:
        f = _extract_host_findings(prev_hosts[ip])
        if f:
            resolved_findings[ip] = sorted(f)

    # KEV CVEs: find any new KEV matches not in previous scan
    prev_kev_set = set()
    for h in previous_results.get("hosts", []):
        for cve in h.get("cve_matches", []):
            if cve.get("kev"):
                prev_kev_set.add(f"{h['ip']}:{cve.get('cve_id', '')}")

    for h in current_results.get("hosts", []):
        for cve in h.get("cve_matches", []):
            if cve.get("kev"):
                key = f"{h['ip']}:{cve.get('cve_id', '')}"
                if key not in prev_kev_set:
                    new_kev_cves.append({
                        "ip": h["ip"],
                        "hostname": h.get("hostname", ""),
                        "cve_id": cve.get("cve_id", ""),
                        "product": cve.get("product", ""),
                        "required_action": cve.get("kev_required_action", ""),
                    })

    # Risk score delta
    curr_env_score = current_results.get("risk", {}).get("environment_score", 0)
    prev_env_score = previous_results.get("risk", {}).get("environment_score", 0)
    risk_delta = curr_env_score - prev_env_score

    delta = {
        "has_previous": True,
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "recurring_findings": recurring_findings,
        "risk_score_delta": risk_delta,
        "new_kev_cves": new_kev_cves,
        "summary": format_delta_summary({
            "has_previous": True,
            "new_hosts": new_hosts,
            "removed_hosts": removed_hosts,
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "new_kev_cves": new_kev_cves,
            "risk_score_delta": risk_delta,
        }),
    }

    logger.info(
        f"Delta computed: +{len(new_hosts)} hosts, -{len(removed_hosts)} hosts, "
        f"{sum(len(v) for v in new_findings.values())} new findings, "
        f"{sum(len(v) for v in resolved_findings.values())} resolved, "
        f"{len(new_kev_cves)} new KEV CVEs"
    )
    return delta


def format_delta_summary(delta: dict) -> str:
    """Return a one-line summary string for email subject line."""
    if not delta.get("has_previous"):
        return "First scan complete"

    parts = []
    new_finding_count = sum(len(v) for v in delta.get("new_findings", {}).values())
    resolved_count = sum(len(v) for v in delta.get("resolved_findings", {}).values())
    kev_count = len(delta.get("new_kev_cves", []))
    new_hosts = len(delta.get("new_hosts", []))
    removed_hosts = len(delta.get("removed_hosts", []))

    if kev_count:
        parts.append(f"⚠ {kev_count} new KEV CVE{'s' if kev_count > 1 else ''}")
    if new_finding_count:
        parts.append(f"{new_finding_count} new issue{'s' if new_finding_count > 1 else ''}")
    if resolved_count:
        parts.append(f"{resolved_count} resolved")
    if new_hosts:
        parts.append(f"{new_hosts} new host{'s' if new_hosts > 1 else ''}")
    if removed_hosts:
        parts.append(f"{removed_hosts} host{'s' if removed_hosts > 1 else ''} offline")

    risk_delta = delta.get("risk_score_delta", 0)
    if abs(risk_delta) >= 5:
        arrow = "↑" if risk_delta > 0 else "↓"
        parts.append(f"risk {arrow}{abs(risk_delta)}")

    return " | ".join(parts) if parts else "No changes since last scan"


def get_trend_data(data_dir: Path = HISTORY_DIR, weeks: int = 12) -> list:
    """
    Return [{date, risk_score, critical_count, high_count, kev_count}, ...]
    for the last `weeks` weekly scans, for trend chart rendering.
    Loads the most recent scan file per week.
    """
    data_dir = Path(data_dir)
    if not data_dir.exists():
        return []

    scan_files = sorted(data_dir.glob("scan_*.json.gz"), reverse=True)
    if not scan_files:
        return []

    trend = []
    seen_weeks = set()
    max_files = weeks * 7  # at most 1 scan per day for `weeks` weeks

    for path in scan_files[:max_files]:
        try:
            with gzip.open(path, "rt", encoding="utf-8") as f:
                data = json.load(f)

            scan_start = data.get("scan_start", "")
            if not scan_start:
                continue

            dt = datetime.fromisoformat(scan_start.replace("Z", "+00:00"))
            week_key = dt.strftime("%Y-W%W")

            if week_key in seen_weeks:
                continue
            seen_weeks.add(week_key)

            risk = data.get("risk", {})
            hosts = data.get("hosts", [])

            critical_count = sum(1 for h in hosts if h.get("risk_level") == "CRITICAL")
            high_count = sum(1 for h in hosts if h.get("risk_level") == "HIGH")
            kev_count = sum(
                1 for h in hosts
                for cve in h.get("cve_matches", [])
                if cve.get("kev")
            )

            trend.append({
                "date": dt.strftime("%Y-%m-%d"),
                "week": week_key,
                "risk_score": risk.get("environment_score", 0),
                "critical_count": critical_count,
                "high_count": high_count,
                "kev_count": kev_count,
            })

        except Exception as e:
            logger.debug(f"Could not parse trend data from {path.name}: {e}")
            continue

        if len(trend) >= weeks:
            break

    # Return chronological order
    trend.reverse()
    return trend
