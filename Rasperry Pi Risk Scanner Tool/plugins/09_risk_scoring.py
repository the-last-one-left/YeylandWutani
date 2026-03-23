#!/usr/bin/env python3
"""
Plugin: Risk Scoring  (Phase 9)
Calculate a composite risk score for each host and a network-wide
aggregate score based on CVE findings, compliance failures, open ports,
credential coverage, and KEV hits.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_RISK

log = logging.getLogger("plugin.risk_scoring")

# ── Scoring weights (all configurable via config["risk_weights"]) ──────────
_DEFAULTS = {
    "cve_critical":     40,   # per critical CVE
    "cve_high":         20,   # per high CVE
    "cve_medium":        8,   # per medium CVE
    "cve_low":           2,   # per low CVE
    "kev_multiplier":    2.0, # multiply CVE score if it is a KEV entry
    "compliance_fail":   5,   # per compliance FAIL
    "no_credential":    10,   # host not audited (no cred)
    "risky_port":        5,   # per risky open port
    "risky_ports": [21, 23, 25, 53, 111, 135, 137, 139, 389, 445,
                    512, 513, 514, 1433, 1521, 2049, 3306, 3389,
                    4444, 5432, 5900, 6379, 8080, 8443, 9200, 27017],
    "host_score_cap":  500,
}

_RISK_BANDS = [
    ("CRITICAL", 200),
    ("HIGH",     100),
    ("MEDIUM",    50),
    ("LOW",        0),
]


def _band(score: float) -> str:
    for label, threshold in _RISK_BANDS:
        if score >= threshold:
            return label
    return "LOW"


def _score_host(host: dict, weights: dict) -> dict:
    breakdown: dict = {
        "cve_score":        0,
        "compliance_score": 0,
        "port_score":       0,
        "no_cred_penalty":  0,
    }
    risky_ports = set(weights.get("risky_ports", _DEFAULTS["risky_ports"]))
    kev_mult    = float(weights.get("kev_multiplier", _DEFAULTS["kev_multiplier"]))

    # CVE contributions
    for cve in host.get("cves", []):
        sev   = cve.get("severity", "LOW")
        base  = weights.get(f"cve_{sev.lower()}", _DEFAULTS.get(f"cve_{sev.lower()}", 0))
        mult  = kev_mult if cve.get("kev") else 1.0
        breakdown["cve_score"] += base * mult

    # Compliance failures
    compliance = host.get("compliance", {})
    n_fail = compliance.get("failed", 0)
    breakdown["compliance_score"] = n_fail * weights.get("compliance_fail", _DEFAULTS["compliance_fail"])

    # Risky open ports
    open_ports = {p["port"] for p in host.get("ports", [])}
    risky_open = open_ports & risky_ports
    breakdown["port_score"] = len(risky_open) * weights.get("risky_port", _DEFAULTS["risky_port"])
    breakdown["risky_ports_open"] = sorted(risky_open)

    # No-credential penalty
    ssh_ok = host.get("ssh", {}).get("success", False)
    wmi_ok = host.get("wmi", {}).get("success", False)
    if not ssh_ok and not wmi_ok:
        breakdown["no_cred_penalty"] = weights.get("no_credential", _DEFAULTS["no_credential"])

    raw = sum([
        breakdown["cve_score"],
        breakdown["compliance_score"],
        breakdown["port_score"],
        breakdown["no_cred_penalty"],
    ])
    capped = min(raw, weights.get("host_score_cap", _DEFAULTS["host_score_cap"]))
    return {
        "score":     round(capped, 1),
        "level":     _band(capped),
        "breakdown": breakdown,
    }


class RiskScoringPlugin(ScanPlugin):
    plugin_id   = "risk_scoring"
    name        = "Risk Scoring"
    category    = CAT_RISK
    phase       = 9
    description = (
        "Calculate a composite risk score per host and a network-wide aggregate "
        "based on CVE findings, compliance failures, open risky ports, and "
        "credential coverage gaps."
    )
    version     = "1.0.0"
    author      = "AWN"
    requires    = ["host_discovery"]

    def run(self, ctx: PluginContext) -> None:
        weights = {**_DEFAULTS, **ctx.config.get("risk_weights", {})}

        total_score   = 0.0
        level_counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        kev_hosts:  list[str] = []
        crit_hosts: list[str] = []

        for host in ctx.hosts:
            result = _score_host(host, weights)
            host["risk_score"] = result["score"]
            host["risk_level"] = result["level"]
            host["risk_breakdown"] = result["breakdown"]
            total_score += result["score"]
            level_counts[result["level"]] = level_counts.get(result["level"], 0) + 1

            if any(c.get("kev") for c in host.get("cves", [])):
                kev_hosts.append(host["ip"])
            if result["level"] == "CRITICAL":
                crit_hosts.append(host["ip"])

        n = len(ctx.hosts)
        network_score = round(total_score / n, 1) if n > 0 else 0.0
        network_level = _band(network_score)

        ctx.scan_results["risk"] = {
            "score":          network_score,
            "level":          network_level,
            "breakdown":      level_counts,
            "kev_hosts":      kev_hosts,
            "critical_hosts": crit_hosts,
        }

        ctx.sync_hosts()
        log.info(
            f"Risk scoring complete: network score={network_score} ({network_level}) | "
            f"CRIT={level_counts['CRITICAL']} HIGH={level_counts['HIGH']} "
            f"MED={level_counts['MEDIUM']} LOW={level_counts['LOW']}"
        )
