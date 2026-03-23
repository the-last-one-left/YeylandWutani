#!/usr/bin/env python3
"""
Plugin: Compliance / Hardening Audit  (Phase 8)
Evaluate each host against CIS-inspired hardening rules loaded from
YAML check definitions in config/compliance_checks/.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_COMPLIANCE

log = logging.getLogger("plugin.compliance")

_CHECKS_DIR = str(Path(__file__).parent.parent / "config" / "compliance_checks")


# ── YAML check loader ─────────────────────────────────────────────────────

def _load_checks(checks_dir: str) -> list[dict]:
    """
    Load all *.yaml compliance check files from checks_dir.
    Each file is a YAML list of check dicts with fields:
      id, title, category, platform, severity, check_type,
      key, operator, value, remediation
    """
    checks: list[dict] = []
    if not os.path.exists(checks_dir):
        log.warning(f"Compliance checks dir not found: {checks_dir}")
        return checks
    try:
        import yaml  # type: ignore
    except ImportError:
        log.error("PyYAML not installed. Run: pip install pyyaml")
        return checks

    for yaml_file in sorted(Path(checks_dir).glob("*.yaml")):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, list):
                checks.extend(data)
            elif isinstance(data, dict) and "checks" in data:
                checks.extend(data["checks"])
        except Exception as exc:
            log.warning(f"Failed to load {yaml_file.name}: {exc}")

    log.info(f"Loaded {len(checks)} compliance check(s) from {checks_dir}")
    return checks


# ── Check evaluation engine ────────────────────────────────────────────────

def _get_nested(data: dict, dotted_key: str):
    """Retrieve a value from a nested dict using dot-notation keys."""
    parts = dotted_key.split(".")
    cur = data
    for part in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _evaluate_check(check: dict, host: dict) -> dict:
    """
    Run a single check against a host dict.
    Returns a result dict: {id, title, status, severity, actual, expected, remediation}
    status is one of: PASS, FAIL, NOT_APPLICABLE, ERROR
    """
    result = {
        "id":          check.get("id", ""),
        "title":       check.get("title", ""),
        "category":    check.get("category", ""),
        "severity":    check.get("severity", "MEDIUM").upper(),
        "status":      "NOT_APPLICABLE",
        "actual":      None,
        "expected":    check.get("value"),
        "remediation": check.get("remediation", ""),
    }

    platform    = (check.get("platform") or "any").lower()
    check_type  = (check.get("check_type") or "").lower()
    key         = check.get("key", "")
    operator    = (check.get("operator") or "eq").lower()
    expected    = check.get("value")

    # ─ Platform gating ────────────────────────────────────────────────────
    os_guess = (host.get("os_guess") or "").lower()
    ssh_ok   = host.get("ssh", {}).get("success", False)
    wmi_ok   = host.get("wmi", {}).get("success", False)

    if platform == "linux" and not ssh_ok:
        return result  # NOT_APPLICABLE
    if platform == "windows" and not wmi_ok:
        return result
    if platform not in ("any", "linux", "windows"):
        return result  # unknown platform

    # ─ Resolve actual value ────────────────────────────────────────────────
    actual = None
    try:
        if check_type == "sshd_config":
            actual = host.get("ssh", {}).get("sshd_config", {}).get(key.lower())
        elif check_type == "ssh_field":
            actual = _get_nested(host.get("ssh", {}), key)
        elif check_type == "wmi_field":
            actual = _get_nested(host.get("wmi", {}), key)
        elif check_type == "snmp_field":
            actual = _get_nested(host.get("snmp", {}), key)
        elif check_type == "host_field":
            actual = _get_nested(host, key)
        elif check_type == "package_absent":
            packages = [p.get("name", "").lower() for p in host.get("ssh", {}).get("packages", [])]
            actual   = key.lower() in packages
        elif check_type == "package_present":
            packages = [p.get("name", "").lower() for p in host.get("ssh", {}).get("packages", [])]
            actual   = key.lower() in packages
        elif check_type == "user_absent":
            users  = [u.get("username", "") for u in host.get("ssh", {}).get("users", [])]
            actual = key in users
        elif check_type == "port_closed":
            open_ports = [p["port"] for p in host.get("ports", [])]
            actual     = int(key) in open_ports
        elif check_type == "cve_absent":
            cve_ids = [c["cve_id"] for c in host.get("cves", [])]
            actual  = key in cve_ids
        else:
            result["status"] = "ERROR"
            result["actual"] = f"Unknown check_type: {check_type}"
            return result
    except Exception as exc:
        result["status"] = "ERROR"
        result["actual"] = str(exc)
        return result

    result["actual"] = actual

    # ─ Evaluate operator ────────────────────────────────────────────────
    try:
        if actual is None:
            result["status"] = "NOT_APPLICABLE"
            return result

        passed = False
        if operator == "eq":
            passed = str(actual).lower() == str(expected).lower()
        elif operator == "ne":
            passed = str(actual).lower() != str(expected).lower()
        elif operator == "contains":
            passed = str(expected).lower() in str(actual).lower()
        elif operator == "not_contains":
            passed = str(expected).lower() not in str(actual).lower()
        elif operator == "is_true":
            passed = bool(actual) is True
        elif operator == "is_false":
            passed = bool(actual) is False
        elif operator == "lt":
            passed = float(actual) < float(expected)
        elif operator == "gt":
            passed = float(actual) > float(expected)
        elif operator == "lte":
            passed = float(actual) <= float(expected)
        elif operator == "gte":
            passed = float(actual) >= float(expected)
        else:
            result["status"] = "ERROR"
            result["actual"] = f"Unknown operator: {operator}"
            return result

        result["status"] = "PASS" if passed else "FAIL"
    except Exception as exc:
        result["status"] = "ERROR"
        result["actual"] = str(exc)

    return result


def _audit_host(host: dict, checks: list[dict]) -> dict:
    results   = [_evaluate_check(c, host) for c in checks]
    passed    = sum(1 for r in results if r["status"] == "PASS")
    failed    = sum(1 for r in results if r["status"] == "FAIL")
    n_a       = sum(1 for r in results if r["status"] == "NOT_APPLICABLE")
    errors    = sum(1 for r in results if r["status"] == "ERROR")
    total_app = passed + failed
    score     = round((passed / total_app * 100) if total_app > 0 else 0, 1)
    return {
        "checks_run":    len(results),
        "passed":        passed,
        "failed":        failed,
        "not_applicable": n_a,
        "errors":        errors,
        "score_pct":     score,
        "findings":      [r for r in results if r["status"] == "FAIL"],
        "all_results":   results,
    }


class CompliancePlugin(ScanPlugin):
    plugin_id   = "compliance"
    name        = "Compliance / Hardening Audit"
    category    = CAT_COMPLIANCE
    phase       = 8
    description = (
        "Evaluate each host against CIS-inspired hardening rules defined in "
        "config/compliance_checks/*.yaml. Reports PASS/FAIL per control."
    )
    version     = "1.0.0"
    author      = "AWN"
    requires    = ["host_discovery"]

    def run(self, ctx: PluginContext) -> None:
        checks_dir = ctx.config.get("compliance", {}).get("checks_dir", _CHECKS_DIR)
        checks = _load_checks(checks_dir)
        if not checks:
            log.warning("No compliance checks loaded — skipping.")
            return

        total_fail = 0
        for host in ctx.hosts:
            result = _audit_host(host, checks)
            host["compliance"] = result
            total_fail += result["failed"]
            log.debug(
                f"{host['ip']}: compliance {result['score_pct']}% "
                f"({result['passed']} pass, {result['failed']} fail)"
            )

        ctx.sync_hosts()
        log.info(
            f"Compliance audit complete: {total_fail} total failures across "
            f"{len(ctx.hosts)} host(s)."
        )
