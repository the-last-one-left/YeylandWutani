#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
lib/soar_connector.py  --  SOAR / Ticketing System Integration

Supports sending scan findings as tickets or alerts to:
  - Jira          (REST API v3, creates Issues)
  - ServiceNow    (Table API, creates Incidents)
  - Generic Webhook (POST JSON payload to any URL)

Configuration  (in config.json under ["soar"])
----------------------------------------------
  enabled          bool    Master on/off switch
  min_severity     str     Minimum severity to notify: CRITICAL | HIGH | MEDIUM | LOW
  on_kev_only      bool    Only notify for CISA KEV findings (default False)
  deduplicate      bool    Don't re-notify for the same CVE on the same host (default True)
  dedup_cache_file str     Path to dedup state file (default data/soar_sent.json)

  providers        list    List of provider configs (can have multiple active)
    Each provider:
      type         str     "jira" | "servicenow" | "webhook"
      name         str     Human-readable label for logs
      enabled      bool    Enable this specific provider
      [provider-specific fields below]

  Jira:
      url          str     Jira base URL, e.g. https://yourorg.atlassian.net
      email        str     Atlassian account email
      api_token    str     Atlassian API token (or set JIRA_API_TOKEN env var)
      project_key  str     Jira project key, e.g. SEC
      issue_type   str     Issue type (default "Bug")
      priority_map dict    Map AWN severity -> Jira priority name
      labels       list    Labels to add to created issues

  ServiceNow:
      url          str     ServiceNow instance URL, e.g. https://yourorg.service-now.com
      username     str     ServiceNow username
      password     str     ServiceNow password (or set SNOW_PASSWORD env var)
      table        str     Target table (default "incident")
      category     str     Category field value (default "security")
      assignment_group str  Assignment group sys_id or name
      urgency_map  dict    Map AWN severity -> ServiceNow urgency (1=High, 2=Med, 3=Low)

  Webhook:
      url          str     Target webhook URL
      method       str     HTTP method: POST (default) | PUT
      headers      dict    Extra HTTP headers (e.g. Authorization)
      template     str     "default" | "slack" | "teams" | "pagerduty"
"""

from __future__ import annotations

import base64
import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
_SECRET_FIELDS  = ("api_token", "password", "client_secret")


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

class Finding:
    """
    A normalised security finding ready for SOAR notification.
    Built from a CVE match, compliance failure, or risk threshold breach.
    """
    def __init__(
        self,
        source:      str,         # "cve" | "compliance" | "risk"
        host_ip:     str,
        hostname:    str,
        title:       str,
        description: str,
        severity:    str,         # CRITICAL | HIGH | MEDIUM | LOW
        cve_id:      str  = "",
        cvss_score:  float = 0.0,
        kev:         bool  = False,
        remediation: str  = "",
        scan_ts:     str  = "",
    ) -> None:
        self.source      = source
        self.host_ip     = host_ip
        self.hostname    = hostname
        self.title       = title
        self.description = description
        self.severity    = severity.upper()
        self.cve_id      = cve_id
        self.cvss_score  = cvss_score
        self.kev         = kev
        self.remediation = remediation
        self.scan_ts     = scan_ts or datetime.now(timezone.utc).isoformat()

    @property
    def dedup_key(self) -> str:
        """Unique key for deduplication: source:host:cve_or_title."""
        ref = self.cve_id or self.title[:60]
        return f"{self.source}:{self.host_ip}:{ref}"

    def to_dict(self) -> dict:
        return self.__dict__


# ---------------------------------------------------------------------------
# Deduplication cache
# ---------------------------------------------------------------------------

def _load_dedup_cache(cache_path: str) -> set[str]:
    p = Path(cache_path)
    if not p.exists():
        return set()
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        # Prune entries older than 30 days
        cutoff = time.time() - (30 * 86400)
        return {k for k, ts in data.items() if ts > cutoff}
    except Exception:
        return set()


def _save_dedup_cache(cache_path: str, sent_keys: set[str]) -> None:
    p = Path(cache_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    # Load existing to merge
    existing: dict = {}
    if p.exists():
        try:
            with open(p, encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            pass
    now = time.time()
    for k in sent_keys:
        existing[k] = now
    with open(p, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _request(
    url: str,
    method: str = "POST",
    payload: dict | None = None,
    headers: dict | None = None,
    tls_verify: bool = True,
    timeout: int = 15,
) -> tuple[int, dict]:
    """
    Make an HTTP request and return (status_code, response_dict).
    """
    ctx = ssl.create_default_context()
    if not tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

    body = json.dumps(payload).encode() if payload else None
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        hdrs.update(headers)

    req = urllib.request.Request(url, data=body, headers=hdrs, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            try:
                return resp.status, json.loads(resp.read().decode())
            except Exception:
                return resp.status, {}
    except urllib.error.HTTPError as exc:
        try:
            body_text = exc.read().decode()[:500]
        except Exception:
            body_text = ""
        logger.error(f"HTTP {exc.code} from {url}: {body_text}")
        return exc.code, {"error": body_text}
    except Exception as exc:
        logger.error(f"Request to {url} failed: {exc}")
        return 0, {"error": str(exc)}


# ---------------------------------------------------------------------------
# Jira provider
# ---------------------------------------------------------------------------

_JIRA_PRIORITY_MAP = {
    "CRITICAL": "Highest",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
}


class JiraProvider:
    def __init__(self, cfg: dict) -> None:
        self.url          = cfg["url"].rstrip("/")
        self.email        = cfg["email"]
        self.api_token    = cfg.get("api_token", "") or os.environ.get("JIRA_API_TOKEN", "")
        self.project_key  = cfg["project_key"]
        self.issue_type   = cfg.get("issue_type", "Bug")
        self.priority_map = {**_JIRA_PRIORITY_MAP, **cfg.get("priority_map", {})}
        self.labels       = cfg.get("labels", ["risk-scanner", "vulnerability"])
        self.tls_verify   = cfg.get("tls_verify", True)
        self.name         = cfg.get("name", "Jira")

    def _auth_header(self) -> str:
        token = base64.b64encode(
            f"{self.email}:{self.api_token}".encode()
        ).decode()
        return f"Basic {token}"

    def send(self, finding: Finding) -> bool:
        kev_badge = " [CISA KEV]" if finding.kev else ""
        summary   = (
            f"[{finding.severity}]{kev_badge} {finding.cve_id or finding.title} "
            f"on {finding.hostname or finding.host_ip}"
        )[:255]

        desc_parts = [
            f"**Scanner Finding** | {finding.scan_ts}",
            f"",
            f"**Host:** {finding.host_ip} ({finding.hostname})",
            f"**Severity:** {finding.severity}  |  **CVSS:** {finding.cvss_score:.1f}",
        ]
        if finding.cve_id:
            desc_parts.append(f"**CVE:** [{finding.cve_id}](https://nvd.nist.gov/vuln/detail/{finding.cve_id})")
        if finding.kev:
            desc_parts.append("**⚠ CISA Known Exploited Vulnerability**")
        desc_parts += [
            f"",
            f"**Description:**",
            finding.description or "No description available.",
        ]
        if finding.remediation:
            desc_parts += ["", f"**Remediation:**", finding.remediation]

        payload = {
            "fields": {
                "project":     {"key": self.project_key},
                "summary":     summary,
                "description": {
                    "version": 1,
                    "type":    "doc",
                    "content": [{
                        "type":    "paragraph",
                        "content": [{"type": "text", "text": "\n".join(desc_parts)}]
                    }]
                },
                "issuetype":   {"name": self.issue_type},
                "priority":    {"name": self.priority_map.get(finding.severity, "Medium")},
                "labels":      self.labels,
            }
        }

        status, resp = _request(
            f"{self.url}/rest/api/3/issue",
            method  = "POST",
            payload = payload,
            headers = {"Authorization": self._auth_header()},
            tls_verify = self.tls_verify,
        )
        if status in (200, 201):
            logger.info(f"{self.name}: created issue {resp.get('key', '?')} for {finding.dedup_key}")
            return True
        logger.error(f"{self.name}: failed to create issue (HTTP {status}): {resp}")
        return False


# ---------------------------------------------------------------------------
# ServiceNow provider
# ---------------------------------------------------------------------------

_SNOW_URGENCY_MAP = {
    "CRITICAL": 1,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
}


class ServiceNowProvider:
    def __init__(self, cfg: dict) -> None:
        self.url              = cfg["url"].rstrip("/")
        self.username         = cfg["username"]
        self.password         = cfg.get("password", "") or os.environ.get("SNOW_PASSWORD", "")
        self.table            = cfg.get("table", "incident")
        self.category         = cfg.get("category", "security")
        self.assignment_group = cfg.get("assignment_group", "")
        self.urgency_map      = {**_SNOW_URGENCY_MAP, **cfg.get("urgency_map", {})}
        self.tls_verify       = cfg.get("tls_verify", True)
        self.name             = cfg.get("name", "ServiceNow")

    def _auth_header(self) -> str:
        token = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()
        return f"Basic {token}"

    def send(self, finding: Finding) -> bool:
        kev_tag   = " [CISA KEV]" if finding.kev else ""
        short_desc = (
            f"[Risk Scanner] {finding.severity}{kev_tag}: "
            f"{finding.cve_id or finding.title} on {finding.hostname or finding.host_ip}"
        )[:160]

        notes = (
            f"Automated finding from Yeyland Wutani Risk Scanner\n"
            f"Scan Time: {finding.scan_ts}\n"
            f"Host: {finding.host_ip} ({finding.hostname})\n"
            f"Severity: {finding.severity} | CVSS: {finding.cvss_score:.1f}\n"
        )
        if finding.cve_id:
            notes += f"CVE: {finding.cve_id} | https://nvd.nist.gov/vuln/detail/{finding.cve_id}\n"
        if finding.kev:
            notes += "WARNING: This CVE is in the CISA Known Exploited Vulnerabilities catalog.\n"
        notes += f"\nDescription:\n{finding.description or 'N/A'}\n"
        if finding.remediation:
            notes += f"\nRemediation:\n{finding.remediation}\n"

        payload: dict[str, Any] = {
            "short_description": short_desc,
            "description":       notes,
            "category":          self.category,
            "urgency":           str(self.urgency_map.get(finding.severity, 2)),
            "impact":            str(self.urgency_map.get(finding.severity, 2)),
        }
        if self.assignment_group:
            payload["assignment_group"] = self.assignment_group

        status, resp = _request(
            f"{self.url}/api/now/table/{self.table}",
            method     = "POST",
            payload    = payload,
            headers    = {"Authorization": self._auth_header()},
            tls_verify = self.tls_verify,
        )
        if status in (200, 201):
            sys_id = resp.get("result", {}).get("sys_id", "?")
            logger.info(f"{self.name}: created incident {sys_id} for {finding.dedup_key}")
            return True
        logger.error(f"{self.name}: failed to create incident (HTTP {status}): {resp}")
        return False


# ---------------------------------------------------------------------------
# Generic Webhook provider
# ---------------------------------------------------------------------------

def _build_slack_payload(finding: Finding) -> dict:
    color = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22",
             "MEDIUM": "#f1c40f", "LOW": "#2ecc71"}.get(finding.severity, "#95a5a6")
    text  = f"*{finding.severity}* {'\u26a0 KEV' if finding.kev else ''} — "
    text += f"`{finding.cve_id or finding.title}` on `{finding.hostname or finding.host_ip}`"
    return {
        "attachments": [{
            "color":  color,
            "title":  finding.title,
            "text":   text,
            "fields": [
                {"title": "Host",     "value": f"{finding.host_ip} ({finding.hostname})", "short": True},
                {"title": "Severity", "value": finding.severity,  "short": True},
                {"title": "CVSS",     "value": str(finding.cvss_score), "short": True},
                {"title": "CVE",      "value": finding.cve_id or "N/A", "short": True},
            ],
            "footer": "Yeyland Wutani Risk Scanner",
            "ts":     int(time.time()),
        }]
    }


def _build_teams_payload(finding: Finding) -> dict:
    color = {"CRITICAL": "attention", "HIGH": "warning",
             "MEDIUM": "accent",    "LOW": "good"}.get(finding.severity, "default")
    return {
        "type":        "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type":    "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "Medium", "weight": "Bolder",
                     "text": f"{finding.severity} Finding: {finding.cve_id or finding.title}",
                     "color": color},
                    {"type": "FactSet", "facts": [
                        {"title": "Host",     "value": f"{finding.host_ip} ({finding.hostname})"},
                        {"title": "Severity", "value": finding.severity},
                        {"title": "CVSS",     "value": str(finding.cvss_score)},
                        {"title": "KEV",      "value": "Yes" if finding.kev else "No"},
                    ]},
                    {"type": "TextBlock", "wrap": True,
                     "text": (finding.description or "")[:300]},
                ],
                "actions": [{
                    "type":  "Action.OpenUrl",
                    "title": "View CVE",
                    "url":   f"https://nvd.nist.gov/vuln/detail/{finding.cve_id}",
                }] if finding.cve_id else [],
            }
        }]
    }


def _build_pagerduty_payload(finding: Finding) -> dict:
    sev_map = {"CRITICAL": "critical", "HIGH": "error",
               "MEDIUM": "warning",   "LOW": "info"}
    return {
        "routing_key":  "",  # set by caller
        "event_action": "trigger",
        "dedup_key":    finding.dedup_key,
        "payload": {
            "summary":   f"{finding.severity}: {finding.cve_id or finding.title} on {finding.host_ip}",
            "source":    finding.host_ip,
            "severity":  sev_map.get(finding.severity, "warning"),
            "timestamp": finding.scan_ts,
            "custom_details": {
                "hostname":    finding.hostname,
                "cve_id":      finding.cve_id,
                "cvss_score":  finding.cvss_score,
                "kev":         finding.kev,
                "description": (finding.description or "")[:500],
                "remediation": finding.remediation,
            },
        }
    }


class WebhookProvider:
    def __init__(self, cfg: dict) -> None:
        self.url        = cfg["url"]
        self.method     = cfg.get("method", "POST").upper()
        self.headers    = cfg.get("headers", {})
        self.template   = cfg.get("template", "default").lower()
        self.routing_key = cfg.get("routing_key", "")  # PagerDuty
        self.tls_verify = cfg.get("tls_verify", True)
        self.name       = cfg.get("name", "Webhook")

    def send(self, finding: Finding) -> bool:
        if self.template == "slack":
            payload = _build_slack_payload(finding)
        elif self.template == "teams":
            payload = _build_teams_payload(finding)
        elif self.template == "pagerduty":
            payload = _build_pagerduty_payload(finding)
            payload["routing_key"] = self.routing_key
        else:
            payload = finding.to_dict()

        status, resp = _request(
            self.url,
            method     = self.method,
            payload    = payload,
            headers    = self.headers,
            tls_verify = self.tls_verify,
        )
        if 200 <= status < 300:
            logger.info(f"{self.name}: webhook sent for {finding.dedup_key} (HTTP {status})")
            return True
        logger.error(f"{self.name}: webhook failed for {finding.dedup_key} (HTTP {status}): {resp}")
        return False


# ---------------------------------------------------------------------------
# Finding extraction from scan results
# ---------------------------------------------------------------------------

def _severity_rank(s: str) -> int:
    return _SEVERITY_ORDER.index(s.upper()) if s.upper() in _SEVERITY_ORDER else 99


def extract_findings(
    scan_results: dict,
    min_severity: str = "HIGH",
    kev_only: bool = False,
) -> list[Finding]:
    """
    Extract notifiable findings from a completed scan result dict.
    Returns Finding objects sorted by severity descending.
    """
    min_rank = _severity_rank(min_severity)
    findings: list[Finding] = []
    scan_ts  = scan_results.get("scan_end", scan_results.get("scan_start", ""))

    for host in scan_results.get("hosts", []):
        ip       = host.get("ip", "")
        hostname = host.get("hostname", "")

        # CVE findings
        for cve in host.get("cves", []):
            sev = (cve.get("severity") or "LOW").upper()
            if _severity_rank(sev) > min_rank:
                continue
            if kev_only and not cve.get("kev"):
                continue
            findings.append(Finding(
                source      = "cve",
                host_ip     = ip,
                hostname    = hostname,
                title       = f"{cve['cve_id']}: {(cve.get('description') or '')[:80]}",
                description = cve.get("description", ""),
                severity    = sev,
                cve_id      = cve.get("cve_id", ""),
                cvss_score  = float(cve.get("score", 0)),
                kev         = bool(cve.get("kev")),
                scan_ts     = scan_ts,
            ))

        # Compliance failures (severity HIGH or CRITICAL only)
        for chk in host.get("compliance", {}).get("findings", []):
            sev = (chk.get("severity") or "MEDIUM").upper()
            if _severity_rank(sev) > min_rank:
                continue
            findings.append(Finding(
                source      = "compliance",
                host_ip     = ip,
                hostname    = hostname,
                title       = f"Compliance FAIL: {chk.get('title', chk.get('id', '?'))}",
                description = f"Check {chk.get('id','?')} failed. Expected: {chk.get('expected')}, Got: {chk.get('actual')}",
                severity    = sev,
                remediation = chk.get("remediation", ""),
                scan_ts     = scan_ts,
            ))

    findings.sort(key=lambda f: _severity_rank(f.severity))
    return findings


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------

def dispatch_findings(
    scan_results: dict,
    soar_cfg: dict,
    data_dir: str = "/opt/risk-scanner/data",
) -> dict:
    """
    Main entry point: extract findings from scan_results and send to all
    enabled SOAR providers per the soar_cfg configuration.

    Returns a summary dict:
      {
        "total_findings":   int,
        "notifications_sent": int,
        "deduped": int,
        "errors":  int,
        "log":     list[str]
      }
    """
    summary = {"total_findings": 0, "notifications_sent": 0, "deduped": 0, "errors": 0, "log": []}

    if not soar_cfg.get("enabled", False):
        logger.debug("SOAR integration not enabled")
        return summary

    min_sev   = (soar_cfg.get("min_severity") or "HIGH").upper()
    kev_only  = bool(soar_cfg.get("on_kev_only", False))
    dedup     = bool(soar_cfg.get("deduplicate", True))
    dedup_file = soar_cfg.get("dedup_cache_file", str(Path(data_dir) / "soar_sent.json"))

    findings = extract_findings(scan_results, min_severity=min_sev, kev_only=kev_only)
    summary["total_findings"] = len(findings)

    if not findings:
        logger.info("SOAR: no findings meet the notification criteria")
        return summary

    sent_keys: set[str] = set()
    dedup_cache = _load_dedup_cache(dedup_file) if dedup else set()

    # Build provider instances
    providers: list = []
    for p_cfg in soar_cfg.get("providers", []):
        if not p_cfg.get("enabled", True):
            continue
        ptype = (p_cfg.get("type") or "").lower()
        try:
            if ptype == "jira":
                providers.append(JiraProvider(p_cfg))
            elif ptype == "servicenow":
                providers.append(ServiceNowProvider(p_cfg))
            elif ptype == "webhook":
                providers.append(WebhookProvider(p_cfg))
            else:
                logger.warning(f"SOAR: unknown provider type '{ptype}' — skipping")
        except Exception as exc:
            logger.error(f"SOAR: failed to init provider '{ptype}': {exc}")
            summary["errors"] += 1

    if not providers:
        logger.warning("SOAR: no enabled providers configured")
        return summary

    for finding in findings:
        # Deduplication check
        if dedup and finding.dedup_key in dedup_cache:
            logger.debug(f"SOAR: deduped {finding.dedup_key}")
            summary["deduped"] += 1
            continue

        for provider in providers:
            try:
                ok = provider.send(finding)
                if ok:
                    summary["notifications_sent"] += 1
                    sent_keys.add(finding.dedup_key)
                    msg = f"OK  [{provider.name}] {finding.severity} {finding.dedup_key}"
                else:
                    summary["errors"] += 1
                    msg = f"ERR [{provider.name}] {finding.severity} {finding.dedup_key}"
                summary["log"].append(msg)
                logger.info(f"SOAR dispatch: {msg}")
            except Exception as exc:
                summary["errors"] += 1
                msg = f"EXC [{provider.name}] {finding.dedup_key}: {exc}"
                summary["log"].append(msg)
                logger.error(f"SOAR dispatch exception: {msg}")

    # Persist dedup keys
    if dedup and sent_keys:
        _save_dedup_cache(dedup_file, sent_keys)

    logger.info(
        f"SOAR dispatch complete: {summary['total_findings']} findings, "
        f"{summary['notifications_sent']} sent, {summary['deduped']} deduped, "
        f"{summary['errors']} errors"
    )
    return summary


def is_soar_enabled(config: dict) -> bool:
    """Quick check: is SOAR integration configured and enabled?"""
    return bool(config.get("soar", {}).get("enabled", False))
