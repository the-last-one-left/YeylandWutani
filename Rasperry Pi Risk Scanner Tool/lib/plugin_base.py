#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
lib/plugin_base.py  -  Abstract base class for all scan plugins.

Every plugin in the plugins/ directory must subclass ScanPlugin and implement
the `run()` method.  The plugin loader validates metadata at load time.
"""

from __future__ import annotations

import abc
import logging
from typing import Any

logger = logging.getLogger(__name__)


# ── Plugin category constants (used by policies to filter modules) ─────────
CAT_DISCOVERY    = "discovery"    # host/service discovery (phases 1-4)
CAT_SSH          = "ssh"          # credentialed SSH audit
CAT_WMI          = "wmi"          # credentialed WMI/WinRM audit
CAT_SNMP         = "snmp"         # SNMP enumeration
CAT_CVE          = "cve"          # CVE / KEV correlation
CAT_COMPLIANCE   = "compliance"   # configuration / hardening checks
CAT_WEB          = "web"          # web application probing
CAT_BRUTEFORCE   = "bruteforce"   # credential brute-force checks
CAT_RISK         = "risk"         # risk scoring (always on)
CAT_DELTA        = "delta"        # delta / trend analysis (always on)
CAT_REPORTING    = "reporting"    # report generation

ALL_CATEGORIES = [
    CAT_DISCOVERY, CAT_SSH, CAT_WMI, CAT_SNMP, CAT_CVE,
    CAT_COMPLIANCE, CAT_WEB, CAT_BRUTEFORCE, CAT_RISK,
    CAT_DELTA, CAT_REPORTING,
]

# Categories that are always executed regardless of policy module selection
ALWAYS_ON = {CAT_RISK, CAT_DELTA}


class PluginContext:
    """
    Shared mutable context passed through every plugin in the pipeline.

    Plugins read inputs from `ctx` and write outputs back into it so that
    later plugins can consume the enriched data.

    Attributes:
        config          Full parsed config.json dict.
        policy          Active scan policy dict (from scan_policies.json),
                        or None if no policy was selected (uses defaults).
        data_dir        Path to persistent data directory.
        scan_results    The accumulating scan results dict returned at the end.
        hosts           Shortcut reference to scan_results["hosts"] list.
        credentials     List of loaded credential profiles.
        coverage        Shortcut reference to scan_results["credential_coverage"].
        phases_completed  Running count of successfully completed phases.
        phases_skipped    Running count of skipped/failed phases.
    """

    def __init__(
        self,
        config: dict,
        data_dir: str,
        policy: dict | None = None,
    ) -> None:
        self.config: dict            = config
        self.data_dir: str           = data_dir
        self.policy: dict | None     = policy
        self.credentials: list       = []
        self.phases_completed: int   = 0
        self.phases_skipped: int     = 0

        self.scan_results: dict = {
            "scan_start":  "",
            "scan_end":    "",
            "scanner_version": "",
            "policy_name": policy.get("name") if policy else None,
            "hosts":       [],
            "summary":     {},
            "reconnaissance": {},
            "delta":       {},
            "risk":        {"score": 0, "level": "LOW", "breakdown": {}},
            "credential_coverage": {
                "ssh_success":    [],
                "ssh_failed":     [],
                "wmi_success":    [],
                "wmi_failed":     [],
                "snmp_success":   [],
                "snmp_failed":    [],
                "no_credential":  [],
            },
            "vuln_db_stats": {},
            "ai_insights":  None,
        }
        self.hosts: list   = self.scan_results["hosts"]
        self.coverage: dict = self.scan_results["credential_coverage"]

    # ------------------------------------------------------------------
    # Policy helpers
    # ------------------------------------------------------------------

    def module_enabled(self, category: str) -> bool:
        """
        Return True if the given module category should run under the active policy.

        Rules (in priority order):
          1. Categories in ALWAYS_ON are always True.
          2. If no policy is loaded, all categories are enabled (default behaviour).
          3. Otherwise, the category must appear in policy["modules"].
        """
        if category in ALWAYS_ON:
            return True
        if self.policy is None:
            return True
        enabled_modules: list = self.policy.get("modules", ALL_CATEGORIES)
        return category in enabled_modules

    def get_policy_value(self, key: str, default: Any = None) -> Any:
        """Read a value from the active policy, falling back to `default`."""
        if self.policy is None:
            return default
        return self.policy.get(key, default)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def sync_hosts(self) -> None:
        """Synchronise the ctx.hosts shortcut with scan_results[\"hosts\"]."""
        self.scan_results["hosts"] = self.hosts


class ScanPlugin(abc.ABC):
    """
    Abstract base class for all AWN scan plugins.

    Subclasses MUST define the class-level metadata attributes and implement
    the `run(ctx)` method.

    Class attributes:
        plugin_id    Unique snake_case identifier, e.g. "nmap_port_scan".
        name         Human-readable name shown in logs and the UI.
        category     One of the CAT_* constants above.
        phase        Integer execution order (lower = earlier). Gaps are fine.
        description  One-line description of what this plugin does.
        version      Semantic version string, e.g. "1.0.0".
        author       Plugin author / maintainer.
        requires     List of plugin_ids that must have run successfully before
                     this plugin is invoked.
    """

    # ── Required metadata ────────────────────────────────────────────────
    plugin_id:   str  = ""
    name:        str  = ""
    category:    str  = ""
    phase:       int  = 999
    description: str  = ""
    version:     str  = "1.0.0"
    author:      str  = "AWN"
    requires:    list = []

    # ── Optional capability flags ────────────────────────────────────────
    # Set to True if the plugin modifies hosts in place (most plugins do).
    modifies_hosts: bool = True
    # Set to True if the plugin requires root/administrator privileges.
    requires_root:  bool = False

    # ── Runtime state (set by loader) ───────────────────────────────────
    _success: bool = False
    _error:   str  = ""

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def run(self, ctx: PluginContext) -> None:
        """
        Execute the plugin against the current scan context.

        Implementations should:
          - Read inputs from ctx (ctx.hosts, ctx.config, ctx.credentials, etc.)
          - Write outputs back into ctx (mutate ctx.hosts, ctx.scan_results, etc.)
          - Call ctx.sync_hosts() after mutating ctx.hosts if necessary
          - Raise an exception on unrecoverable failure (the loader will catch it)
          - Use self.logger for all log output
        """

    # ------------------------------------------------------------------
    # Helpers available to all plugins
    # ------------------------------------------------------------------

    @property
    def logger(self) -> logging.Logger:
        return logging.getLogger(f"plugin.{self.plugin_id}")

    def validate(self) -> list[str]:
        """
        Validate plugin metadata.  Returns a list of error strings (empty = OK).
        Called by the loader at import time.
        """
        errors: list[str] = []
        if not self.plugin_id:
            errors.append("plugin_id is required")
        if not self.name:
            errors.append("name is required")
        if self.category not in ALL_CATEGORIES:
            errors.append(f"category '{self.category}' is not a recognised CAT_* constant")
        if not isinstance(self.phase, int) or self.phase < 1:
            errors.append("phase must be a positive integer")
        return errors

    def __repr__(self) -> str:
        return f"<Plugin phase={self.phase} id={self.plugin_id!r} cat={self.category!r}>"
