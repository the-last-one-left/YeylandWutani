# AWN Scanner — Plugin Directory

This directory contains the modular scan plugins that make up the AWN scanning pipeline.
Each plugin is a self-contained Python file that subclasses `ScanPlugin` from `lib/plugin_base.py`.

## Execution Order

| Phase | File | Plugin ID | Category | Description |
|-------|------|-----------|----------|-------------|
| 1 | `01_reconnaissance.py` | `reconnaissance` | `discovery` | Network topology, subnets, gateway, DNS, public IP |
| 2 | `02_host_discovery.py` | `host_discovery` | `discovery` | Nmap ping-sweep to find live hosts |
| 3 | `03_port_scan.py` | `port_scan` | `discovery` | Nmap SV+OS scan on all live hosts |
| 4 | `04_ssh_audit.py` | `ssh_audit` | `ssh` | Credentialed SSH audit (packages, users, sshd config) |
| 5 | `05_wmi_audit.py` | `wmi_audit` | `wmi` | WinRM/WMI audit (software, hotfixes, firewall) |
| 6 | `06_snmp_audit.py` | `snmp_audit` | `snmp` | SNMP v1/v2c/v3 enumeration |
| 7 | `07_cve_correlation.py` | `cve_correlation` | `cve` | Match packages against NVD/KEV/OSV databases |
| 8 | `08_compliance.py` | `compliance` | `compliance` | CIS-inspired YAML-driven hardening checks |
| 9 | `09_risk_scoring.py` | `risk_scoring` | `risk` | Composite risk score per host + network aggregate |
| 10 | `10_delta_analysis.py` | `delta_analysis` | `delta` | Compare current vs previous scan for trend data |
| 11 | `11_reporting.py` | `reporting` | `reporting` | Persist results to disk, write plain-text summary |

## Writing a Custom Plugin

Create a new `.py` file in this directory. The plugin loader will discover it automatically
on the next scan run.

```python
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_DISCOVERY

class MyCustomPlugin(ScanPlugin):
    plugin_id   = "my_custom_check"       # unique snake_case ID
    name        = "My Custom Check"       # human-readable name
    category    = CAT_DISCOVERY           # one of the CAT_* constants
    phase       = 3                       # execution order (integer)
    description = "What this plugin does"
    version     = "1.0.0"
    author      = "Your Name"
    requires    = ["host_discovery"]      # plugin_ids that must complete first

    def run(self, ctx: PluginContext) -> None:
        for host in ctx.hosts:
            # Read data: host["ip"], host["ports"], host["ssh"], etc.
            # Write data back into host dict or ctx.scan_results
            host["my_custom_data"] = {"checked": True}
        ctx.sync_hosts()
```

### Available `PluginContext` attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `ctx.config` | `dict` | Full parsed `config.json` |
| `ctx.policy` | `dict\|None` | Active scan policy (from `scan_policies.json`) |
| `ctx.hosts` | `list[dict]` | Live hosts (mutable, call `ctx.sync_hosts()` after changes) |
| `ctx.credentials` | `list[dict]` | Loaded credential profiles |
| `ctx.coverage` | `dict` | SSH/WMI/SNMP success/failed/no-cred lists |
| `ctx.data_dir` | `str` | Path to the `data/` directory |
| `ctx.scan_results` | `dict` | Full results dict (hosts, risk, delta, etc.) |

### Policy helper methods

```python
ctx.module_enabled("compliance")           # True/False based on policy modules list
ctx.get_policy_value("intensity", "normal") # Read a policy field with fallback
```

## Category Constants

| Constant | Value | Always Runs |
|----------|-------|-------------|
| `CAT_DISCOVERY` | `"discovery"` | |
| `CAT_SSH` | `"ssh"` | |
| `CAT_WMI` | `"wmi"` | |
| `CAT_SNMP` | `"snmp"` | |
| `CAT_CVE` | `"cve"` | |
| `CAT_COMPLIANCE` | `"compliance"` | |
| `CAT_WEB` | `"web"` | |
| `CAT_BRUTEFORCE` | `"bruteforce"` | |
| `CAT_RISK` | `"risk"` | ✓ |
| `CAT_DELTA` | `"delta"` | ✓ |
| `CAT_REPORTING` | `"reporting"` | |

`CAT_RISK` and `CAT_DELTA` plugins always run regardless of policy module selection.

## Compliance Check YAML Format

Custom compliance checks live in `config/compliance_checks/*.yaml`.
See `config/compliance_checks/linux_cis.yaml` for a full example.

```yaml
checks:
  - id: MY-CHK-001
    title: Example check
    category: My Category
    platform: linux          # linux | windows | any
    severity: HIGH           # CRITICAL | HIGH | MEDIUM | LOW
    check_type: sshd_config  # see plugin docs for all types
    key: permitrootlogin
    operator: eq
    value: "no"
    remediation: Set PermitRootLogin no in /etc/ssh/sshd_config
```
