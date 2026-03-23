#!/usr/bin/env python3
"""
Plugin: WMI / WinRM Credentialed Audit  (Phase 5)
Connect to Windows hosts via WMI (impacket) or WinRM (pywinrm) and collect
installed software, patches, users, services, firewall state.
"""

from __future__ import annotations

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_WMI

log = logging.getLogger("plugin.wmi_audit")


def _find_cred_for_host(ip: str, credentials: list) -> dict | None:
    for cred in credentials:
        if cred.get("type") not in ("wmi", "winrm"):
            continue
        hosts = cred.get("hosts", [])
        if ip in hosts:
            return cred
    for cred in credentials:
        if cred.get("type") not in ("wmi", "winrm"):
            continue
        if not cred.get("hosts") or "*" in cred.get("hosts", []):
            return cred
    return None


def _is_windows_host(host: dict) -> bool:
    os_guess = (host.get("os_guess") or "").lower()
    services  = [s.lower() for s in host.get("services", [])]
    if "windows" in os_guess:
        return True
    # WinRM ports open
    for p in host.get("ports", []):
        if p["port"] in (135, 445, 5985, 5986):
            return True
    return False


def _winrm_audit(ip: str, cred: dict, timeout: int) -> dict:
    result: dict = {
        "success":          False,
        "method":           "winrm",
        "username":         cred.get("username", ""),
        "os_info":          {},
        "installed_software": [],
        "hotfixes":         [],
        "local_users":      [],
        "local_admins":     [],
        "services":         [],
        "firewall":         {},
        "errors":           [],
    }
    try:
        import winrm  # type: ignore
    except ImportError:
        result["errors"].append("pywinrm not installed. Run: pip install pywinrm")
        return result

    domain   = cred.get("domain", "")
    username = f"{domain}\\{cred['username']}" if domain else cred.get("username", "")
    password = cred.get("password", "")
    port     = 5985
    scheme   = "http"
    for p in [5985, 5986]:
        if p == 5986:
            scheme = "https"
        port = p
        break

    try:
        session = winrm.Session(
            f"{scheme}://{ip}:{port}/wsman",
            auth=(username, password),
            transport="ntlm",
            server_cert_validation="ignore",
            read_timeout_sec=timeout,
            operation_timeout_sec=timeout,
        )

        def _ps(script: str) -> str:
            r = session.run_ps(script)
            return r.std_out.decode(errors="replace").strip()

        # OS info
        os_raw = _ps("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | ConvertTo-Json -Compress")
        try:
            import json; result["os_info"] = json.loads(os_raw)
        except Exception:
            result["os_info"] = {"raw": os_raw}

        # Installed software
        sw_raw = _ps(
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            "| Select-Object DisplayName,DisplayVersion,Publisher "
            "| Where-Object {$_.DisplayName} "
            "| ConvertTo-Json -Compress"
        )
        try:
            import json
            sw_list = json.loads(sw_raw)
            if isinstance(sw_list, dict):
                sw_list = [sw_list]
            result["installed_software"] = sw_list[:500]
        except Exception:
            pass

        # Hotfixes (patches)
        hf_raw = _ps("Get-HotFix | Select-Object HotFixID,InstalledOn | ConvertTo-Json -Compress")
        try:
            import json
            hf_list = json.loads(hf_raw)
            if isinstance(hf_list, dict):
                hf_list = [hf_list]
            result["hotfixes"] = hf_list
        except Exception:
            pass

        # Local users
        users_raw = _ps("Get-LocalUser | Select-Object Name,Enabled,PasswordLastSet | ConvertTo-Json -Compress")
        try:
            import json
            u_list = json.loads(users_raw)
            result["local_users"] = u_list if isinstance(u_list, list) else [u_list]
        except Exception:
            pass

        # Local admins
        admins_raw = _ps("Get-LocalGroupMember -Group Administrators | Select-Object Name,ObjectClass | ConvertTo-Json -Compress")
        try:
            import json
            a_list = json.loads(admins_raw)
            result["local_admins"] = a_list if isinstance(a_list, list) else [a_list]
        except Exception:
            pass

        # Services
        svc_raw = _ps("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName,StartType | ConvertTo-Json -Compress")
        try:
            import json
            s_list = json.loads(svc_raw)
            result["services"] = s_list if isinstance(s_list, list) else [s_list]
        except Exception:
            pass

        # Firewall state
        fw_raw = _ps("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress")
        try:
            import json
            fw_list = json.loads(fw_raw)
            result["firewall"] = {p["Name"]: p["Enabled"] for p in (fw_list if isinstance(fw_list, list) else [fw_list])}
        except Exception:
            pass

        result["success"] = True

    except Exception as exc:
        result["errors"].append(str(exc))
        log.debug(f"{ip}: WinRM audit error: {exc}")

    return result


class WMIAuditPlugin(ScanPlugin):
    plugin_id   = "wmi_audit"
    name        = "WMI / WinRM Credentialed Audit"
    category    = CAT_WMI
    phase       = 5
    description = (
        "Authenticate to Windows hosts via WinRM/WMI and collect installed software, "
        "hotfixes, local users, running services and firewall state."
    )
    version     = "1.0.0"
    author      = "AWN"
    requires    = ["host_discovery"]

    def run(self, ctx: PluginContext) -> None:
        windows_hosts = [h for h in ctx.hosts if _is_windows_host(h)]
        if not windows_hosts:
            log.info("No Windows hosts detected — skipping WMI/WinRM audit.")
            return

        scan_cfg = ctx.config.get("scan", {})
        timeout  = int(ctx.get_policy_value("timeout_per_host", scan_cfg.get("host_timeout", 30)))
        parallel = int(ctx.get_policy_value("max_parallel", scan_cfg.get("max_parallel_hosts", 5)))

        def _try_host(host: dict):
            ip   = host["ip"]
            cred = _find_cred_for_host(ip, ctx.credentials)
            if cred is None:
                log.debug(f"{ip}: No WMI/WinRM credential available.")
                if ip not in ctx.coverage["no_credential"]:
                    ctx.coverage["no_credential"].append(ip)
                return
            result = _winrm_audit(ip, cred, timeout)
            host["wmi"] = result
            if result["success"]:
                ctx.coverage["wmi_success"].append(ip)
            else:
                ctx.coverage["wmi_failed"].append(ip)

        with ThreadPoolExecutor(max_workers=parallel) as ex:
            futures = {ex.submit(_try_host, h): h["ip"] for h in windows_hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    fut.result()
                except Exception as exc:
                    log.error(f"WMI audit future error for {ip}: {exc}")

        ctx.sync_hosts()
        success = len(ctx.coverage["wmi_success"])
        failed  = len(ctx.coverage["wmi_failed"])
        log.info(f"WMI audit complete: {success} success, {failed} failed.")
