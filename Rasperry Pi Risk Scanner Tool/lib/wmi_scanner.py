#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
wmi_scanner.py - Credentialed Windows WMI/WinRM Interrogation

Tries WinRM (port 5985) via pypsrp first, falls back to WMI DCOM via
impacket (port 135). Collects OS, KBs, software, users, services,
firewall, AV, shares, RDP, and UAC status.
"""

import logging
import re
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

_CMD_TIMEOUT = 30


def scan_host_wmi(ip: str, credential_profile: dict) -> dict:
    """
    Perform credentialed Windows scan via WinRM or WMI.
    Returns dict with Windows system info, security configuration.
    """
    result = {
        "ip": ip,
        "wmi_success": False,
        "wmi_method": None,
        "os_version": None,
        "os_build": None,
        "last_boot": None,
        "domain": None,
        "manufacturer": None,
        "model": None,
        "wmi_software": [],
        "installed_kbs": [],
        "local_users": [],
        "running_services": [],
        "windows_firewall": {},
        "antivirus": {},
        "smb_shares": [],
        "rdp_enabled": None,
        "uac_enabled": None,
        "autorun_entries": [],
        "patch_status": {},
        "error": None,
    }

    username_orig = credential_profile.get("username", "")
    password = credential_profile.get("password", "")
    domain = ""
    username = username_orig
    if "\\" in username_orig:
        domain, username = username_orig.split("\\", 1)
    elif "@" in username_orig:
        username, domain = username_orig.split("@", 1)

    logger.info(f"WMI scan: {ip} (user={username} domain={domain or 'local'})")

    # Try WinRM first (faster, more reliable) — pass original format so pypsrp
    # handles both UPN (user@domain.local) and NTLM (DOMAIN\user) natively.
    winrm_success = _try_winrm(ip, username_orig, password, domain, result)
    if winrm_success:
        result["wmi_success"] = True
        result["wmi_method"] = "winrm"
        return result

    # Fallback: WMI DCOM via impacket
    logger.info(f"WinRM failed for {ip}, trying WMI DCOM...")
    wmi_success = _try_wmi_dcom(ip, username, password, domain, result)
    if wmi_success:
        result["wmi_success"] = True
        result["wmi_method"] = "wmi_dcom"
        return result

    result["error"] = "Both WinRM and WMI DCOM failed"
    logger.warning(f"WMI scan failed: {ip} — {result['error']}")
    return result


def _try_winrm(ip: str, username: str, password: str, domain: str, result: dict) -> bool:
    """Try WinRM (pypsrp) connection and collect data via PowerShell.

    ``username`` is the original credential string — either UPN format
    (user@domain.local) or NTLM format (DOMAIN\\user) — passed as-is to
    pypsrp which handles both natively without manual reconstruction.
    ``domain`` is available for DCOM fallback only.
    """
    try:
        import pypsrp
        from pypsrp.client import Client
    except ImportError:
        logger.debug("pypsrp not installed — WinRM unavailable")
        return False

    try:
        # Pass username verbatim — pypsrp accepts both user@domain.local and DOMAIN\user
        client = Client(
            ip,
            username=username,
            password=password,
            ssl=False,
            connection_timeout=_CMD_TIMEOUT,
        )

        def ps(cmd: str) -> Optional[str]:
            try:
                stdout, stderr, rc = client.execute_ps(cmd)
                out = (stdout or "").strip()
                if not out and stderr:
                    logger.debug(f"WinRM PS cmd stderr: {cmd[:60]}... — {stderr[:200]}")
                return out or None
            except Exception as e:
                logger.debug(f"WinRM PS cmd failed: {cmd[:60]}... — {e}")
                return None

        # OS info
        os_info = ps(
            "$os = Get-WmiObject Win32_OperatingSystem; "
            "[PSCustomObject]@{Caption=$os.Caption; BuildNumber=$os.BuildNumber} | ConvertTo-Json"
        )
        if os_info:
            try:
                import json
                data = json.loads(os_info)
                if isinstance(data, list):
                    data = data[0] if data else {}
                caption = data.get("Caption") or data.get("caption") or ""
                result["os_version"] = str(caption).strip()
                result["os_build"] = str(data.get("BuildNumber") or data.get("buildNumber") or "").strip()
            except Exception:
                result["os_version"] = os_info[:100]

        # Computer system
        cs_info = ps("Get-WmiObject Win32_ComputerSystem | Select-Object Domain,Manufacturer,Model | ConvertTo-Json")
        if cs_info:
            try:
                import json
                data = json.loads(cs_info)
                result["domain"] = data.get("Domain", "")
                result["manufacturer"] = data.get("Manufacturer", "")
                result["model"] = data.get("Model", "")
            except Exception:
                pass

        # Installed KBs
        kb_out = ps(
            "Get-WmiObject Win32_QuickFixEngineering | "
            "Select-Object HotFixID,InstalledOn | "
            "Sort-Object InstalledOn -Descending | "
            "Select-Object -First 50 | ConvertTo-Json"
        )
        if kb_out:
            try:
                import json
                kbs = json.loads(kb_out)
                if isinstance(kbs, dict):
                    kbs = [kbs]
                result["installed_kbs"] = kbs[:50]
                # Check patch staleness
                if kbs:
                    newest_kb = kbs[0]
                    installed_on = newest_kb.get("InstalledOn", "")
                    if installed_on:
                        try:
                            dt = datetime.strptime(installed_on[:10], "%m/%d/%Y")
                            days_old = (datetime.now() - dt).days
                            result["patch_status"] = {
                                "last_update": dt.strftime("%Y-%m-%d"),
                                "pending_updates": None,
                                "days_since_update": days_old,
                                "update_manager": "Windows Update",
                            }
                        except Exception:
                            pass
            except Exception:
                pass

        # Installed software via registry (faster than Win32_Product, no MSI side-effects)
        sw_out = ps(
            "$paths = @("
            "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
            "$paths | ForEach-Object { if (Test-Path $_) { Get-ItemProperty $_ } } | "
            "Where-Object { $_.DisplayName } | "
            "Select-Object DisplayName,DisplayVersion,Publisher | "
            "Select-Object -First 200 | ConvertTo-Json -Compress"
        )
        if sw_out:
            try:
                import json
                sws = json.loads(sw_out)
                if isinstance(sws, dict):
                    sws = [sws]
                result["wmi_software"] = [
                    {
                        "name": s.get("DisplayName", ""),
                        "version": s.get("DisplayVersion", ""),
                        "publisher": s.get("Publisher", ""),
                    }
                    for s in sws
                    if s.get("DisplayName")
                ]
            except Exception:
                pass

        # Local users
        users_out = ps(
            "Get-WmiObject Win32_UserAccount -Filter \"LocalAccount=True\" | "
            "Select-Object Name,Disabled,PasswordRequired | ConvertTo-Json"
        )
        if users_out:
            try:
                import json
                users = json.loads(users_out)
                if isinstance(users, dict):
                    users = [users]
                result["local_users"] = [
                    {"username": u.get("Name", ""), "disabled": u.get("Disabled", False)}
                    for u in users
                ]
            except Exception:
                pass

        # Running services (flag suspicious)
        svc_out = ps(
            "Get-WmiObject Win32_Service -Filter \"State='Running'\" | "
            "Select-Object Name,PathName | Select-Object -First 100 | ConvertTo-Json"
        )
        if svc_out:
            try:
                import json
                svcs = json.loads(svc_out)
                if isinstance(svcs, dict):
                    svcs = [svcs]
                result["running_services"] = [s.get("Name", "") for s in svcs]
            except Exception:
                pass

        # Windows Firewall
        fw_out = ps(
            "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json"
        )
        if fw_out:
            try:
                import json
                profiles = json.loads(fw_out)
                if isinstance(profiles, dict):
                    profiles = [profiles]
                for p in profiles:
                    name = p.get("Name", "unknown").lower()
                    enabled = p.get("Enabled", True)
                    result["windows_firewall"][name] = "enabled" if enabled else "disabled"
            except Exception:
                pass

        # Antivirus (SecurityCenter2)
        av_out = ps(
            "Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct | "
            "Select-Object displayName,productState | ConvertTo-Json 2>$null"
        )
        if av_out:
            try:
                import json
                avs = json.loads(av_out)
                if isinstance(avs, dict):
                    avs = [avs]
                if avs:
                    av = avs[0]
                    # productState bit 12 = real-time protection; bit 4 = definitions up to date
                    state = av.get("productState", 0)
                    result["antivirus"] = {
                        "product": av.get("displayName", ""),
                        "product_state": state,
                        "status": _decode_av_state(state),
                    }
            except Exception:
                pass

        # SMB shares
        shares_out = ps(
            "Get-WmiObject Win32_Share | Select-Object Name,Path,Type | ConvertTo-Json"
        )
        if shares_out:
            try:
                import json
                shares = json.loads(shares_out)
                if isinstance(shares, dict):
                    shares = [shares]
                non_admin = [
                    {"name": s.get("Name", ""), "path": s.get("Path", ""), "access": "Unknown"}
                    for s in shares
                    if not str(s.get("Name", "")).endswith("$")
                ]
                result["smb_shares"] = non_admin
            except Exception:
                pass

        # RDP enabled
        rdp_out = ps(
            "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections 2>$null).fDenyTSConnections"
        )
        if rdp_out is not None:
            result["rdp_enabled"] = rdp_out.strip() == "0"

        # UAC
        uac_out = ps(
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA 2>$null).EnableLUA"
        )
        if uac_out is not None:
            result["uac_enabled"] = uac_out.strip() == "1"

        logger.info(f"WinRM scan complete: {ip} — OS: {result['os_version'] or 'unknown'}")
        return True

    except Exception as e:
        logger.debug(f"WinRM failed: {ip} — {e}")
        return False


def _try_wmi_dcom(ip: str, username: str, password: str, domain: str, result: dict) -> bool:
    """Fallback: basic WMI DCOM via impacket wmiquery."""
    try:
        from impacket.dcerpc.v5.dcom import wmi
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
    except ImportError:
        logger.debug("impacket not installed — WMI DCOM unavailable")
        return False

    try:
        dcom = DCOMConnection(
            ip,
            username=username,
            password=password,
            domain=domain or ".",
            oxidResolver=True,
            doKerberos=False,
        )
        iinterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iinterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", None, None)

        def query(q: str) -> list:
            try:
                iEnumWbemClassObject = iWbemServices.ExecQuery(q)
                rows = []
                while True:
                    try:
                        obj, _ = iEnumWbemClassObject.Next(0xffffffff, 1)
                        if not obj:
                            break
                        rows.append(obj)
                    except Exception:
                        break
                return rows
            except Exception as e:
                logger.debug(f"WMI query failed: {q[:60]}... — {e}")
                return []

        # OS
        for row in query("SELECT Caption, BuildNumber FROM Win32_OperatingSystem"):
            try:
                result["os_version"] = str(row.Caption)
                result["os_build"] = str(row.BuildNumber)
            except Exception:
                pass

        # Computer system
        for row in query("SELECT Domain, Manufacturer, Model FROM Win32_ComputerSystem"):
            try:
                result["domain"] = str(row.Domain)
                result["manufacturer"] = str(row.Manufacturer)
                result["model"] = str(row.Model)
            except Exception:
                pass

        dcom.disconnect()
        logger.info(f"WMI DCOM scan complete: {ip}")
        return True

    except Exception as e:
        logger.debug(f"WMI DCOM failed: {ip} — {e}")
        return False


def _decode_av_state(state: int) -> str:
    """Decode Windows SecurityCenter2 productState to status string."""
    # Bit 12 in productState indicates real-time protection
    # 0x1000 = real-time ON, 0x0010 = definitions up to date
    if state == 0:
        return "missing"
    # Check if definition age bit is stale (simplified heuristic)
    hex_state = format(state, "06x")
    real_time_on = hex_state[1:3] == "10"
    defs_current = hex_state[4:6] in ("00", "10")
    if not real_time_on:
        return "missing"
    if not defs_current:
        return "stale"
    return "current"
