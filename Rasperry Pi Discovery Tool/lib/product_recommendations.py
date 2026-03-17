#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
product_recommendations.py - Infrastructure Recommendations PDF Generator

Analyzes network scan data and generates a professional product recommendation
report proposing appropriately-sized WatchGuard, Aruba, and Dell infrastructure.

Product selection is fully deterministic (catalog-based rules).
Narrative text is optionally enhanced by Hatz AI (same API as hatz_ai.py).

Requires: reportlab  (pip install reportlab)
"""

import io
import json
import logging
import math
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, white, black
    from reportlab.pdfgen import canvas as rl_canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ── Page geometry (matches client_report.py) ─────────────────────────────────

PAGE_W, PAGE_H = 612.0, 792.0
MARGIN    = 0.75 * 72          # 54 pt
CONTENT_W = PAGE_W - 2 * MARGIN
FOOTER_H  = 38
HEADER_H  = 55

# ── Vendor accent colours ──────────────────────────────────────────────────

VENDOR_COLORS = {
    "WatchGuard": "#c8102e",   # WatchGuard red
    "Aruba":      "#ff6b00",   # Aruba orange
    "Dell":       "#007db8",   # Dell blue
    "Datto":      "#e8001b",   # Datto red
}


def _hex(s: str, fallback: str = "#FF6600") -> "HexColor":
    try:
        return HexColor(s if s.startswith("#") else f"#{s}")
    except Exception:
        return HexColor(fallback)


# ── Catalog loader ────────────────────────────────────────────────────────────

def load_product_catalog() -> dict:
    """Load product_catalog.json from the same directory as this module."""
    catalog_path = Path(__file__).parent / "product_catalog.json"
    if not catalog_path.exists():
        logger.warning(f"Product catalog not found at {catalog_path}")
        return {}
    with open(catalog_path, encoding="utf-8") as f:
        return json.load(f)


# ── Environment analyser ─────────────────────────────────────────────────────

def size_environment(scan_results: dict) -> dict:
    """
    Extract infrastructure sizing signals from scan_results.

    Returns a dict with:
        device_count            total hosts discovered
        server_count            hosts categorised as servers
        estimated_wired         rough wired device estimate
        estimated_wireless      rough wireless device estimate
        download_mbps           ISP download speed (0 if unavailable)
        upload_mbps             ISP upload speed (0 if unavailable)
        isp                     ISP name string
        domain                  primary domain (from OSINT)
        wifi_network_count      number of wireless networks detected
        existing_vendors        list of recognised infrastructure vendor names
        has_watchguard          bool – WatchGuard appliance on network
        has_aruba               bool – Aruba switch/AP on network
        has_consumer_wifi       bool – consumer mesh/AP vendor detected
        consumer_wifi_brands    list of consumer brand names detected
        eol_server_count        EOL devices that look like servers
        subnet                  primary subnet CIDR
    """
    hosts   = scan_results.get("hosts", [])
    summary = scan_results.get("summary", {})
    recon   = scan_results.get("reconnaissance", {})
    osint   = scan_results.get("osint", {})
    speed   = scan_results.get("speedtest", {})
    wifi    = scan_results.get("wifi", {})
    eol     = scan_results.get("eol_detection", {})
    ad      = scan_results.get("ad_enrichment", {})

    # ── Device counts ─────────────────────────────────────────────────────
    device_count = summary.get("total_hosts", len(hosts))

    server_cats = {"Server", "Linux/Unix Server", "Windows Server",
                   "Database Server", "Mail Server", "Web Server"}
    cat_breakdown = summary.get("category_breakdown", {})
    server_count = sum(v for k, v in cat_breakdown.items() if k in server_cats)

    # ── Vendor detection ──────────────────────────────────────────────────
    _consumer_brands = {
        "eero inc.":                "eero",
        "google, inc.":             "Google Nest",
        "tp-link technologies":     "TP-Link",
        "netgear":                  "Netgear",
        "linksys":                  "Linksys",
        "ubiquiti networks":        "Ubiquiti",   # not consumer but not enterprise MSP line
        "asus":                     "ASUS",
    }
    _aruba_names = {
        "aruba networks", "hewlett packard enterprise",
        "aruba, a hewlett packard enterprise company",
    }
    _watchguard_names = {"watchguard technologies, inc.", "watchguard"}

    existing_vendors: list = []
    has_watchguard   = False
    has_aruba        = False
    has_consumer_wifi: list = []

    for entry in summary.get("top_vendors", []):
        vendor_lower = entry.get("vendor", "").lower()
        if vendor_lower in _watchguard_names:
            has_watchguard = True
            existing_vendors.append("WatchGuard")
        if any(a in vendor_lower for a in _aruba_names):
            has_aruba = True
            existing_vendors.append("Aruba")
        for key, label in _consumer_brands.items():
            if key in vendor_lower:
                if label not in has_consumer_wifi:
                    has_consumer_wifi.append(label)

    # Also check SSL cert CNs for WatchGuard domain
    if not has_watchguard:
        for cert in scan_results.get("ssl_audit", {}).get("certificates", []):
            cn = (cert.get("subject_cn") or "").lower()
            if "watchguard" in cn:
                has_watchguard = True
                if "WatchGuard" not in existing_vendors:
                    existing_vendors.append("WatchGuard")
                break

    # ── WiFi ──────────────────────────────────────────────────────────────
    wifi_networks   = wifi.get("networks", []) if isinstance(wifi, dict) else []
    wifi_net_count  = len(wifi_networks)

    # ── Speed ─────────────────────────────────────────────────────────────
    dl_mbps = float(speed.get("download_mbps", 0) or 0)
    ul_mbps = float(speed.get("upload_mbps",   0) or 0)

    # ── Wireless vs wired estimate ────────────────────────────────────────
    # Heuristic: hosts with no MAC vendor and no open ports tend to be mobile
    # devices. Use a 35% wireless ratio as a conservative default when no
    # WiFi scan data is available.
    if wifi_net_count > 0:
        # Rough estimate: each WiFi network carries ~8 clients on average
        estimated_wireless = min(wifi_net_count * 8, device_count)
    else:
        estimated_wireless = int(device_count * 0.35)
    estimated_wired = max(0, device_count - estimated_wireless)

    # ── EOL servers ───────────────────────────────────────────────────────
    eol_devices    = eol.get("eol_devices", [])
    eol_server_ips = {h["ip"] for h in hosts
                      for cat in [h.get("device_type") or h.get("category","")]
                      if cat in server_cats}
    eol_server_count = sum(1 for d in eol_devices if d.get("ip") in eol_server_ips)

    # ── OSINT domain / ISP ────────────────────────────────────────────────
    ident  = osint.get("company_identification", {})
    domain = ident.get("primary_domain", "")
    isp    = summary.get("isp") or ident.get("isp", "")

    subnets = recon.get("subnets", [])
    subnet  = subnets[0] if subnets else ""

    # ── Virtualization detection ──────────────────────────────────────────
    # MAC OUI prefixes that indicate a VM's virtual NIC
    _vm_mac_ouis = {
        "00:0c:29", "00:50:56", "00:05:69", "00:0e:c8",  # VMware
        "00:15:5d",                                        # Microsoft Hyper-V
        "08:00:27",                                        # VirtualBox
    }

    # ── Active Directory enrichment (credentialed scan) ───────────────────
    ad_available = bool(ad.get("available"))
    ad_context   = {}    # populated below once hardware data is collected
    if ad_available:
        # AD server count is authoritative — overrides port-based heuristic
        ad_server_count = ad.get("server_count", 0)
        if ad_server_count > 0:
            server_count = ad_server_count

    # ── VM vs physical host classification ───────────────────────────────
    # Count VMs and confirmed physical hosts so we recommend the right number
    # of physical servers rather than one-per-VM.
    vm_count      = 0
    phys_detected = 0

    if ad_available and ad.get("hardware"):
        for _cname, _hw in (ad.get("hardware") or {}).items():
            _mfr   = (_hw.get("manufacturer") or "").lower()
            _model = (_hw.get("model") or "").lower()
            if "vmware" in _mfr or "virtual machine" in _model:
                vm_count += 1
            elif _hw.get("wmi_accessible") and _mfr and "microsoft" not in _mfr:
                # WMI-accessible + real hardware vendor = confirmed physical server
                phys_detected += 1
    else:
        # No AD data — use MAC OUI heuristic
        for _h in hosts:
            _mac    = (_h.get("mac") or "").lower().replace("-", ":")
            _prefix = _mac[:8] if len(_mac) >= 8 else ""
            if _prefix in _vm_mac_ouis:
                vm_count += 1

    is_virtualized = vm_count > 0
    # Physical host count: use confirmed count, or derive 1 host per 5 VMs
    if is_virtualized and phys_detected == 0:
        physical_host_count = max(1, math.ceil(vm_count / 5))
    else:
        physical_host_count = phys_detected if phys_detected > 0 else server_count

    # ── Security software signals ─────────────────────────────────────────
    # AuthPoint (MFA): recommend when VPN, RDS, or WatchGuard detected
    _vpn_keywords = {"vpn", "remote access", "remote users", "ssl-vpn",
                     "sslvpn", "anyconnect", "remote desktop users"}
    authpoint_reasons: list = []

    # RDS/RDP: any Windows Server with port 3389 open warrants MFA on admin access
    for _h in hosts:
        _op = {p["port"] for p in _h.get("ports", []) if p.get("state") == "open"}
        if 3389 in _op:
            _os = (_h.get("ad_computer", {}).get("os") or _h.get("os") or "").lower()
            if "server" in _os:
                authpoint_reasons.append(
                    "Windows Server with RDP (port 3389) detected -- MFA protects admin access"
                )
                break

    # VPN/RDS from AD groups and SPNs
    if ad_available:
        for _grp in list((ad.get("privileged_groups") or {}).keys()):
            if any(kw in _grp.lower() for kw in _vpn_keywords):
                authpoint_reasons.append(f"AD group suggests VPN/remote access in use: '{_grp}'")
                break
        for _c in (ad.get("computers") or []):
            _spns = _c.get("ServicePrincipalNames") or _c.get("spns") or []
            if any("termsrv" in str(s).lower() for s in _spns):
                if not any("RDS" in r for r in authpoint_reasons):
                    authpoint_reasons.append("RDS (TERMSRV SPN) confirmed in Active Directory")
                break

    # WatchGuard already on network = VPN almost certainly in use
    if has_watchguard and not authpoint_reasons:
        authpoint_reasons.append(
            "WatchGuard firewall detected -- native AuthPoint integration available for VPN MFA"
        )

    recommend_authpoint = bool(authpoint_reasons)

    # EPDR (endpoint protection): recommend unless enterprise AV is positively identified
    _enterprise_av = {
        "crowdstrike", "sentinelone", "cylance", "carbon black", "cb defense",
        "sophos endpoint", "eset endpoint", "symantec endpoint", "sep manager",
        "trellix", "mcafee endpoint", "trend micro", "deep security",
        "malwarebytes endpoint", "bitdefender gravityzone", "cybereason",
        "cortex xdr", "defender for endpoint", "microsoft defender for endpoint",
        "watchguard epdr", "panda endpoint", "f-secure elements",
    }
    _consumer_av = {
        "windows defender", "microsoft defender antivirus",
        "avast", "avg antivirus", "avira antivirus",
        "malwarebytes free", "360 total", "comodo antivirus",
    }

    enterprise_av_detected = False
    enterprise_av_name     = ""
    free_av_detected       = False
    free_av_name           = ""

    def _check_av(text: str) -> tuple:
        tl = text.lower()
        for kw in _enterprise_av:
            if kw in tl:
                return kw.title(), ""
        for kw in _consumer_av:
            if kw in tl:
                return "", kw.title()
        return "", ""

    # Scan SSL certs, HTTP titles, and service banners for AV product names
    for _cert in scan_results.get("ssl_audit", {}).get("certificates", []):
        _e, _f = _check_av(
            (_cert.get("subject_cn") or "") + " " + (_cert.get("subject_org") or "")
        )
        if _e:
            enterprise_av_detected = True; enterprise_av_name = _e; break
        if _f:
            free_av_detected = True; free_av_name = _f

    if not enterprise_av_detected:
        for _h in hosts:
            _e, _f = _check_av((_h.get("http_info") or {}).get("title") or "")
            if _e:
                enterprise_av_detected = True; enterprise_av_name = _e; break
            if _f:
                free_av_detected = True; free_av_name = _f
            for _p in (_h.get("ports") or []):
                _banner = (_p.get("banner") or "") + " " + (_p.get("service_version") or "")
                _e, _f = _check_av(_banner)
                if _e:
                    enterprise_av_detected = True; enterprise_av_name = _e; break
                if _f:
                    free_av_detected = True; free_av_name = _f
            if enterprise_av_detected:
                break

    epdr_reasons: list = []
    if free_av_detected:
        epdr_reasons.append(
            f"Consumer-grade AV detected ({free_av_name}) -- "
            "not suitable for business threat protection"
        )
    elif not enterprise_av_detected:
        epdr_reasons.append("No enterprise endpoint protection detected on this network")
    if device_count > 0:
        epdr_reasons.append(f"{device_count} endpoint(s) to protect")

    recommend_epdr = not enterprise_av_detected

    # ── Cloud / M365 migration assessment ────────────────────────────────
    # Determine whether the environment is a good candidate for Microsoft 365
    # and/or Azure Virtual Desktop. Scored on positive + negative signals.

    # User count: authoritative from AD; estimate from devices otherwise
    _cloud_user_count = (ad_context.get("user_count", 0)
                         if ad_available and ad_context.get("user_count")
                         else max(1, int(device_count * 0.6)))

    # Detect server roles from port banners + AD SPNs
    _cloud_has_exchange  = False
    _cloud_has_rds       = False   # confirmed terminal/app server (not just mgmt RDP)
    _cloud_has_sql       = False
    _cloud_has_lob       = False

    _kw_exchange = {"exchange", "ews", "autodiscover", "microsoft exchange", "msexchange"}
    _kw_sql      = {"sql server", "sqlservr", "mssql", "sql native"}
    _kw_lob      = {"quickbooks", "sage ", "acumatica", "epicor", "dynamics nav",
                    "dynamics gp", "netsuite", "infor ", "fishbowl", "mas 90",
                    "mas 200", "great plains", "solomon"}

    for _h in hosts:
        _title  = ((_h.get("http_info") or {}).get("title") or "").lower()
        _os_str = ((_h.get("ad_computer") or {}).get("os") or _h.get("os") or "").lower()
        _open   = {p["port"] for p in _h.get("ports", []) if p.get("state") == "open"}
        for _p in (_h.get("ports") or []):
            _banner = ((_p.get("banner") or "") + " "
                       + (_p.get("service_version") or "")).lower()
            if any(kw in _banner for kw in _kw_exchange):
                _cloud_has_exchange = True
            if any(kw in _banner or kw in _title for kw in _kw_sql):
                _cloud_has_sql = True
            if any(kw in _banner or kw in _title for kw in _kw_lob):
                _cloud_has_lob = True
        # Terminal server: port 3389 on a Windows Server
        if 3389 in _open and "server" in _os_str:
            # Confirmed by TERMSRV SPN in AD
            if ad_available:
                for _c in (ad.get("computers") or []):
                    _spns = _c.get("ServicePrincipalNames") or _c.get("spns") or []
                    if any("termsrv" in str(s).lower() for s in _spns):
                        _cloud_has_rds = True
                        break
            # Fallback: server with RDP but not DC (no port 389) and not file-only
            if not _cloud_has_rds and 389 not in _open:
                _cloud_has_rds = True

    # Internet quality from speed test
    _cloud_internet = "unknown"
    if dl_mbps > 0:
        if dl_mbps >= 100 and ul_mbps >= 20:
            _cloud_internet = "good"
        elif dl_mbps >= 25 and ul_mbps >= 5:
            _cloud_internet = "adequate"
        else:
            _cloud_internet = "poor"

    # Scoring
    _cs = 0   # cloud score
    cloud_migration_reasons: list = []
    cloud_onprem_anchors:    list = []

    if _cloud_user_count <= 15:
        _cs += 3
        cloud_migration_reasons.append(
            f"Small team ({_cloud_user_count} users) -- M365 per-user licensing is highly cost-effective at this scale"
        )
    elif _cloud_user_count <= 30:
        _cs += 1
        cloud_migration_reasons.append(
            f"Medium-sized team ({_cloud_user_count} users) -- full cloud or hybrid both viable"
        )
    elif _cloud_user_count > 100:
        _cs -= 2
        cloud_onprem_anchors.append(
            f"Large user base ({_cloud_user_count} users) -- on-premises may be more cost-effective at scale"
        )

    _eol_count = eol_server_count  # already computed above
    if _eol_count > 0:
        _cs += 2
        cloud_migration_reasons.append(
            f"{_eol_count} end-of-life server(s) -- hardware refresh is a natural migration window"
        )

    if server_count <= 2:
        _cs += 2
        cloud_migration_reasons.append(
            f"Minimal on-premises servers ({server_count}) -- low infrastructure dependency"
        )
    elif server_count >= 6:
        _cs -= 2
        cloud_onprem_anchors.append(
            f"Large server footprint ({server_count} servers) -- phased migration recommended"
        )

    if _cloud_has_exchange:
        _cs += 2
        cloud_migration_reasons.append(
            "On-premises Exchange Server detected -- Exchange Online is a direct, proven replacement"
        )

    if _cloud_internet == "good":
        _cs += 1
        cloud_migration_reasons.append(
            f"Strong internet connection ({dl_mbps:.0f}/{ul_mbps:.0f} Mbps) -- cloud dependency is low risk"
        )
    elif _cloud_internet == "poor":
        _cs -= 2
        cloud_onprem_anchors.append(
            f"Slow internet ({dl_mbps:.0f} Mbps down) -- cloud dependency requires redundant connection"
        )

    if _cloud_has_sql:
        _cs -= 1
        cloud_onprem_anchors.append(
            "SQL Server detected -- database workloads typically remain on-prem or migrate to Azure SQL"
        )

    if _cloud_has_lob:
        _cs -= 2
        cloud_onprem_anchors.append(
            "Line-of-business application detected -- may require on-premises or private cloud hosting"
        )

    # Security gaps push toward Business Premium
    _security_gaps = len(ad_context.get("security_findings") or []) if ad_available else 0

    # Derive confidence and approach
    if _cs >= 5:
        cloud_migration_confidence = "high"
    elif _cs >= 2:
        cloud_migration_confidence = "medium"
    elif _cs >= 0:
        cloud_migration_confidence = "low"
    else:
        cloud_migration_confidence = None   # not recommended

    if cloud_migration_confidence is not None:
        if cloud_migration_confidence == "high" and not _cloud_has_lob and not _cloud_has_sql:
            cloud_migration_approach = "full_cloud"
        elif cloud_migration_confidence in ("high", "medium"):
            cloud_migration_approach = "hybrid"
        else:
            cloud_migration_approach = "cloud_first"   # start with M365 email/Teams, keep servers

        # Pick M365 tier
        if _security_gaps > 0 or free_av_detected or _cloud_user_count >= 20:
            cloud_m365_tier = "Business Premium"
            if _security_gaps > 0:
                cloud_migration_reasons.append(
                    "Security findings detected -- Business Premium includes Defender for Business and Intune"
                )
        elif _cloud_user_count <= 10:
            cloud_m365_tier = "Business Basic"
        else:
            cloud_m365_tier = "Business Standard"

        recommend_avd = _cloud_has_rds
        if recommend_avd:
            cloud_migration_reasons.append(
                "Remote Desktop / terminal server detected -- Azure Virtual Desktop replaces RDS with cloud-native VDI"
            )
    else:
        cloud_migration_approach = "onprem_preferred"
        cloud_m365_tier          = None
        recommend_avd            = False
        if not cloud_onprem_anchors:
            cloud_onprem_anchors.append(
                f"Infrastructure complexity ({server_count} servers, {device_count} devices) favours on-premises"
            )

    # ── Server storage total (for Datto sizing) ───────────────────────────
    # Pull actual disk totals from AD WMI data when available;
    # fall back to a conservative 1 TB-per-server estimate.
    total_server_storage_tb = 0.0
    if ad_available:
        for _cname, h in (ad.get("hardware") or {}).items():
            if h.get("wmi_accessible") and h.get("disks"):
                disk_gb = sum(d.get("size_gb", 0) for d in h["disks"])
                total_server_storage_tb += disk_gb / 1024.0
    if total_server_storage_tb == 0 and server_count > 0:
        total_server_storage_tb = server_count * 1.0   # 1 TB/server estimate

    ad_context = {}
    if ad_available:
        hw = ad.get("hardware", {})
        # Summarise hardware across all servers for the AI prompt
        hw_summaries = []
        for cname, h in hw.items():
            if h.get("wmi_accessible"):
                parts = []
                if h.get("manufacturer") and h.get("model"):
                    parts.append(f"{h['manufacturer']} {h['model']}")
                if h.get("cpu_name"):
                    parts.append(f"{h['cpu_socket_count']}x {h['cpu_name']} "
                                 f"({h.get('cpu_cores_total','?')} cores)")
                if h.get("total_ram_gb"):
                    parts.append(f"{h['total_ram_gb']} GB RAM")
                if h.get("disks"):
                    dsz = sum(d.get("size_gb", 0) for d in h["disks"])
                    parts.append(f"{len(h['disks'])}x disk ({dsz} GB total)")
                if h.get("uptime_days") is not None:
                    parts.append(f"up {h['uptime_days']} days")
                if parts:
                    hw_summaries.append(f"  {cname}: " + ", ".join(parts))

        ad_context = {
            "user_count":        ad.get("user_count", 0),
            "enabled_users":     ad.get("enabled_user_count", 0),
            "domain_admins":     len(ad.get("domain_admins", [])),
            "stale_users":       len(ad.get("stale_users", [])),
            "service_accounts":  len(ad.get("service_accounts", [])),
            "pwd_never_expires": len(ad.get("password_never_expires", [])),
            "stale_computers":   len(ad.get("stale_computers", [])),
            "security_findings": ad.get("security_findings", []),
            "password_policy":   ad.get("password_policy", {}),
            "hardware_summaries": hw_summaries,
            "gpo_count":         len(ad.get("gpos", [])),
        }

    return {
        "device_count":       device_count,
        "server_count":       server_count,
        "estimated_wired":    estimated_wired,
        "estimated_wireless": estimated_wireless,
        "download_mbps":      dl_mbps,
        "upload_mbps":        ul_mbps,
        "isp":                isp,
        "domain":             domain,
        "wifi_network_count": wifi_net_count,
        "existing_vendors":   existing_vendors,
        "has_watchguard":     has_watchguard,
        "has_aruba":          has_aruba,
        "has_consumer_wifi":  len(has_consumer_wifi) > 0,
        "consumer_wifi_brands": has_consumer_wifi,
        "eol_server_count":   eol_server_count,
        "subnet":             subnet,
        # AD credentialed scan data (empty dict if proxy was not used)
        "ad_available":            ad_available,
        "ad":                      ad_context,
        # Datto sizing input
        "total_server_storage_tb": round(total_server_storage_tb, 1),
        # Virtualization
        "is_virtualized":       is_virtualized,
        "vm_count":             vm_count,
        "physical_host_count":  physical_host_count,
        # Security software signals
        "recommend_authpoint":  recommend_authpoint,
        "authpoint_reasons":    authpoint_reasons,
        "recommend_epdr":       recommend_epdr,
        "epdr_reasons":         epdr_reasons,
        "enterprise_av_name":   enterprise_av_name,
        "free_av_name":         free_av_name,
        # Cloud / M365 migration assessment
        "cloud_migration_confidence":  cloud_migration_confidence,
        "cloud_migration_approach":    cloud_migration_approach,
        "cloud_m365_tier":             cloud_m365_tier,
        "recommend_avd":               recommend_avd,
        "cloud_migration_reasons":     cloud_migration_reasons,
        "cloud_onprem_anchors":        cloud_onprem_anchors,
        "cloud_user_count":            _cloud_user_count,
        "cloud_has_exchange":          _cloud_has_exchange,
        "cloud_has_rds":               _cloud_has_rds,
        "cloud_has_sql":               _cloud_has_sql,
        "cloud_internet_quality":      _cloud_internet,
    }


# ── Product selection ─────────────────────────────────────────────────────────

def _select_firewall(env: dict, catalog: dict) -> dict:
    """Return the best-fit firewall product dict from the catalog."""
    devices = env["device_count"]
    candidates = [p for p in catalog.get("firewalls", [])
                  if p["min_devices"] <= devices <= p["max_devices"]]
    if not candidates:
        # Device count exceeds all catalog entries — return the largest
        candidates = catalog.get("firewalls", [])
        return max(candidates, key=lambda p: p["max_devices"]) if candidates else {}
    # Prefer the smallest model that covers the device count (least over-spec)
    return min(candidates, key=lambda p: p["max_devices"])


def _select_switches(env: dict, catalog: dict) -> tuple:
    """
    Return (product_dict, switch_count).
    Switch count is how many of that model are needed to cover estimated wired
    devices with 25% growth headroom.
    Returns ({}, 1) if the catalog has no switch entries.
    """
    all_switches = catalog.get("switches", [])
    if not all_switches:
        return {}, 1

    wired      = env["estimated_wired"]
    ports_need = max(8, int(wired * 1.25))  # 25% growth room

    # All switches are candidates — the filter below just separates "single covers it" vs "need to stack"
    single = [s for s in all_switches if s["ports"] >= ports_need]
    if single:
        product = min(single, key=lambda s: s["ports"])
        count = 1
    else:
        # Need multiple switches — use the largest available model
        product = max(all_switches, key=lambda s: s["ports"])
        count   = math.ceil(ports_need / product["ports"])

    return product, count


def _select_aps(env: dict, catalog: dict) -> Optional[tuple]:
    """
    Return (product_dict, ap_count) or None if wireless is not a concern.
    """
    wireless   = env["estimated_wireless"]
    has_cwifi  = env["has_consumer_wifi"]
    wifi_count = env["wifi_network_count"]

    # Skip AP recommendations only if no wireless detected and no consumer APs
    if wireless == 0 and not has_cwifi and wifi_count == 0:
        return None

    # Pick model: AP32 (Wi-Fi 6E) for dense environments, AP25 (Wi-Fi 6) as standard
    aps = catalog.get("access_points", [])
    indoor_aps = [a for a in aps if a.get("indoor_outdoor") == "Indoor"]
    if not indoor_aps:
        return None

    # Use AP32 (Wi-Fi 6E) for high-density environments (50+ wireless), AP25 otherwise
    if wireless > 50:
        product = next((a for a in indoor_aps if a["model"] == "AP32"), indoor_aps[-1])
    else:
        product = next((a for a in indoor_aps if a["model"] == "AP25"), indoor_aps[0])

    max_clients = product.get("max_clients", 30)
    count = max(1, math.ceil(wireless / max_clients))

    return product, count


def _select_servers(env: dict, catalog: dict) -> Optional[tuple]:
    """
    Return (product_dict, count) or None if no servers detected.

    When virtualisation is detected the recommended count is physical hosts
    (1 per 5 VMs by default), not the raw VM count, and the product is
    selected for a hypervisor workload (highest RAM/core density available).
    """
    server_count = env.get("server_count", 0)
    if server_count == 0:
        return None

    all_servers = catalog.get("servers", [])
    if not all_servers:
        return None

    is_virtualized = env.get("is_virtualized", False)

    if is_virtualized:
        # Recommend physical hosts to consolidate VMs
        host_count = env.get("physical_host_count", max(1, math.ceil(server_count / 5)))
        # Prefer the highest-RAM rack server — it will run the VMs
        rack_servers = [s for s in all_servers
                        if "rack" in (s.get("form_factor") or "").lower()]
        pool = rack_servers if rack_servers else all_servers
        product = max(pool, key=lambda s: s.get("max_ram_gb", 0))
        return product, host_count

    # Non-virtualised: size by raw server count as before
    candidates = [s for s in all_servers
                  if s.get("min_servers", 1) <= server_count <= s.get("max_servers", 99)]
    if not candidates:
        product = max(all_servers, key=lambda s: s.get("max_servers", 0))
    else:
        product = min(candidates, key=lambda s: s.get("max_servers", 99))

    return product, server_count


def _select_security_software(env: dict, catalog: dict) -> dict:
    """
    Return AuthPoint and/or EPDR recommendations based on detected signals.

    Returns dict with optional keys 'authpoint' and 'epdr', each containing
    the product dict from the catalog.
    """
    software = catalog.get("security_software", [])
    by_model = {s.get("model", ""): s for s in software}

    result = {}
    if env.get("recommend_authpoint") and "AuthPoint" in by_model:
        result["authpoint"] = by_model["AuthPoint"]
    if env.get("recommend_epdr") and "EPDR" in by_model:
        result["epdr"] = by_model["EPDR"]
    return result


def _select_cloud_migration(env: dict, catalog: dict) -> dict:
    """
    Return M365 tier and optionally AVD based on the cloud migration assessment
    computed in size_environment().

    Returns dict with optional keys:
        "m365"  -> product dict for the recommended M365 Business tier
        "avd"   -> product dict for Azure Virtual Desktop (when RDS detected)
    Returns empty dict when cloud migration is not recommended.
    """
    confidence = env.get("cloud_migration_confidence")
    if confidence is None:
        return {}

    services  = catalog.get("cloud_services", [])
    by_model  = {s.get("model", ""): s for s in services}
    tier      = env.get("cloud_m365_tier", "Business Standard")

    result = {}
    if tier and tier in by_model:
        result["m365"] = by_model[tier]

    if env.get("recommend_avd") and "AVD" in by_model:
        result["avd"] = by_model["AVD"]

    return result


def _select_datto(env: dict, catalog: dict) -> Optional[dict]:
    """
    Select the appropriate Datto BCDR appliance based on server storage.

    Sizing input priority:
      1. total_server_storage_tb from AD WMI hardware inventory (authoritative)
      2. Conservative estimate: server_count × 1 TB

    Returns the product dict, or None if no servers were found.
    """
    if env.get("server_count", 0) == 0:
        return None

    appliances = catalog.get("backup_appliances", [])
    if not appliances:
        return None

    protected_tb = env.get("total_server_storage_tb", 0) or \
                   (env.get("server_count", 0) * 1.0)

    # Find the smallest appliance whose max_protected_tb covers the environment
    candidates = [
        a for a in appliances
        if a.get("max_protected_tb", 0) >= protected_tb
    ]
    if candidates:
        return min(candidates, key=lambda a: a.get("max_protected_tb", 9999))

    # If somehow nothing fits, return the largest appliance
    return max(appliances, key=lambda a: a.get("max_protected_tb", 0))


def select_all_products(env: dict, catalog: dict) -> dict:
    """
    Run all selection functions and return a consolidated recommendations dict.

    Returns:
        {
            "firewall":      {"product": {...}, "reason_signals": [...]},
            "switches":      {"product": {...}, "count": N, "reason_signals": [...]},
            "access_points": {"product": {...}, "count": N, "reason_signals": [...]} | None,
            "servers":       {"product": {...}, "count": N, "reason_signals": [...]} | None,
        }
    Raises ValueError if the catalog is completely empty (no entries in any category).
    """
    if not any(catalog.get(k) for k in ("firewalls", "switches", "access_points", "servers")):
        raise ValueError(
            "Product catalog is empty or could not be loaded. "
            "Ensure lib/product_catalog.json is present and valid."
        )

    fw = _select_firewall(env, catalog)
    sw_product, sw_count = _select_switches(env, catalog)
    ap_result = _select_aps(env, catalog)
    sv_result = _select_servers(env, catalog)
    datto_product = _select_datto(env, catalog)
    sec_sw        = _select_security_software(env, catalog)
    cloud_sw      = _select_cloud_migration(env, catalog)

    # Build reason signals for each recommendation
    fw_signals = [
        f"{env['device_count']} devices on network",
    ]
    if env["download_mbps"] > 0:
        fw_signals.append(
            f"{env['download_mbps']:.0f} Mbps internet connection"
        )
    if env["has_watchguard"]:
        fw_signals.append("Existing WatchGuard appliance detected — upgrade/refresh sizing")
    else:
        fw_signals.append("No enterprise firewall detected on this network")

    sw_signals = [
        f"~{env['estimated_wired']} estimated wired devices",
        f"~{env['estimated_wired'] * 1.25:.0f} ports needed with 25% growth headroom",
    ]
    if env["has_aruba"]:
        sw_signals.append("Aruba equipment already present — consistent platform")

    ap_signals = []
    if env["has_consumer_wifi"]:
        brands = ", ".join(env["consumer_wifi_brands"])
        ap_signals.append(f"Consumer-grade WiFi detected ({brands}) — not suitable for business use")
    if env["wifi_network_count"] > 0:
        ap_signals.append(f"{env['wifi_network_count']} wireless network(s) in use")
    if env["estimated_wireless"] > 0:
        ap_signals.append(f"~{env['estimated_wireless']} estimated wireless devices")

    if env.get("is_virtualized") and env.get("vm_count", 0) > 0:
        vm_n   = env["vm_count"]
        host_n = env.get("physical_host_count", max(1, math.ceil(vm_n / 5)))
        sv_signals = [
            f"{vm_n} virtual machine(s) detected — consolidating onto {host_n} physical host(s)",
            f"Recommended ratio: ~{vm_n // host_n if host_n else vm_n} VMs per host with headroom for growth",
        ]
    else:
        sv_signals = [
            f"{env['server_count']} server(s) identified on network",
        ]
    if env["eol_server_count"] > 0:
        sv_signals.append(
            f"{env['eol_server_count']} EOL server(s) — immediate replacement recommended"
        )

    datto_signals = [
        f"{env['server_count']} server(s) to protect",
    ]
    storage_tb = env.get("total_server_storage_tb", 0)
    if storage_tb > 0:
        source = "WMI" if env.get("ad_available") else "estimated"
        datto_signals.append(
            f"{storage_tb:.1f} TB total server storage ({source}) — sizing basis"
        )
    else:
        datto_signals.append("Server storage estimated at 1 TB per server")
    datto_signals.append("No dedicated BCDR appliance detected on this network")

    result = {
        "firewall": {
            "product":        fw,
            "reason_signals": fw_signals,
        },
        "switches": {
            "product":        sw_product,
            "count":          sw_count,
            "reason_signals": sw_signals,
        },
    }
    if ap_result:
        result["access_points"] = {
            "product":        ap_result[0],
            "count":          ap_result[1],
            "reason_signals": ap_signals,
        }
    else:
        result["access_points"] = None

    if sv_result:
        result["servers"] = {
            "product":        sv_result[0],
            "count":          sv_result[1],
            "reason_signals": sv_signals,
        }
    else:
        result["servers"] = None

    if datto_product:
        result["backup"] = {
            "product":        datto_product,
            "count":          1,
            "reason_signals": datto_signals,
        }
    else:
        result["backup"] = None

    ap_prod = sec_sw.get("authpoint")
    if ap_prod:
        result["authpoint"] = {
            "product":        ap_prod,
            "count":          1,
            "reason_signals": env.get("authpoint_reasons", []),
        }
    else:
        result["authpoint"] = None

    epdr_prod = sec_sw.get("epdr")
    if epdr_prod:
        free_av = env.get("free_av_name", "")
        epdr_signals = list(env.get("epdr_reasons", []))
        if free_av:
            epdr_signals.insert(0, f"Replace {free_av} with enterprise EDR")
        result["epdr"] = {
            "product":        epdr_prod,
            "count":          1,
            "reason_signals": epdr_signals,
        }
    else:
        result["epdr"] = None

    # Cloud / M365 migration assessment
    m365_prod = cloud_sw.get("m365")
    avd_prod  = cloud_sw.get("avd")
    if m365_prod:
        cloud_signals = list(env.get("cloud_migration_reasons", []))
        result["cloud"] = {
            "product":          m365_prod,
            "avd_product":      avd_prod,           # optional AVD pairing
            "confidence":       env.get("cloud_migration_confidence", "low"),
            "approach":         env.get("cloud_migration_approach", "cloud_first"),
            "onprem_anchors":   env.get("cloud_onprem_anchors", []),
            "recommend_avd":    env.get("recommend_avd", False),
            "reason_signals":   cloud_signals,
        }
    else:
        result["cloud"] = None

    return result


# ── Optional Hatz AI narratives ───────────────────────────────────────────────

_HATZ_API_URL   = "https://ai.hatz.ai/v1/chat/completions"
_HATZ_MODEL     = "anthropic.claude-opus-4-6"

_NARRATIVE_SYSTEM = (
    "You are a senior sales engineer at a managed service provider writing concise "
    "product recommendation justifications for a client infrastructure proposal. "
    "Write 2-3 sentences per category explaining why the recommended product is the "
    "right fit for this specific environment. Be specific — reference the actual "
    "device counts, speeds, or detected equipment from the environment data. "
    "Use business-friendly language; avoid deep technical jargon. "
    "Do not invent features not listed in the product specs provided."
)

_NARRATIVE_SECTION_KEYS = ["FIREWALL", "SWITCHING", "WIRELESS", "SERVERS", "BACKUP",
                           "AUTHPOINT", "EPDR", "CLOUD"]


def get_recommendation_narratives(
    env: dict,
    recommendations: dict,
    api_key: str,
) -> dict:
    """
    Call Hatz AI to generate one narrative paragraph per product category.

    Returns dict:  {"firewall": "...", "switching": "...", "wireless": "...", "servers": "..."}
    Returns empty dict on any failure or if api_key is blank.
    """
    if not api_key or not api_key.strip():
        logger.info("Hatz AI: no API key configured — using static recommendation text.")
        return {}

    fw   = recommendations.get("firewall",      {}).get("product", {})
    sw   = recommendations.get("switches",      {})
    ap   = recommendations.get("access_points", {}) or {}
    sv   = recommendations.get("servers",       {}) or {}

    def _spec(product: dict, count: int = 1) -> str:
        if not product:
            return "None recommended"
        vendor = product.get("vendor", "")
        model  = product.get("model",  "")
        best   = product.get("best_for", "")
        note   = f"  ({best})" if best else ""
        qty    = f"{count}x " if count > 1 else ""
        return f"{qty}{vendor} {model}{note}"

    context = f"""ENVIRONMENT SUMMARY:
- Total devices on network: {env['device_count']}
- Estimated wired devices:  {env['estimated_wired']}
- Estimated wireless:       {env['estimated_wireless']}
- Server count:             {env['server_count']}
- Internet speed:           {env['download_mbps']:.0f} Mbps down / {env['upload_mbps']:.0f} Mbps up
- ISP:                      {env['isp'] or 'Unknown'}
- Primary domain:           {env['domain'] or 'Unknown'}
- WatchGuard on network:    {'Yes' if env['has_watchguard'] else 'No'}
- Aruba on network:         {'Yes' if env['has_aruba'] else 'No'}
- Consumer WiFi detected:   {', '.join(env['consumer_wifi_brands']) or 'No'}
"""

    # Append AD credentialed data when available — gives AI much richer context
    if env.get("ad_available") and env.get("ad"):
        ad = env["ad"]
        pp = ad.get("password_policy", {})
        context += f"""
ACTIVE DIRECTORY (credentialed scan — authoritative data):
- Total user accounts:      {ad['user_count']}  (enabled: {ad['enabled_users']})
- Domain Admin accounts:    {ad['domain_admins']}
- Stale enabled users:      {ad['stale_users']} (inactive >90 days)
- Service accounts (SPNs):  {ad['service_accounts']}
- Pwd never expires:        {ad['pwd_never_expires']}
- Stale computers:          {ad['stale_computers']}
- Group Policy objects:     {ad['gpo_count']}
- Password min length:      {pp.get('min_password_length', 'Unknown')} chars
- Lockout threshold:        {pp.get('lockout_threshold', 'Unknown')} attempts
- Complexity enforced:      {'Yes' if pp.get('complexity_enabled') else 'No'}
"""
        if ad.get("hardware_summaries"):
            context += "\nSERVER HARDWARE (from WMI/CIM — use for replacement justification):\n"
            context += "\n".join(ad["hardware_summaries"]) + "\n"

        if ad.get("security_findings"):
            context += "\nSECURITY FINDINGS FROM AD:\n"
            for f in ad["security_findings"]:
                sev = f.get("severity", "info").upper()
                context += f"- [{sev}] {f.get('title', '')}: {f.get('detail', '')}\n"

    context += f"""
RECOMMENDED PRODUCTS:
- Firewall:   {_spec(fw)}
  UTM throughput: {fw.get('utm_throughput_mbps', 'N/A')} Mbps
  Max devices: {fw.get('max_devices', 'N/A')}
- Switching:  {_spec(sw.get('product', {}), sw.get('count', 1))}
  Ports: {sw.get('product', {}).get('ports', 'N/A')} per switch
- Wireless:   {_spec(ap.get('product', {}), ap.get('count', 1)) if ap else 'Not applicable'}
  WiFi standard: {ap.get('product', {}).get('wifi_standard', 'N/A') if ap else 'N/A'}
- Servers:    {_spec(sv.get('product', {}), sv.get('count', 1)) if sv else 'None recommended'}
"""

    bk   = recommendations.get("backup")   or {}
    aup  = recommendations.get("authpoint") or {}
    epdr = recommendations.get("epdr")      or {}
    context += (
        f"- Backup/BCDR:  {_spec(bk.get('product', {})) if bk else 'None recommended'}\n"
        f"  Protected data: {env.get('total_server_storage_tb', 0):.1f} TB\n"
        f"  Local storage: {bk.get('product', {}).get('local_storage_tb', 'N/A') if bk else 'N/A'} TB\n"
    )
    if aup:
        context += (
            f"- MFA:           WatchGuard AuthPoint\n"
            f"  Trigger:       {'; '.join(env.get('authpoint_reasons', []))[:120]}\n"
        )
    if epdr:
        free_av = env.get("free_av_name", "")
        context += (
            f"- Endpoint AV:   WatchGuard EPDR\n"
            f"  Current state: {('Replace ' + free_av) if free_av else 'No enterprise AV detected'}\n"
        )

    cloud_rec = recommendations.get("cloud") or {}
    if cloud_rec:
        _conf     = cloud_rec.get("confidence", "low").upper()
        _approach = cloud_rec.get("approach", "cloud_first").replace("_", " ")
        _tier     = (cloud_rec.get("product") or {}).get("model", "Business Standard")
        _anchors  = "; ".join(cloud_rec.get("onprem_anchors", []))[:160]
        _reasons  = "; ".join(cloud_rec.get("reason_signals", []))[:200]
        context += (
            f"\nCLOUD / M365 MIGRATION ASSESSMENT:\n"
            f"- Confidence:       {_conf}\n"
            f"- Approach:         {_approach}\n"
            f"- Recommended tier: Microsoft 365 {_tier}\n"
            f"- Azure Virtual Desktop: {'Yes -- replace RDS' if cloud_rec.get('recommend_avd') else 'No'}\n"
            f"- Migration drivers: {_reasons}\n"
        )
        if _anchors:
            context += f"- On-prem anchors:  {_anchors}\n"

    sections = "FIREWALL:\nSWITCHING:\nWIRELESS:\nSERVERS:\nBACKUP:\n"
    if aup:
        sections += "AUTHPOINT:\n"
    if epdr:
        sections += "EPDR:\n"
    if cloud_rec:
        sections += "CLOUD:\n"

    user_msg = (
        "Based on the environment data and recommended products below, write a "
        "2-3 sentence justification for each product category. Use EXACTLY these "
        "section headers with a colon, then the narrative on the next line:\n\n"
        + sections + "\n"
        + context
    )

    body = {
        "model":       _HATZ_MODEL,
        "messages":    [
            {"role": "system",  "content": _NARRATIVE_SYSTEM},
            {"role": "user",    "content": user_msg},
        ],
        "stream":      False,
        "temperature": 0.35,
    }

    req = urllib.request.Request(
        _HATZ_API_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "X-API-Key":    api_key.strip(),
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            raw = resp.read().decode("utf-8")
        parsed   = json.loads(raw)
        raw_text = parsed["choices"][0]["message"]["content"]
        logger.info(f"Hatz AI: recommendation narratives received ({len(raw_text)} chars).")
        return _parse_narratives(raw_text)
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode("utf-8", errors="replace")
        except Exception:
            err = e.reason
        logger.warning(f"Hatz AI: HTTP {e.code} — {err}. Using static recommendation text.")
        return {}
    except Exception as e:
        logger.warning(f"Hatz AI: {e}. Using static recommendation text.")
        return {}


def _parse_narratives(text: str) -> dict:
    """Parse the structured AI response into a dict keyed by lowercase category."""
    result = {}
    current_key = None
    lines_buf: list = []

    for line in text.splitlines():
        stripped = line.strip()
        matched  = False
        for key in _NARRATIVE_SECTION_KEYS:
            if stripped.upper().startswith(key + ":"):
                if current_key and lines_buf:
                    result[current_key.lower()] = " ".join(lines_buf).strip()
                current_key = key
                lines_buf   = []
                # Text after the colon on the same line
                after = stripped[len(key) + 1:].strip()
                if after:
                    lines_buf.append(after)
                matched = True
                break
        if not matched and current_key and stripped:
            lines_buf.append(stripped)

    if current_key and lines_buf:
        result[current_key.lower()] = " ".join(lines_buf).strip()

    return result


# ── Static fallback narratives ────────────────────────────────────────────────

def _static_narratives(env: dict, recommendations: dict, brand_name: str = "") -> dict:
    """Generate deterministic fallback narrative text when Hatz AI is unavailable."""
    fw   = recommendations.get("firewall",      {}).get("product", {})
    sw   = recommendations.get("switches",      {})
    ap   = recommendations.get("access_points", {}) or {}
    sv   = recommendations.get("servers",       {}) or {}

    fw_model = f"{fw.get('vendor', 'WatchGuard')} {fw.get('model', 'Firebox')}"
    fw_max   = fw.get("max_devices", env["device_count"])
    utm      = fw.get("utm_throughput_mbps", 0)
    dl       = env["download_mbps"]

    fw_text = (
        f"With {env['device_count']} devices on this network"
        + (f" and a {dl:.0f} Mbps internet connection" if dl > 0 else "")
        + f", the {fw_model} provides the right balance of performance and capacity — "
        f"rated for up to {fw_max} devices with {utm} Mbps of UTM throughput. "
        "The WatchGuard Cloud management platform gives your IT team or MSP full "
        "visibility and policy control from a single pane of glass."
    )
    if env["has_watchguard"]:
        fw_text = (
            f"A WatchGuard appliance is already deployed in this environment. "
            f"Based on the current {env['device_count']}-device network, the {fw_model} "
            "represents the correctly-sized platform for today's load with headroom for growth. "
            "Upgrading ensures the latest threat intelligence, active support, and "
            "access to next-generation subscription services."
        )

    sw_product = sw.get("product", {})
    sw_ports   = sw_product.get("ports", 24)
    sw_count   = sw.get("count", 1)
    sw_model   = f"{sw_product.get('vendor', 'Aruba')} {sw_product.get('model', '')}"
    sw_text = (
        f"With approximately {env['estimated_wired']} wired devices, "
        f"{'a single' if sw_count == 1 else str(sw_count) + 'x'} "
        f"{sw_model} ({sw_ports}-port) provides the right port density with "
        "25% capacity headroom for future growth. "
        "Aruba Instant On switches are cloud-managed through a mobile app, "
        "eliminating the need for complex on-site configuration."
    )

    if ap:
        ap_product = ap.get("product", {})
        ap_count   = ap.get("count", 1)
        ap_model   = f"{ap_product.get('vendor', 'Aruba')} {ap_product.get('model', '')}"
        wifi_std   = ap_product.get("wifi_standard", "Wi-Fi 6")
        if env["has_consumer_wifi"]:
            brands = ", ".join(env["consumer_wifi_brands"])
            ap_text = (
                f"This network currently uses consumer-grade {brands} equipment, "
                f"which lacks the security features, centralised management, and "
                f"reliability required for a business environment. "
                f"{'A single' if ap_count == 1 else str(ap_count) + 'x'} "
                f"{ap_model} running {wifi_std} would provide enterprise-grade "
                "wireless with WPA3 encryption and Instant On cloud management."
            )
        else:
            ap_text = (
                f"{'A single' if ap_count == 1 else str(ap_count) + 'x'} "
                f"{ap_model} running {wifi_std} would provide full coverage for "
                f"~{env['estimated_wireless']} wireless devices with WPA3 security "
                "and centralised management through the Aruba Instant On platform."
            )
    else:
        ap_text = (
            "No wireless assessment data was captured in this scan. "
            f"Contact {brand_name} to schedule a dedicated wireless survey and "
            "receive a tailored access point recommendation."
        )

    if sv:
        sv_product = sv.get("product", {})
        sv_count   = sv.get("count", 1)
        sv_model   = f"{sv_product.get('vendor', 'Dell')} PowerEdge {sv_product.get('model', '')}"

        # Use real hardware data from AD credentialed scan if available
        ad      = env.get("ad", {})
        hw_sums = ad.get("hardware_summaries", [])
        if env.get("ad_available") and hw_sums:
            hw_line = hw_sums[0].strip() if hw_sums else ""
            sv_text = (
                f"The credentialed scan identified {sv_count} server(s) with detailed hardware "
                f"inventory. Current hardware: {hw_line}. "
                f"The {sv_model} is the recommended replacement or expansion platform — "
                "providing current-generation performance, iDRAC remote management, and "
                "OpenManage proactive alerting."
            )
        else:
            sv_text = (
                f"With {sv_count} server(s) identified on the network, "
                f"the {sv_model} provides the right compute and storage capacity "
                "for consolidation or replacement of ageing hardware. "
                "Dell PowerEdge servers include iDRAC remote management and "
                "OpenManage proactive alerting — reducing on-site support requirements."
            )
        if env["eol_server_count"] > 0:
            sv_text = (
                f"{env['eol_server_count']} end-of-life server(s) were identified "
                f"on this network, representing an unacceptable security and reliability risk. "
                f"The {sv_model} is the recommended replacement platform — "
                "providing current-generation performance, vendor support, and "
                "integration with your existing backup and management tools."
            )
    else:
        sv_text = (
            "No servers were identified in this scan. If dedicated server "
            f"infrastructure is required in the future, contact {brand_name} "
            "for a current Dell PowerEdge recommendation."
        )

    # Backup / BCDR narrative
    bk = recommendations.get("backup") or {}
    if bk and bk.get("product"):
        bk_product  = bk["product"]
        bk_model    = f"{bk_product.get('vendor', 'Datto')} {bk_product.get('model', '')}"
        bk_local    = bk_product.get("local_storage_tb", "")
        storage_tb  = env.get("total_server_storage_tb", 0)
        storage_src = "from the credentialed hardware scan" if env.get("ad_available") \
                      else "estimated"
        bk_text = (
            f"With {env.get('server_count', 0)} server(s) and approximately "
            f"{storage_tb:.1f} TB of protected data ({storage_src}), "
            f"the {bk_model} ({bk_local} TB local storage) provides the right capacity for "
            "local backup, instant on-site virtualization, and automatic off-site replication "
            "to the Datto Cloud. "
            "In the event of ransomware or hardware failure, servers can be running in "
            "the Datto appliance within minutes — not hours or days."
        )
    else:
        bk_text = (
            "No servers requiring backup protection were identified in this scan. "
            f"Contact {brand_name} for a Datto BCDR recommendation when server "
            "infrastructure is deployed."
        )

    # AuthPoint (MFA) narrative
    aup = recommendations.get("authpoint") or {}
    if aup:
        reasons = env.get("authpoint_reasons", [])
        trigger = reasons[0] if reasons else "remote access detected on this network"
        aup_text = (
            f"WatchGuard AuthPoint MFA is recommended because {trigger.lower()}. "
            "AuthPoint integrates natively with the WatchGuard Firebox for VPN authentication "
            "and supports RDP, cloud apps, and on-premises services via RADIUS and SAML -- "
            "without requiring a separate RADIUS server. "
            "One-tap push authentication and device DNA fingerprinting stop credential-based attacks "
            "even when passwords are compromised."
        )
    else:
        aup_text = ""

    # EPDR narrative
    epdr_rec = recommendations.get("epdr") or {}
    if epdr_rec:
        free_av = env.get("free_av_name", "")
        if free_av:
            epdr_text = (
                f"{free_av} was detected on this network -- a consumer-grade product that lacks "
                "the behavioral detection, EDR capabilities, and centralised management "
                "required for a business environment. "
                "WatchGuard EPDR uses a Zero-Trust Application Service to block unknown processes "
                "by default, combined with AI-powered threat hunting and automatic ransomware rollback. "
                "Management is unified with the WatchGuard Cloud console alongside the Firebox."
            )
        else:
            epdr_text = (
                f"No enterprise endpoint protection was detected across the {env['device_count']} "
                "devices on this network, representing a significant and common attack surface. "
                "WatchGuard EPDR deploys a lightweight cloud-managed agent that blocks unknown "
                "processes by default (Zero-Trust), detects ransomware behaviour, and provides "
                "full EDR capabilities -- all managed from the same WatchGuard Cloud console "
                "as the Firebox."
            )
    else:
        epdr_text = ""

    # Cloud / M365 migration narrative
    cloud_rec = recommendations.get("cloud") or {}
    if cloud_rec:
        _tier     = (cloud_rec.get("product") or {}).get("model", "Business Standard")
        _conf     = cloud_rec.get("confidence", "low")
        _approach = cloud_rec.get("approach", "cloud_first")
        _anchors  = cloud_rec.get("onprem_anchors", [])
        _avd      = cloud_rec.get("recommend_avd", False)

        if _approach == "full_cloud":
            cloud_text = (
                f"With {env.get('cloud_user_count', env['device_count'])} users and minimal "
                f"on-premises dependency, this environment is an excellent candidate for a full "
                f"Microsoft 365 {_tier} migration. "
                "Moving email, identity, file storage, and collaboration to the Microsoft cloud "
                "eliminates the cost and complexity of maintaining local server infrastructure, "
                "while delivering enterprise-grade security and compliance tools out of the box."
            )
        elif _approach == "hybrid":
            anchor_note = (f" {_anchors[0].split('--')[0].strip()} will remain on-premises."
                           if _anchors else "")
            cloud_text = (
                f"A hybrid approach is recommended for this environment: migrate email, identity, "
                f"and collaboration workloads to Microsoft 365 {_tier} while retaining on-premises "
                f"servers for specialised workloads.{anchor_note} "
                "This staged strategy reduces risk, delivers immediate productivity gains from "
                "Teams and Exchange Online, and lays the foundation for a full cloud transition "
                "at the organisation's own pace."
            )
        else:   # cloud_first
            cloud_text = (
                f"Even without a full server migration, adopting Microsoft 365 {_tier} for email, "
                "Teams, and OneDrive is a low-risk first step that delivers immediate value. "
                "Collaboration moves to the cloud while existing on-premises servers continue to "
                "support workloads that are not yet cloud-ready -- a practical starting point for "
                "any modernisation journey."
            )

        if _avd:
            cloud_text += (
                " An on-premises Remote Desktop server was detected in this environment. "
                "Azure Virtual Desktop (AVD) is a direct replacement that streams Windows "
                "desktops and applications from Azure, eliminating the need to maintain "
                "terminal server hardware while improving security through modern conditional access."
            )
    else:
        cloud_text = ""

    return {
        "firewall":   fw_text,
        "switching":  sw_text,
        "wireless":   ap_text,
        "servers":    sv_text,
        "backup":     bk_text,
        "authpoint":  aup_text,
        "epdr":       epdr_text,
        "cloud":      cloud_text,
    }


# ── PDF drawing helpers ───────────────────────────────────────────────────────

def _draw_wrapped(c, text: str, x: float, y: float, max_w: float,
                  font: str = "Helvetica", size: float = 9,
                  color: str = "#333333", line_h: float = 13) -> float:
    """Draw word-wrapped text. Returns y below the last line."""
    c.setFont(font, size)
    c.setFillColor(_hex(color))
    words = text.split()
    line  = ""
    for word in words:
        test = (line + " " + word).strip()
        if c.stringWidth(test, font, size) <= max_w:
            line = test
        else:
            if line:
                c.drawString(x, y, line)
                y -= line_h
            line = word
    if line:
        c.drawString(x, y, line)
        y -= line_h
    return y


def _draw_page_header(c, title: str, subtitle: str,
                      scan_date: str, brand_name: str,
                      company_color: str) -> float:
    """Draw the standard page header band. Returns y just below the band."""
    col = _hex(company_color)
    c.setFillColor(col)
    c.rect(0, PAGE_H - HEADER_H, PAGE_W, HEADER_H, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(MARGIN, PAGE_H - 28, title)
    c.setFont("Helvetica", 9)
    c.setFillColor(_hex("#ffffffcc"))
    c.drawString(MARGIN, PAGE_H - 44, subtitle)
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 28, scan_date)
    return PAGE_H - HEADER_H - 12


def _draw_page_footer(c, scan_date: str, brand_name: str) -> None:
    """Draw the standard dark footer band."""
    c.setFillColor(_hex("#343a40"))
    c.rect(0, 0, PAGE_W, FOOTER_H, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica", 8)
    c.drawCentredString(PAGE_W / 2, FOOTER_H - 16,
                        f"CONFIDENTIAL  |  (c) {datetime.now().year} "
                        f"{brand_name}")
    c.setFillColor(_hex("#aaaaaa"))
    c.setFont("Helvetica", 7)
    c.drawCentredString(PAGE_W / 2, FOOTER_H - 28, f"Analyzed {scan_date}")


def _draw_product_card(c, product: dict, count: int,
                       x: float, y: float, w: float,
                       vendor_color: str) -> float:
    """
    Draw a product card. Returns y below the card.

    Layout:
        Colored header bar  – vendor + model name
        Spec grid           – key numeric specs in a 2-column grid
        Feature bullets     – up to 4 key features
    """
    if not product:
        return y

    vendor   = product.get("vendor", "")
    model    = product.get("model",  "")
    vc       = _hex(VENDOR_COLORS.get(vendor, vendor_color))

    # ── Estimate card height ───────────────────────────────────────────────
    features = product.get("key_features", [])[:4]
    n_specs  = _count_specs(product)
    spec_h   = math.ceil(n_specs / 2) * 20 + 12   # row_h=20, 12px padding
    feat_h   = len(features) * 16 + 10
    card_h   = 36 + spec_h + feat_h + 12   # header + specs + features + padding

    # ── Card background ────────────────────────────────────────────────────
    c.setFillColor(white)
    c.setStrokeColor(vc)
    c.setLineWidth(1.2)
    c.roundRect(x, y - card_h, w, card_h, 4, fill=1, stroke=1)

    # ── Colored header ─────────────────────────────────────────────────────
    c.setFillColor(vc)
    c.roundRect(x, y - 28, w, 28, 4, fill=1, stroke=0)
    # Cover only bottom corners of header to get flat bottom join
    c.rect(x, y - 28, w, 14, fill=1, stroke=0)

    qty_label = f"{count}x " if count > 1 else ""
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x + 10, y - 18, f"{qty_label}{vendor} {model}")

    c.setFont("Helvetica", 8)
    c.setFillColor(_hex("#ffffffcc"))
    best_for = product.get("best_for", "")
    if best_for and c.stringWidth(best_for, "Helvetica", 8) < w - 20:
        c.drawString(x + 10, y - 26, best_for)

    # ── Spec grid ─────────────────────────────────────────────────────────
    sy = y - 28 - 6
    _draw_spec_grid(c, product, x + 8, sy, w - 16)
    sy -= spec_h

    # ── Feature bullets ────────────────────────────────────────────────────
    sy -= 6
    for feat in features:
        c.setFillColor(vc)
        c.circle(x + 14, sy + 4, 2.5, fill=1, stroke=0)
        c.setFont("Helvetica", 8.5)
        c.setFillColor(_hex("#222222"))
        _draw_wrapped(c, feat, x + 22, sy, w - 32, size=8.5, line_h=12)
        sy -= 16

    return y - card_h - 6


def _count_specs(product: dict) -> int:
    """
    Count how many spec rows _draw_spec_grid will render for this product.
    MUST stay in sync with _draw_spec_grid — add a key here whenever a new
    spec is added to the grid, so card heights are calculated correctly.
    """
    n = 0
    # Firewall specs
    for k in ("stateful_throughput_gbps", "utm_throughput_mbps",
              "vpn_throughput_mbps", "max_devices", "interfaces"):
        if product.get(k) is not None:
            n += 1
    # form_factor only rendered for firewalls (when stateful_throughput_gbps present)
    if product.get("form_factor") and product.get("stateful_throughput_gbps"):
        n += 1
    # Switch specs — "ports" only rendered when not a firewall
    if product.get("ports") and not product.get("stateful_throughput_gbps"):
        n += 1
    for k in ("poe_ports", "poe_budget_w", "uplinks", "layer"):
        if product.get(k) is not None:
            n += 1
    # AP specs
    for k in ("wifi_standard", "max_throughput_mbps", "max_clients",
              "bands", "poe_required"):
        if product.get(k) is not None:
            n += 1
    # Security software specs
    for k in ("deployment", "authentication_methods", "detection_engine",
              "platforms", "integrations", "management"):
        if product.get(k) is not None:
            n += 1
    # Server specs
    for k in ("processor", "max_ram_gb", "max_storage"):
        if product.get(k) is not None:
            n += 1
    # raid_support only rendered when form_factor also present
    if product.get("raid_support") and product.get("form_factor"):
        n += 1
    return n


def _draw_spec_grid(c, product: dict, x: float, y: float, w: float) -> None:
    """Draw a 2-column spec table inside a product card."""
    specs: list = []

    # Firewall specs
    if "stateful_throughput_gbps" in product:
        specs.append(("Stateful Throughput",
                       f"{product['stateful_throughput_gbps']} Gbps"))
    if "utm_throughput_mbps" in product:
        mbps = product["utm_throughput_mbps"]
        label = f"{mbps/1000:.1f} Gbps" if mbps >= 1000 else f"{mbps} Mbps"
        specs.append(("UTM Throughput", label))
    if "vpn_throughput_mbps" in product:
        mbps = product["vpn_throughput_mbps"]
        label = f"{mbps/1000:.1f} Gbps" if mbps >= 1000 else f"{mbps} Mbps"
        specs.append(("VPN Throughput", label))
    if "max_devices" in product:
        specs.append(("Max Devices", str(product["max_devices"])))
    if "interfaces" in product:
        specs.append(("Interfaces", product["interfaces"]))
    if "form_factor" in product and "stateful_throughput_gbps" in product:
        specs.append(("Form Factor", product["form_factor"]))

    # Switch specs
    if "ports" in product and "stateful_throughput_gbps" not in product:
        specs.append(("Total Ports", str(product["ports"])))
    if "poe_ports" in product:
        specs.append(("PoE Ports", str(product["poe_ports"])))
    if "poe_budget_w" in product:
        specs.append(("PoE Budget", f"{product['poe_budget_w']} W"))
    if "uplinks" in product:
        specs.append(("Uplinks", product["uplinks"]))
    if "layer" in product:
        specs.append(("Switching Layer", product["layer"]))

    # AP specs
    if "wifi_standard" in product:
        specs.append(("WiFi Standard", product["wifi_standard"]))
    if "max_throughput_mbps" in product:
        specs.append(("Max Throughput", f"{product['max_throughput_mbps']} Mbps"))
    if "max_clients" in product:
        specs.append(("Max Clients/AP", str(product["max_clients"])))
    if "bands" in product:
        specs.append(("Bands", product["bands"]))
    if "poe_required" in product:
        specs.append(("PoE Required", product["poe_required"]))

    # Security software specs
    if "deployment" in product:
        specs.append(("Deployment", product["deployment"]))
    if "authentication_methods" in product:
        specs.append(("Auth Methods", product["authentication_methods"]))
    if "detection_engine" in product:
        specs.append(("Detection Engine", product["detection_engine"]))
    if "platforms" in product:
        specs.append(("Platforms", product["platforms"]))
    if "integrations" in product:
        specs.append(("Integrations", product["integrations"][:45]))
    if "management" in product:
        specs.append(("Management", product["management"]))

    # Server specs
    if "processor" in product:
        specs.append(("Processor", product["processor"]))
    if "max_ram_gb" in product:
        specs.append(("Max RAM", f"{product['max_ram_gb']} GB"))
    if "max_storage" in product:
        specs.append(("Max Storage", product["max_storage"]))
    if "raid_support" in product and "form_factor" in product:
        specs.append(("RAID", product["raid_support"][:40]))

    col_w = w / 2 - 4
    row_h = 20       # MUST match spec_h formula in _draw_product_card
    for i, (label, value) in enumerate(specs):
        cx  = x + (i % 2) * (col_w + 8)
        cy  = y - (i // 2) * row_h

        # Alternating row shade (full-width band across both columns)
        if (i // 2) % 2 == 0:
            band_x = x - 2
            band_w = w + 4
            c.setFillColor(_hex("#f8f9fa"))
            c.rect(band_x, cy - row_h + 4, band_w, row_h, fill=1, stroke=0)

        c.setFont("Helvetica", 7)
        c.setFillColor(_hex("#888888"))
        c.drawString(cx + 2, cy - 5, label.upper())
        c.setFont("Helvetica-Bold", 8.5)
        c.setFillColor(_hex("#111111"))
        # Truncate long values to fit column width
        disp = value if c.stringWidth(value, "Helvetica-Bold", 8.5) <= col_w - 8 else value[:32] + "..."
        c.drawString(cx + 2, cy - 15, disp)


# ── Cover page ────────────────────────────────────────────────────────────────

def _draw_cover(c, client_name: str, scan_date: str,
                env: dict, brand_name: str, brand_tagline: str,
                company_color: str) -> None:
    """Draw the recommendations report cover page."""
    col = _hex(company_color)

    # ── Header band ────────────────────────────────────────────────────────
    header_h = 90
    c.setFillColor(col)
    c.rect(0, PAGE_H - header_h, PAGE_W, header_h, fill=1, stroke=0)

    c.setFillColor(_hex("#ffffff99"))
    c.setFont("Helvetica", 8)
    c.drawString(MARGIN, PAGE_H - 20, "INFRASTRUCTURE RECOMMENDATIONS FOR")
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 20, "DATE")

    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(MARGIN, PAGE_H - 46, client_name[:48])

    c.setFont("Helvetica", 11)
    c.setFillColor(_hex("#ffffffcc"))
    c.drawString(MARGIN, PAGE_H - 64, "Network Infrastructure Assessment & Technology Recommendations")

    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 12)
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 46, scan_date)

    # ── Prepared by ────────────────────────────────────────────────────────
    c.setFillColor(_hex("#f8f9fa"))
    c.rect(0, PAGE_H - header_h - 36, PAGE_W, 36, fill=1, stroke=0)
    c.setFillColor(_hex("#555555"))
    c.setFont("Helvetica", 9)
    c.drawString(MARGIN, PAGE_H - header_h - 14, "PREPARED BY")
    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(_hex("#222222"))
    c.drawString(MARGIN, PAGE_H - header_h - 27, f"{brand_name}  |  {brand_tagline}")

    # ── "What's Inside" section ────────────────────────────────────────────
    title_y = PAGE_H - header_h - 80
    c.setFillColor(_hex("#343a40"))
    c.setFont("Helvetica-Bold", 13)
    c.drawString(MARGIN, title_y, "What's Inside This Report")
    c.setFont("Helvetica", 9)
    c.setFillColor(_hex("#555555"))
    c.drawString(MARGIN, title_y - 16,
                 "Based on your network scan, we've identified the right-sized "
                 "infrastructure across 4 key areas:")

    # Vendor/category cards
    categories = [
        ("Firewall Security",      "WatchGuard Firebox",           "#c8102e"),
        ("Network Switching",      "Aruba Instant On Switches",    "#ff6b00"),
        ("Wireless Infrastructure","Aruba Instant On Access Points","#ff6b00"),
        ("Server Hardware",        "Dell PowerEdge Servers",       "#007db8"),
    ]
    card_y   = title_y - 40
    card_w   = (CONTENT_W - 12) / 2
    card_h   = 62

    for i, (cat, brand, clr) in enumerate(categories):
        cx = MARGIN + (i % 2) * (card_w + 12)
        cy = card_y - (i // 2) * (card_h + 10)

        c.setFillColor(_hex(clr))
        c.roundRect(cx, cy - card_h, card_w, card_h, 4, fill=1, stroke=0)

        c.setFillColor(white)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(cx + 10, cy - 22, cat)
        c.setFont("Helvetica", 8.5)
        c.setFillColor(_hex("#ffffffcc"))
        c.drawString(cx + 10, cy - 36, brand)

    # ── Environment summary strip ──────────────────────────────────────────
    strip_y = card_y - 2 * (card_h + 10) - 20
    c.setFillColor(_hex("#f1f3f5"))
    c.rect(MARGIN, strip_y - 54, CONTENT_W, 54, fill=1, stroke=0)

    stats = [
        (str(env["device_count"]),     "Devices Discovered"),
        (str(env["server_count"]),      "Servers Identified"),
        (f"{env['download_mbps']:.0f} Mbps" if env["download_mbps"] else "N/A",
                                        "Internet Speed"),
        (env.get("domain") or "Unknown", "Primary Domain"),
    ]
    sw = CONTENT_W / len(stats)
    for i, (val, lbl) in enumerate(stats):
        sx = MARGIN + i * sw + sw / 2
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(col)
        c.drawCentredString(sx, strip_y - 22, val[:14])
        c.setFont("Helvetica", 7.5)
        c.setFillColor(_hex("#666666"))
        c.drawCentredString(sx, strip_y - 36, lbl)

    # ── Footer ─────────────────────────────────────────────────────────────
    c.setFillColor(_hex("#343a40"))
    c.rect(0, 0, PAGE_W, FOOTER_H, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica", 8)
    c.drawCentredString(PAGE_W / 2, FOOTER_H - 16,
                        f"CONFIDENTIAL  |  (c) {datetime.now().year} "
                        f"{brand_name}  |  {brand_tagline}")
    c.setFillColor(_hex("#aaaaaa"))
    c.setFont("Helvetica", 7)
    c.drawCentredString(PAGE_W / 2, FOOTER_H - 28, f"Prepared {scan_date}")


# ── Cloud assessment page ─────────────────────────────────────────────────────

def _draw_cloud_page(c, cloud_rec: dict, narrative: str,
                     scan_date: str, brand_name: str,
                     company_color: str) -> None:
    """
    Render a cloud / Microsoft 365 migration assessment page.

    Unlike hardware spec pages this page shows a strategic assessment card:
      - Confidence badge (HIGH / MEDIUM / LOW)
      - Recommended M365 tier with key features
      - Migration drivers (why cloud makes sense)
      - On-premises anchors (what stays on-prem, if any)
      - AVD callout if an RDS server was detected
      - Narrative text at the bottom
    """
    _MS_BLUE   = "#0078d4"    # Microsoft brand blue
    _AVD_TEAL  = "#00a0d9"    # Azure colour accent
    _CONF_COL  = {"high": "#28a745", "medium": "#fd7e14", "low": "#6c757d"}

    confidence  = cloud_rec.get("confidence", "low")
    approach    = (cloud_rec.get("approach") or "cloud_first").replace("_", " ").title()
    product     = cloud_rec.get("product") or {}
    avd_product = cloud_rec.get("avd_product")
    anchors     = cloud_rec.get("onprem_anchors", [])
    reasons     = cloud_rec.get("reason_signals", [])
    recommend_avd = cloud_rec.get("recommend_avd", False)

    tier_name   = product.get("model", "Business Standard")
    features    = product.get("key_features", [])
    best_for    = product.get("best_for", "")

    conf_color  = _CONF_COL.get(confidence, "#6c757d")
    conf_label  = confidence.upper()

    # ── Page header ──────────────────────────────────────────────────────
    y = _draw_page_header(
        c,
        title     = "CLOUD & INFRASTRUCTURE STRATEGY",
        subtitle  = f"Microsoft 365 Migration Assessment  --  {approach}",
        scan_date = scan_date,
        brand_name     = brand_name,
        company_color  = company_color,
    )
    y -= 6

    # ── Confidence badge ─────────────────────────────────────────────────
    badge_w, badge_h = 140, 28
    c.setFillColor(_hex(conf_color))
    c.roundRect(MARGIN, y - badge_h, badge_w, badge_h, 4, fill=1, stroke=0)
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(MARGIN + 10, y - 18, f"MIGRATION FIT:  {conf_label}")

    # Approach label beside badge
    c.setFillColor(_hex("#343a40"))
    c.setFont("Helvetica-Bold", 9)
    c.drawString(MARGIN + badge_w + 12, y - 10, approach)
    c.setFont("Helvetica", 8)
    c.setFillColor(_hex("#666666"))
    approach_desc = {
        "Full Cloud":   "Migrate all workloads and identity to Microsoft 365 -- eliminate on-prem servers",
        "Hybrid":       "Move email, identity and collaboration to M365 -- retain servers for specialised workloads",
        "Cloud First":  "Start with M365 email and Teams -- plan server migration in future phases",
    }.get(approach, "Evaluate Microsoft 365 for collaboration and productivity workloads")
    c.drawString(MARGIN + badge_w + 12, y - 21, approach_desc[:90])

    y -= badge_h + 14

    # ── Two-column layout ─────────────────────────────────────────────────
    col_gap    = 14
    left_w     = (CONTENT_W - col_gap) * 0.46
    right_w    = CONTENT_W - left_w - col_gap
    left_x     = MARGIN
    right_x    = MARGIN + left_w + col_gap

    col_top_y  = y

    # LEFT: Migration drivers
    c.setFillColor(_hex("#343a40"))
    c.setFont("Helvetica-Bold", 9)
    c.drawString(left_x, y, "WHY MIGRATE TO CLOUD")
    y -= 12

    for reason in reasons[:6]:
        # Bullet + word-wrap within left column
        c.setFillColor(_hex(conf_color))
        c.setFont("Helvetica-Bold", 10)
        c.drawString(left_x, y, "\u2022")
        c.setFont("Helvetica", 8)
        c.setFillColor(_hex("#333333"))
        # Wrap reason text
        words    = reason.replace(" -- ", ": ").split()
        line     = ""
        first    = True
        line_x   = left_x + 12
        line_w   = left_w - 14
        for word in words:
            test = (line + " " + word).strip()
            if c.stringWidth(test, "Helvetica", 8) <= line_w:
                line = test
            else:
                if line:
                    c.drawString(line_x, y, line)
                    y -= 11
                    first = False
                line = word
        if line:
            c.drawString(line_x, y, line)
            y -= 11
        y -= 3

    # On-prem anchors (what stays behind)
    if anchors:
        y -= 4
        c.setFillColor(_hex("#343a40"))
        c.setFont("Helvetica-Bold", 9)
        c.drawString(left_x, y, "WHAT STAYS ON-PREMISES")
        y -= 12
        for anchor in anchors[:4]:
            c.setFillColor(_hex("#888888"))
            c.setFont("Helvetica-Bold", 10)
            c.drawString(left_x, y, "\u2013")
            c.setFont("Helvetica", 8)
            c.setFillColor(_hex("#555555"))
            short = anchor.split(" -- ")[0][:80]
            c.drawString(left_x + 12, y, short)
            y -= 12

    # RIGHT: M365 tier recommendation card
    ry = col_top_y
    card_h = 170
    c.setFillColor(_hex(_MS_BLUE))
    c.roundRect(right_x, ry - card_h, right_w, card_h, 6, fill=1, stroke=0)

    # Microsoft logo text + tier
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(right_x + 10, ry - 20, "Microsoft 365")
    c.setFont("Helvetica-Bold", 13)
    c.drawString(right_x + 10, ry - 36, tier_name)

    # Divider
    c.setStrokeColor(_hex("#ffffff55"))
    c.setLineWidth(0.5)
    c.line(right_x + 10, ry - 44, right_x + right_w - 10, ry - 44)

    # Features list
    feat_y = ry - 56
    for feat in features[:5]:
        c.setFillColor(_hex("#ffffffcc"))
        c.setFont("Helvetica", 7.5)
        short_feat = feat[:62] if len(feat) > 62 else feat
        c.drawString(right_x + 10, feat_y, f"\u2713  {short_feat}")
        feat_y -= 14

    # Best for note
    if best_for:
        c.setFillColor(_hex("#ffffff88"))
        c.setFont("Helvetica-Oblique", 7)
        c.drawString(right_x + 10, ry - card_h + 10, best_for[:72])

    # AVD callout below the M365 card
    if recommend_avd and avd_product:
        avd_card_y = ry - card_h - 8
        avd_h      = 60
        c.setFillColor(_hex(_AVD_TEAL))
        c.roundRect(right_x, avd_card_y - avd_h, right_w, avd_h, 6, fill=1, stroke=0)
        c.setFillColor(white)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(right_x + 10, avd_card_y - 14, "Azure Virtual Desktop")
        c.setFont("Helvetica", 7.5)
        c.setFillColor(_hex("#ffffffcc"))
        avd_feats = (avd_product.get("key_features") or [])[:2]
        avd_fy = avd_card_y - 27
        for af in avd_feats:
            c.drawString(right_x + 10, avd_fy, f"\u2713  {af[:58]}")
            avd_fy -= 13
        c.setFont("Helvetica-Oblique", 7)
        c.setFillColor(_hex("#ffffff88"))
        c.drawString(right_x + 10, avd_card_y - avd_h + 8,
                     "Replaces on-premises Remote Desktop Services")

    # ── Narrative ────────────────────────────────────────────────────────
    narrative_y = min(y - 14,
                      col_top_y - card_h - (68 if recommend_avd else 0) - 14)
    narrative_y = max(narrative_y, FOOTER_H + 90)

    c.setFillColor(_hex("#f0f4f8"))
    c.roundRect(MARGIN, narrative_y - 70, CONTENT_W, 70, 4, fill=1, stroke=0)
    c.setFillColor(_hex("#0078d4"))
    c.setFont("Helvetica-Bold", 8)
    c.drawString(MARGIN + 10, narrative_y - 14, "ASSESSMENT SUMMARY")
    if narrative:
        _draw_wrapped(c, narrative, MARGIN + 10, narrative_y - 26,
                      CONTENT_W - 20, size=8, color="#333333", line_h=12)

    _draw_page_footer(c, scan_date, brand_name)


# ── Product category pages ────────────────────────────────────────────────────

def _draw_category_page(c, title: str, subtitle: str,
                        current_state_lines: list,
                        product: dict, count: int,
                        narrative: str,
                        scan_date: str, brand_name: str,
                        company_color: str) -> None:
    """
    Draw a single product category recommendation page.

    Args:
        current_state_lines : list of str describing what was found
        product             : product dict from catalog
        count               : quantity recommended
        narrative           : 2-3 sentence justification string
    """
    vendor        = product.get("vendor", "") if product else ""
    vendor_color  = VENDOR_COLORS.get(vendor, company_color)

    y = _draw_page_header(c, "NETWORK INFRASTRUCTURE RECOMMENDATIONS",
                          subtitle, scan_date, brand_name, company_color)
    y -= 8

    # ── "Current State" section ────────────────────────────────────────────
    c.setFillColor(_hex("#343a40"))
    c.setFont("Helvetica-Bold", 10)
    c.drawString(MARGIN, y, "CURRENT STATE")
    y -= 4

    box_h = len(current_state_lines) * 14 + 16
    c.setFillColor(_hex("#f8f9fa"))
    c.setStrokeColor(_hex("#dee2e6"))
    c.setLineWidth(0.8)
    c.roundRect(MARGIN, y - box_h, CONTENT_W, box_h, 3, fill=1, stroke=1)

    cy = y - 14
    for line in current_state_lines:
        c.setFillColor(_hex(vendor_color))
        c.circle(MARGIN + 12, cy + 4, 3, fill=1, stroke=0)
        c.setFont("Helvetica", 9)
        c.setFillColor(_hex("#333333"))
        c.drawString(MARGIN + 22, cy, line)
        cy -= 14

    y -= box_h + 14

    # ── "Recommended Solution" section ────────────────────────────────────
    c.setFillColor(_hex("#343a40"))
    c.setFont("Helvetica-Bold", 10)
    c.drawString(MARGIN, y, "RECOMMENDED SOLUTION")
    y -= 8

    card_bottom = _draw_product_card(c, product, count,
                                     MARGIN, y, CONTENT_W,
                                     vendor_color)
    y = card_bottom - 14

    # ── "Why This Recommendation" narrative ───────────────────────────────
    if y > FOOTER_H + 80 and narrative:
        c.setFillColor(_hex("#343a40"))
        c.setFont("Helvetica-Bold", 10)
        c.drawString(MARGIN, y, "WHY THIS RECOMMENDATION")
        y -= 10

        # Light colored background for narrative
        # Estimate height first
        words    = narrative.split()
        est_lines = math.ceil(len(words) / 10)  # rough estimate
        narr_h   = est_lines * 14 + 20

        c.setFillColor(_hex("#fff8f2" if company_color == "#FF6600" else "#f0f8ff"))
        c.setStrokeColor(_hex(vendor_color))
        c.setLineWidth(2)
        c.line(MARGIN, y, MARGIN, y - narr_h)
        c.setLineWidth(0.5)

        y = _draw_wrapped(c, narrative, MARGIN + 12, y - 4,
                          CONTENT_W - 12, size=9.5, line_h=14)

    _draw_page_footer(c, scan_date, brand_name)


# ── Next steps page ───────────────────────────────────────────────────────────

def _draw_next_steps(c, scan_date: str, brand_name: str,
                     brand_tagline: str, client_name: str,
                     company_color: str, recommendations: dict) -> None:
    """Draw the final 'Next Steps' page."""
    col = _hex(company_color)

    y = _draw_page_header(c, "NETWORK INFRASTRUCTURE RECOMMENDATIONS",
                          "Next Steps", scan_date, brand_name, company_color)
    y -= 10

    c.setFont("Helvetica-Bold", 14)
    c.setFillColor(_hex("#343a40"))
    c.drawString(MARGIN, y, "RECOMMENDED NEXT STEPS")
    y -= 20

    steps = [
        ("1. Schedule a Discovery Call",
         f"Review this report with your {brand_name} sales engineer. We'll walk "
         "through each recommendation, confirm sizing, and answer any questions "
         "about the products or implementation approach."),
        ("2. Confirm Scope and Priorities",
         "Not every recommendation needs to happen at once. We'll help you "
         "prioritise based on risk, budget, and operational impact — firewall "
         "and switching infrastructure typically come first."),
        ("3. Receive a Formal Quote",
         "Once scope is confirmed, your sales engineer will provide a detailed "
         "quote including hardware, licensing, and professional services for "
         "design, deployment, and configuration."),
        ("4. Plan the Deployment",
         f"{brand_name} handles the full deployment: preconfiguration, "
         "on-site installation, user training, and handover documentation. "
         "Most SMB deployments are completed with minimal business disruption."),
        ("5. Ongoing Managed Services",
         f"Consider pairing your new infrastructure with {brand_name} managed "
         "services: 24/7 monitoring, firmware management, threat response, and "
         "quarterly security reassessment to keep your environment current."),
    ]

    for title, body in steps:
        if y < FOOTER_H + 80:
            break
        c.setFont("Helvetica-Bold", 10)
        c.setFillColor(col)
        c.drawString(MARGIN, y, title)
        y -= 14
        y = _draw_wrapped(c, body, MARGIN + 10, y, CONTENT_W - 10,
                          size=9, line_h=13, color="#444444")
        y -= 10

    # ── Summary table ──────────────────────────────────────────────────────
    if y > FOOTER_H + 120:
        y -= 10
        c.setFillColor(_hex("#343a40"))
        c.setFont("Helvetica-Bold", 10)
        c.drawString(MARGIN, y, "RECOMMENDATION SUMMARY")
        y -= 14

        rows = []
        fw = recommendations.get("firewall", {}).get("product", {})
        if fw:
            rows.append(("Firewall",
                          f"{fw.get('vendor','')} {fw.get('model','')}",
                          fw.get("best_for", "")))
        sw = recommendations.get("switches", {})
        if sw and sw.get("product"):
            p = sw["product"]
            rows.append(("Switching",
                          f"{sw['count']}x {p.get('vendor','')} {p.get('model','')}",
                          p.get("best_for", "")))
        ap = recommendations.get("access_points") or {}
        if ap and ap.get("product"):
            p = ap["product"]
            rows.append(("Wireless",
                          f"{ap['count']}x {p.get('vendor','')} {p.get('model','')}",
                          p.get("best_for", "")))
        sv = recommendations.get("servers") or {}
        if sv and sv.get("product"):
            p = sv["product"]
            rows.append(("Servers",
                          f"{p.get('vendor','')} {p.get('model','')}",
                          p.get("best_for", "")))

        bk = recommendations.get("backup") or {}
        if bk and bk.get("product"):
            p = bk["product"]
            rows.append(("Backup / BCDR",
                          f"{p.get('vendor','')} {p.get('model','')}",
                          p.get("best_for", "")))

        aup_rec = recommendations.get("authpoint") or {}
        if aup_rec and aup_rec.get("product"):
            p = aup_rec["product"]
            rows.append(("MFA",
                          f"{p.get('vendor','')} {p.get('model','')}",
                          p.get("best_for", "")))

        epdr_rec = recommendations.get("epdr") or {}
        if epdr_rec and epdr_rec.get("product"):
            p = epdr_rec["product"]
            rows.append(("Endpoint Security",
                          f"{p.get('vendor','')} {p.get('model','')}",
                          p.get("best_for", "")))

        cloud_rec = recommendations.get("cloud") or {}
        if cloud_rec and cloud_rec.get("product"):
            p    = cloud_rec["product"]
            conf = cloud_rec.get("confidence", "low").title()
            avd  = " + AVD" if cloud_rec.get("recommend_avd") else ""
            rows.append(("Cloud Strategy",
                          f"Microsoft 365 {p.get('model','')}{avd}",
                          f"[{conf} fit] {p.get('best_for', '')}"))

        col_ws = [90, 130, CONTENT_W - 90 - 130]
        hdr_y  = y
        c.setFillColor(_hex("#343a40"))
        c.rect(MARGIN, hdr_y - 16, CONTENT_W, 16, fill=1, stroke=0)
        for j, (hdr, cw) in enumerate(
                zip(["CATEGORY", "PRODUCT", "BEST FOR"], col_ws)):
            cx = MARGIN + sum(col_ws[:j]) + 6
            c.setFillColor(white)
            c.setFont("Helvetica-Bold", 8)
            c.drawString(cx, hdr_y - 11, hdr)

        y = hdr_y - 16
        for i, row in enumerate(rows):
            row_h = 18
            c.setFillColor(_hex("#f8f9fa") if i % 2 == 0 else white)
            c.rect(MARGIN, y - row_h, CONTENT_W, row_h, fill=1, stroke=0)
            for j, (val, cw) in enumerate(zip(row, col_ws)):
                cx = MARGIN + sum(col_ws[:j]) + 6
                c.setFont("Helvetica", 8.5)
                c.setFillColor(_hex("#222222"))
                # Truncate "BEST FOR" text to fit column width
                if j == 2:
                    while val and c.stringWidth(val, "Helvetica", 8.5) > cw - 12:
                        val = val[:-1]
                c.drawString(cx, y - 12, str(val))
            y -= row_h

        y -= 8
        c.setFont("Helvetica", 7.5)
        c.setFillColor(_hex("#888888"))
        c.drawString(MARGIN, y,
                     f"Contact {brand_name} for current partner pricing and "
                     "solution design. Subscriptions and professional services quoted separately.")

    _draw_page_footer(c, scan_date, brand_name)


# ── Public API ────────────────────────────────────────────────────────────────

def build_product_recommendations_pdf(scan_results: dict, config: dict) -> bytes:
    """
    Build and return the product recommendations PDF as bytes.

    Uses scan_results to size the environment and select products from the
    catalog. Optionally calls Hatz AI (via config.hatz_ai.api_key) to
    generate per-category narrative text.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab is required for PDF reports. "
            "Install: pip install reportlab"
        )

    reporting     = config.get("reporting", {})
    brand_name    = reporting.get("company_name",  "Yeyland Wutani LLC")
    company_color = reporting.get("company_color", "#FF6600")
    brand_tagline = reporting.get("tagline",       "Building Better Systems")
    client_name   = reporting.get("client_name") or _infer_client(scan_results)

    scan_start = scan_results.get("scan_start", "")
    try:
        dt = datetime.fromisoformat(scan_start)
        scan_date = dt.strftime("%m/%d/%Y")
    except Exception:
        scan_date = datetime.now().strftime("%m/%d/%Y")

    # ── Analyse environment + select products ─────────────────────────────
    catalog = load_product_catalog()
    if not catalog or not any(catalog.get(k) for k in
                               ("firewalls", "switches", "access_points", "servers",
                                "backup_appliances")):
        raise FileNotFoundError(
            "product_catalog.json not found or empty. "
            "Ensure lib/product_catalog.json is deployed to "
            "/opt/network-discovery/lib/ (it is included in the repo and "
            "will be synced automatically on the next self-update)."
        )
    env  = size_environment(scan_results)
    recs = select_all_products(env, catalog)

    # ── Narratives (AI or static) ─────────────────────────────────────────
    hatz_key = config.get("hatz_ai", {}).get("api_key", "")
    if hatz_key:
        narratives = get_recommendation_narratives(env, recs, hatz_key)
    else:
        narratives = {}
    if not narratives:
        narratives = _static_narratives(env, recs, brand_name)

    logger.info(
        f"Product recommendations: {env['device_count']} devices, "
        f"{env['server_count']} servers, "
        f"{'AI' if hatz_key else 'static'} narratives."
    )

    # ── Build PDF ─────────────────────────────────────────────────────────
    buf = io.BytesIO()
    c   = rl_canvas.Canvas(buf, pagesize=(PAGE_W, PAGE_H))
    c.setTitle(f"Infrastructure Recommendations — {client_name}")
    c.setAuthor(brand_name)
    c.setSubject("Network Infrastructure Technology Recommendations")

    # Page 1: Cover
    _draw_cover(c, client_name, scan_date, env,
                brand_name, brand_tagline, company_color)
    c.showPage()

    # Page 2: Firewall
    fw         = recs["firewall"]
    fw_product = fw["product"]
    fw_current = fw["reason_signals"]
    _draw_category_page(
        c,
        title     = "NETWORK INFRASTRUCTURE RECOMMENDATIONS",
        subtitle  = "Firewall Security — WatchGuard Firebox",
        current_state_lines = fw_current,
        product   = fw_product,
        count     = 1,
        narrative = narratives.get("firewall", ""),
        scan_date = scan_date, brand_name = brand_name,
        company_color = company_color,
    )
    c.showPage()

    # Page 3: Switching
    sw         = recs["switches"]
    sw_product = sw["product"]
    sw_count   = sw["count"]
    _draw_category_page(
        c,
        title     = "NETWORK INFRASTRUCTURE RECOMMENDATIONS",
        subtitle  = "Network Switching — Aruba Instant On",
        current_state_lines = sw["reason_signals"],
        product   = sw_product,
        count     = sw_count,
        narrative = narratives.get("switching", ""),
        scan_date = scan_date, brand_name = brand_name,
        company_color = company_color,
    )
    c.showPage()

    # Page 4: Wireless (optional)
    ap = recs.get("access_points")
    if ap:
        _draw_category_page(
            c,
            title     = "NETWORK INFRASTRUCTURE RECOMMENDATIONS",
            subtitle  = "Wireless Infrastructure — Aruba Instant On",
            current_state_lines = ap["reason_signals"],
            product   = ap["product"],
            count     = ap["count"],
            narrative = narratives.get("wireless", ""),
            scan_date = scan_date, brand_name = brand_name,
            company_color = company_color,
        )
        c.showPage()

    # Page 5: Servers (optional)
    sv = recs.get("servers")
    if sv:
        _draw_category_page(
            c,
            title     = "NETWORK INFRASTRUCTURE RECOMMENDATIONS",
            subtitle  = "Server Hardware — Dell PowerEdge",
            current_state_lines = sv["reason_signals"],
            product   = sv["product"],
            count     = sv["count"],
            narrative = narratives.get("servers", ""),
            scan_date = scan_date, brand_name = brand_name,
            company_color = company_color,
        )
        c.showPage()

    # Page 6: Backup & Disaster Recovery — Datto (optional, only when servers present)
    bk = recs.get("backup")
    if bk:
        _draw_category_page(
            c,
            title     = "NETWORK INFRASTRUCTURE RECOMMENDATIONS",
            subtitle  = "Backup & Disaster Recovery — Datto BCDR",
            current_state_lines = bk["reason_signals"],
            product   = bk["product"],
            count     = 1,
            narrative = narratives.get("backup", ""),
            scan_date = scan_date, brand_name = brand_name,
            company_color = company_color,
        )
        c.showPage()

    # Page 7: MFA -- WatchGuard AuthPoint (optional, when VPN/RDS detected)
    aup_rec = recs.get("authpoint")
    if aup_rec:
        _draw_category_page(
            c,
            title     = "SECURITY SOFTWARE RECOMMENDATIONS",
            subtitle  = "Multi-Factor Authentication -- WatchGuard AuthPoint",
            current_state_lines = aup_rec["reason_signals"],
            product   = aup_rec["product"],
            count     = 1,
            narrative = narratives.get("authpoint", ""),
            scan_date = scan_date, brand_name = brand_name,
            company_color = company_color,
        )
        c.showPage()

    # Page 8: Endpoint Security -- WatchGuard EPDR (optional, when no enterprise AV detected)
    epdr_rec = recs.get("epdr")
    if epdr_rec:
        _draw_category_page(
            c,
            title     = "SECURITY SOFTWARE RECOMMENDATIONS",
            subtitle  = "Endpoint Protection & Response -- WatchGuard EPDR",
            current_state_lines = epdr_rec["reason_signals"],
            product   = epdr_rec["product"],
            count     = 1,
            narrative = narratives.get("epdr", ""),
            scan_date = scan_date, brand_name = brand_name,
            company_color = company_color,
        )
        c.showPage()

    # Cloud & M365 Migration Assessment page (optional)
    cloud_rec = recs.get("cloud")
    if cloud_rec:
        _draw_cloud_page(
            c,
            cloud_rec     = cloud_rec,
            narrative     = narratives.get("cloud", ""),
            scan_date     = scan_date,
            brand_name    = brand_name,
            company_color = company_color,
        )
        c.showPage()

    # Final: Next Steps
    _draw_next_steps(c, scan_date, brand_name, brand_tagline,
                     client_name, company_color, recs)
    c.showPage()

    c.save()
    return buf.getvalue()


def _infer_client(scan_results: dict) -> str:
    """Minimal client name inference (mirrors client_report.infer_client_name)."""
    primary = (
        scan_results.get("osint", {})
        .get("company_identification", {})
        .get("primary_domain", "")
    )
    if primary:
        name = primary.split(".")[0].replace("-", " ").replace("_", " ").title()
        if name:
            return name
    dhcp = (
        scan_results.get("summary", {})
        .get("dhcp", {})
        .get("domain", "")
    )
    if dhcp:
        name = dhcp.split(".")[0].replace("-", " ").title()
        if name:
            return name
    return "Prospect Network"
