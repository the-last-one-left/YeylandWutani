#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
report_generator.py - HTML Report Builder

Generates professional HTML email reports with Pacific Office Automation
branding and Yeyland Wutani tooling attribution.
"""

import csv
import io
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Email size limits ─────────────────────────────────────────────────────
# Graph API allows 4 MB for inline sendMail messages. We cap HTML body at
# ~3 MB to leave room for JSON envelope overhead and attachments.
MAX_EMAIL_HTML_BYTES = 3 * 1024 * 1024
# When device count exceeds this, truncate the inline device table and
# direct the reader to the attached CSV for the full inventory.
MAX_INLINE_DEVICES = 200

# ── Severity badge colors ──────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#6c757d",
    "INFO":     "#17a2b8",
}

CATEGORY_ICONS = {
    "Firewall":               "&#9650;",  # solid up-triangle
    "Network Switch":         "&#9636;",  # lozenge
    "Wireless Access Point":  "&#9926;",  # wifi-like (antenna)
    "Network Infrastructure": "&#9654;",  # right-pointing
    "Windows Server":         "&#9632;",  # solid square
    "Linux/Unix Server":      "&#9632;",
    "Server":                 "&#9632;",
    "Database Server":        "&#9632;",
    "Hypervisor":             "&#9635;",  # square with inner
    "Windows Workstation":    "&#9675;",  # circle
    "Windows Device":         "&#9675;",
    "Apple Device":           "&#9675;",
    "IP Camera / NVR":        "&#9673;",  # bullseye
    "NAS / Storage":          "&#9699;",  # small triangle
    "VoIP Phone":             "&#9742;",  # telephone
    "Printer":                "&#9643;",
    "UPS / Power Device":     "&#9889;",  # lightning bolt
    "IoT Device":             "&#9670;",  # diamond
    "Raspberry Pi":           "&#9670;",
    "Virtual Machine":        "&#9671;",  # open diamond
    "Unknown Device":         "&#9661;",  # down-triangle
}

# Category display labels (short form for inventory cards)
CATEGORY_LABELS = {
    "Firewall":               "Firewalls",
    "Network Switch":         "Switches",
    "Wireless Access Point":  "Access Points",
    "Network Infrastructure": "Infrastructure",
    "Windows Server":         "Win Servers",
    "Linux/Unix Server":      "Linux Servers",
    "Server":                 "Servers",
    "Database Server":        "DB Servers",
    "Hypervisor":             "Hypervisors",
    "Windows Workstation":    "Workstations",
    "Windows Device":         "Win Devices",
    "Apple Device":           "Apple Devices",
    "IP Camera / NVR":        "IP Cameras",
    "NAS / Storage":          "NAS / Storage",
    "VoIP Phone":             "VoIP Phones",
    "Printer":                "Printers",
    "UPS / Power Device":     "UPS / Power",
    "IoT Device":             "IoT Devices",
    "Raspberry Pi":           "Raspberry Pi",
    "Virtual Machine":        "VMs",
    "Unknown Device":         "Unknown",
}

# Card color scheme for MSP inventory (bg, border, text)
CATEGORY_CARD_STYLE = {
    "Firewall":               ("#fff0e6", "#e07820", "#a04000"),
    "Network Switch":         ("#e6f0ff", "#2060c0", "#003080"),
    "Wireless Access Point":  ("#e6f0ff", "#2060c0", "#003080"),
    "Network Infrastructure": ("#e6f0ff", "#2060c0", "#003080"),
    "Windows Server":         ("#e8f4e8", "#3a8a3a", "#1a5a1a"),
    "Linux/Unix Server":      ("#e8f4e8", "#3a8a3a", "#1a5a1a"),
    "Server":                 ("#e8f4e8", "#3a8a3a", "#1a5a1a"),
    "Database Server":        ("#e8f4e8", "#3a8a3a", "#1a5a1a"),
    "Hypervisor":             ("#f0e8ff", "#7040b0", "#4a1880"),
    "Windows Workstation":    ("#f8f8f8", "#888888", "#444444"),
    "Windows Device":         ("#f8f8f8", "#888888", "#444444"),
    "Apple Device":           ("#f8f8f8", "#888888", "#444444"),
    "IP Camera / NVR":        ("#fff8e6", "#c08000", "#805000"),
    "NAS / Storage":          ("#e8eeff", "#4060c0", "#203080"),
    "VoIP Phone":             ("#e6fff0", "#20a060", "#006030"),
    "Printer":                ("#f8f8f8", "#888888", "#444444"),
    "UPS / Power Device":     ("#fff0e6", "#e06000", "#903000"),
    "IoT Device":             ("#fff8f0", "#c07040", "#804020"),
    "Raspberry Pi":           ("#ffe6f0", "#c02060", "#800040"),
    "Virtual Machine":        ("#f0e8ff", "#7040b0", "#4a1880"),
    "Unknown Device":         ("#f8f8f8", "#aaaaaa", "#666666"),
}


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#888")
    return (
        f'<span style="background:{color}; color:#fff; '
        f'font-size:10px; font-weight:bold; padding:2px 6px; '
        f'border-radius:3px; white-space:nowrap;">{severity}</span>'
    )


def _cat_icon(category: str) -> str:
    return CATEGORY_ICONS.get(category, "&#9661;")


def _port_badges(ports: list, max_show: int = 12) -> str:
    if not ports:
        return '<span style="color:#bbb; font-size:11px;">none</span>'
    shown = ports[:max_show]
    extra = len(ports) - max_show
    badges = []
    for p in shown:
        badges.append(
            f'<span style="background:#e8f4fb; color:#00628a; '
            f'font-size:10px; padding:1px 5px; border-radius:2px; '
            f'margin:1px; display:inline-block;">{p}</span>'
        )
    if extra > 0:
        badges.append(
            f'<span style="color:#888; font-size:10px;">+{extra} more</span>'
        )
    return " ".join(badges)


# ── MSP Summary Section ────────────────────────────────────────────────────

def _build_msp_summary(hosts: list, summary: dict, recon: dict, company_color: str) -> str:
    """
    Build a single-page MSP-friendly summary: device inventory cards,
    network identity (public IP / ISP / firewall), and top security gaps.
    """
    breakdown = summary.get("category_breakdown", {})

    # ── Row 1: Device Inventory Cards ─────────────────────────────────────
    # Priority order for display
    card_order = [
        "Firewall", "Network Switch", "Wireless Access Point",
        "Windows Server", "Linux/Unix Server", "Server", "Database Server",
        "Hypervisor", "Windows Workstation", "Windows Device", "Apple Device",
        "IP Camera / NVR", "NAS / Storage", "VoIP Phone", "Printer",
        "UPS / Power Device", "IoT Device", "Raspberry Pi",
        "Virtual Machine", "Network Infrastructure", "Unknown Device",
    ]

    cards_html = ""
    for cat in card_order:
        count = breakdown.get(cat, 0)
        if count == 0:
            continue
        label = CATEGORY_LABELS.get(cat, cat)
        icon = _cat_icon(cat)
        bg, border, text = CATEGORY_CARD_STYLE.get(cat, ("#f8f8f8", "#aaa", "#666"))
        cards_html += f"""
        <td style="padding:4px;">
          <div style="background:{bg}; border:1px solid {border}; border-radius:6px;
                      padding:10px 8px; text-align:center; min-width:80px;">
            <div style="font-size:16px; color:{text};">{icon}</div>
            <div style="font-size:22px; font-weight:bold; color:{text}; line-height:1.1;">{count}</div>
            <div style="font-size:9px; color:{text}; margin-top:2px; white-space:nowrap;">{label}</div>
          </div>
        </td>"""

    # ── Row 2: Network Identity Bar ───────────────────────────────────────
    pub_info = recon.get("public_ip_info", {})
    public_ip = pub_info.get("public_ip", "")
    isp = pub_info.get("isp", "")
    ptr = pub_info.get("hostname", "")
    city = pub_info.get("city", "")
    region = pub_info.get("region", "")

    location_str = ", ".join(p for p in (city, region) if p)

    # Find gateway host and its fingerprint
    gw_ip = recon.get("default_gateway", "")
    gateway_label = ""
    for h in hosts:
        if h.get("is_gateway") or h.get("ip") == gw_ip:
            gw_info = h.get("gateway_info", {})
            if gw_info.get("vendor"):
                parts = [gw_info["vendor"]]
                if gw_info.get("product") and gw_info["product"] != gw_info["vendor"]:
                    parts.append(gw_info["product"])
                if gw_info.get("model"):
                    parts.append(gw_info["model"])
                gateway_label = " ".join(parts)
            elif h.get("vendor") and h["vendor"] != "Unknown":
                gateway_label = h["vendor"]
            if not gateway_label:
                gateway_label = gw_ip
            break
    if not gateway_label:
        gateway_label = gw_ip or "Unknown"

    net_identity_cells = ""
    if public_ip:
        net_identity_cells += f"""
        <td style="padding:8px 16px; border-right:1px solid #dde4ef; white-space:nowrap;">
          <div style="color:#888; font-size:10px; text-transform:uppercase; letter-spacing:0.5px;">Public IP</div>
          <div style="color:#222; font-size:13px; font-weight:bold; font-family:monospace;">{public_ip}</div>
        </td>"""
    if isp:
        net_identity_cells += f"""
        <td style="padding:8px 16px; border-right:1px solid #dde4ef; white-space:nowrap;">
          <div style="color:#888; font-size:10px; text-transform:uppercase; letter-spacing:0.5px;">ISP / ASN</div>
          <div style="color:#222; font-size:12px;">{isp[:50]}</div>
        </td>"""
    if ptr:
        net_identity_cells += f"""
        <td style="padding:8px 16px; border-right:1px solid #dde4ef; white-space:nowrap;">
          <div style="color:#888; font-size:10px; text-transform:uppercase; letter-spacing:0.5px;">Reverse PTR</div>
          <div style="color:#222; font-size:12px; font-family:monospace;">{ptr[:50]}</div>
        </td>"""
    if location_str:
        net_identity_cells += f"""
        <td style="padding:8px 16px; border-right:1px solid #dde4ef; white-space:nowrap;">
          <div style="color:#888; font-size:10px; text-transform:uppercase; letter-spacing:0.5px;">Location</div>
          <div style="color:#222; font-size:12px;">{location_str}</div>
        </td>"""
    net_identity_cells += f"""
    <td style="padding:8px 16px; white-space:nowrap;">
      <div style="color:#888; font-size:10px; text-transform:uppercase; letter-spacing:0.5px;">Gateway / Firewall</div>
      <div style="color:#222; font-size:12px; font-weight:bold;">{gateway_label}</div>
    </td>"""

    # ── Row 3: Top Security Gaps ──────────────────────────────────────────
    gaps = summary.get("security_gaps", [])
    gap_html = ""
    for gap in gaps[:5]:
        sev = gap.get("severity", "LOW")
        count = gap.get("count", 0)
        issue = gap.get("issue", "")
        sample_ips = gap.get("ips", [])[:3]
        sample_str = ", ".join(sample_ips)
        if len(gap.get("ips", [])) > 3:
            sample_str += f" +{len(gap['ips']) - 3} more"
        gap_html += f"""
        <tr style="border-bottom:1px solid #f0f0f0;">
          <td style="padding:5px 10px; font-size:12px; width:80px;">{_severity_badge(sev)}</td>
          <td style="padding:5px 10px; font-size:12px; font-weight:bold; color:#333;">
            {issue} <span style="color:#888; font-weight:normal;">({count} device{'s' if count != 1 else ''})</span>
          </td>
          <td style="padding:5px 10px; font-size:11px; color:#888; font-family:monospace;">{sample_str}</td>
        </tr>"""

    if not gap_html:
        gap_html = """
        <tr><td colspan="3" style="padding:10px; color:#2d6a4f; background:#d8f3dc; font-size:12px;">
          &#10003; No significant security gaps detected.
        </td></tr>"""

    total_hosts = summary.get("total_hosts", len(hosts))
    total_devices_label = f"{total_hosts} device{'s' if total_hosts != 1 else ''} discovered"

    return f"""
  <!-- ═══ MSP SUMMARY ═══ -->
  <tr>
    <td style="padding:28px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 14px 0;
                 border-bottom:2px solid {company_color}; padding-bottom:8px;">
        MSP Environment Summary
        <span style="font-size:12px; font-weight:normal; color:#888; margin-left:8px;">
          {total_devices_label}
        </span>
      </h2>

      <!-- Inventory cards -->
      <table cellpadding="0" cellspacing="0" style="margin-bottom:14px;">
        <tr>
          {cards_html}
        </tr>
      </table>

      <!-- Network identity bar -->
      <table cellpadding="0" cellspacing="0"
             style="width:100%; background:#f4f7fc; border:1px solid #dde4ef;
                    border-radius:6px; margin-bottom:14px;">
        <tr>
          {net_identity_cells}
        </tr>
      </table>

      <!-- Security gap highlights -->
      <div style="font-size:12px; font-weight:bold; color:#c0392b; margin-bottom:6px;">
        &#9888; Top Security Gaps
      </div>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="background:#fafafa; border:1px solid #f0d0d0; border-radius:4px;">
        {gap_html}
      </table>
    </td>
  </tr>"""


# ── Device table rows ──────────────────────────────────────────────────────

def _build_device_rows(hosts: list, company_color: str) -> str:
    rows = ""
    for i, host in enumerate(hosts):
        bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
        ip = host.get("ip", "N/A")
        mac = host.get("mac", "N/A") or "N/A"
        vendor = host.get("vendor", "Unknown")
        hostname = host.get("hostname", "N/A") or "N/A"
        category = host.get("category", "Unknown")
        ports = sorted(host.get("open_ports", []))
        flags = host.get("security_flags", [])

        icon = _cat_icon(category)
        port_html = _port_badges(ports)

        flag_html = ""
        for f in flags[:3]:
            flag_html += _severity_badge(f.get("severity", "LOW")) + " "

        # HTTP title if available
        services = host.get("services", {})
        http_title = ""
        for port in (80, 443, 8080, 8443):
            svc = services.get(port, {})
            if isinstance(svc, dict) and svc.get("title"):
                http_title = f'<br><span style="color:#555; font-size:10px; font-style:italic;">{svc["title"][:60]}</span>'
                break

        smb = services.get("smb", {})
        smb_info = ""
        if smb and smb.get("smb_computer"):
            smb_info = f'<br><span style="color:#555; font-size:10px;">SMB: {smb["smb_computer"]}</span>'

        # SNMP device name
        snmp = services.get("snmp", {}) or {}
        snmp_info = ""
        if snmp.get("sysName"):
            snmp_info = f'<br><span style="color:#555; font-size:10px;">SNMP: {snmp["sysName"][:50]}</span>'

        # OS guess
        os_guess = host.get("os_guess", "")
        os_info = ""
        if os_guess:
            os_info = f'<br><span style="color:#888; font-size:10px; font-style:italic;">OS: {os_guess[:50]}</span>'

        # SSL cert expiry
        ssl_cert = services.get("ssl_cert", {}) or {}
        cert_info = ""
        if ssl_cert.get("expires"):
            cert_info = f'<br><span style="color:#888; font-size:10px;">SSL exp: {ssl_cert["expires"][:20]}</span>'

        # Representative service version
        version_str = ""
        for vport in (80, 443, 22, 21, 25):
            svc = services.get(vport, {})
            if isinstance(svc, dict) and svc.get("version"):
                version_str = f'<br><span style="color:#aaa; font-size:9px;">{svc["version"][:50]}</span>'
                break

        # Subnet label badge (e.g. "Corporate LAN") and additional-subnet indicator
        subnet_badge = ""
        subnet_label = host.get("subnet_label", "")
        if subnet_label:
            subnet_badge = f'<br><span style="background:#e8f0fe; color:#1a56db; font-size:9px; padding:1px 5px; border-radius:2px; display:inline-block; margin-top:1px;">{subnet_label}</span>'
        if host.get("subnet_source") == "additional":
            subnet_badge += f'<span style="background:#fff3cd; color:#856404; font-size:9px; padding:1px 4px; border-radius:2px; margin-left:4px;">+subnet</span>'

        # Gateway firewall model badge
        gw_badge = ""
        gw_info = host.get("gateway_info", {})
        if gw_info.get("vendor"):
            gw_label = gw_info["vendor"]
            if gw_info.get("model"):
                gw_label += f" {gw_info['model']}"
            gw_badge = (
                f'<br><span style="background:#fff0e6; color:#a04000; font-size:9px; '
                f'padding:1px 5px; border-radius:2px; display:inline-block; margin-top:2px;">'
                f'&#9650; {gw_label}</span>'
            )

        rows += f"""
        <tr style="background:{bg};">
          <td style="padding:7px 10px; border-bottom:1px solid #eef2f7; font-size:12px; font-family:monospace;">{ip}{subnet_badge}</td>
          <td style="padding:7px 10px; border-bottom:1px solid #eef2f7; font-size:12px;">
            {icon} <span style="color:{company_color}; font-weight:bold;">{category}</span>
            {gw_badge}{http_title}{smb_info}{snmp_info}{os_info}{cert_info}
          </td>
          <td style="padding:7px 10px; border-bottom:1px solid #eef2f7; font-size:11px; color:#555;">{hostname}</td>
          <td style="padding:7px 10px; border-bottom:1px solid #eef2f7; font-size:11px; font-family:monospace;">{mac}<br><span style="color:#888;">{vendor}</span></td>
          <td style="padding:7px 10px; border-bottom:1px solid #eef2f7;">{port_html}{version_str}</td>
          <td style="padding:7px 10px; border-bottom:1px solid #eef2f7;">{flag_html}</td>
        </tr>"""
    return rows


# ── Security observations section ─────────────────────────────────────────

def _build_ad_section(hosts: list, company_color: str = "#00A0D9") -> str:
    """
    Build an Active Directory Environment section for the report.
    Only rendered when at least one host has ad_info.enumerated == True.
    Returns empty string if no DCs were enumerated.
    """
    dc_hosts = [h for h in hosts if (h.get("ad_info") or {}).get("enumerated")]
    if not dc_hosts:
        return ""

    cards_html = ""
    for host in dc_hosts:
        ad = host.get("ad_info", {})
        domain = ad.get("domain_name") or host.get("hostname", host["ip"])
        base_dn = ad.get("base_dn", "")
        func_level = ad.get("domain_functional_level", "Unknown")
        dc_count = ad.get("dc_count", 1)
        user_count = ad.get("user_count")
        computer_count = ad.get("computer_count")
        domain_admins = ad.get("domain_admins", [])
        os_versions = ad.get("os_versions", {})
        anon_bind = ad.get("anonymous_bind_allowed", False)

        # Counts row
        count_cells = ""
        for label, val in [("Users", user_count), ("Computers", computer_count), ("DCs", dc_count)]:
            if val is not None:
                count_cells += f"""
              <td style="padding:10px 16px; text-align:center; border-right:1px solid #d0e8f5;">
                <div style="font-size:22px; font-weight:bold; color:{company_color};">{val}</div>
                <div style="font-size:11px; color:#666;">{label}</div>
              </td>"""
            else:
                count_cells += f"""
              <td style="padding:10px 16px; text-align:center; border-right:1px solid #d0e8f5;">
                <div style="font-size:22px; font-weight:bold; color:#aaa;">?</div>
                <div style="font-size:11px; color:#666;">{label}</div>
              </td>"""

        # OS breakdown table
        os_rows_html = ""
        if os_versions:
            for os_name, count in sorted(os_versions.items(), key=lambda x: -x[1]):
                bar_pct = int(count / max(os_versions.values()) * 100)
                os_rows_html += f"""
            <tr style="border-bottom:1px solid #eef4f9;">
              <td style="padding:4px 8px; font-size:11px; color:#333;">{os_name}</td>
              <td style="padding:4px 8px; font-size:11px; font-weight:bold; color:{company_color};">{count}</td>
              <td style="padding:4px 8px;">
                <div style="background:{company_color}; height:8px; width:{bar_pct}%; border-radius:4px; opacity:0.7;"></div>
              </td>
            </tr>"""

        # Domain admins pills
        admin_pills = ""
        if domain_admins:
            for name in domain_admins:
                admin_pills += f'<span style="display:inline-block; background:#fff3cd; color:#856404; border:1px solid #ffc107; border-radius:3px; padding:2px 8px; margin:2px; font-size:11px;">{name}</span>'
        else:
            admin_pills = '<span style="color:#888; font-size:11px; font-style:italic;">Not enumerable (anonymous bind restricted)</span>'

        # Anonymous bind warning
        anon_warning = ""
        if anon_bind:
            anon_warning = f"""
          <div style="background:#fff3cd; border:1px solid #ffc107; border-left:4px solid #e69900; border-radius:3px; padding:8px 12px; margin-top:10px; font-size:12px; color:#856404;">
            <strong>&#9888; Security Gap:</strong> Anonymous LDAP bind is enabled &mdash;
            Active Directory structure and user information is readable without credentials.
          </div>"""

        cards_html += f"""
        <div style="background:#f0f7fc; border:1px solid #b0d8ef; border-left:4px solid {company_color}; border-radius:4px; padding:14px 16px; margin-bottom:14px;">
          <!-- DC title bar -->
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:10px;">
            <tr>
              <td>
                <span style="font-size:15px; font-weight:bold; color:{company_color};">&#9672; {domain}</span>
                <span style="font-size:11px; color:#888; margin-left:10px;">{host['ip']}</span>
                <span style="font-size:11px; color:#555; margin-left:8px;">&bull; {func_level}</span>
              </td>
              <td align="right">
                <span style="font-size:11px; color:#888;">{base_dn}</span>
              </td>
            </tr>
          </table>

          <!-- Counts grid -->
          <table cellpadding="0" cellspacing="0" style="border:1px solid #d0e8f5; border-radius:4px; margin-bottom:10px; background:#fff;">
            <tr>{count_cells}
            </tr>
          </table>

          <!-- OS Breakdown -->
          {"" if not os_versions else f"""
          <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:4px;">Operating Systems Detected</div>
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; margin-bottom:10px; font-size:11px;">
            {os_rows_html}
          </table>"""}

          <!-- Domain Admins -->
          <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:4px;">Domain Administrators</div>
          <div style="margin-bottom:4px;">{admin_pills}</div>

          {anon_warning}
        </div>"""

    return f"""
  <!-- ═══ ACTIVE DIRECTORY ENVIRONMENT ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0; border-bottom:2px solid {company_color}; padding-bottom:8px;">
        &#9672; Active Directory Environment
      </h2>
      {cards_html}
    </td>
  </tr>
"""


def _build_delta_section(summary: dict, company_color: str = "#00A0D9") -> str:
    """
    Build a 'Changes Since Last Scan' section.
    Only rendered if summary["scan_delta"]["has_changes"] is True.
    Returns empty string otherwise.
    """
    delta = summary.get("scan_delta", {}) or {}
    if not delta.get("has_changes"):
        return ""

    new_devices = delta.get("new_devices", [])
    gone_devices = delta.get("gone_devices", [])
    changed_devices = delta.get("changed_devices", [])
    prev_date = delta.get("previous_scan_date", "unknown")
    # Format date nicely if ISO format
    try:
        from datetime import datetime as _dt
        prev_date_fmt = _dt.fromisoformat(prev_date).strftime("%Y-%m-%d %H:%M")
    except Exception:
        prev_date_fmt = prev_date

    # Badge row
    badges = ""
    if new_devices:
        badges += f'<span style="background:#dc3545; color:#fff; padding:3px 10px; border-radius:3px; font-size:12px; margin-right:8px; font-weight:bold;">+{len(new_devices)} New Device{"s" if len(new_devices) != 1 else ""}</span>'
    if gone_devices:
        badges += f'<span style="background:#fd7e14; color:#fff; padding:3px 10px; border-radius:3px; font-size:12px; margin-right:8px; font-weight:bold;">-{len(gone_devices)} Device{"s" if len(gone_devices) != 1 else ""} Gone</span>'
    if changed_devices:
        badges += f'<span style="background:#ffc107; color:#333; padding:3px 10px; border-radius:3px; font-size:12px; margin-right:8px; font-weight:bold;">&#9650; {len(changed_devices)} Change{"s" if len(changed_devices) != 1 else ""} Detected</span>'

    # New devices table
    new_rows = ""
    for h in new_devices[:20]:  # cap at 20 rows
        new_rows += f"""
        <tr style="border-bottom:1px solid #ffd6d6;">
          <td style="padding:5px 8px; font-size:12px; font-weight:bold; color:#333;">{h.get('ip', '')}</td>
          <td style="padding:5px 8px; font-size:12px; color:#555;">{h.get('hostname', '') or '—'}</td>
          <td style="padding:5px 8px; font-size:12px; color:#555;">{h.get('vendor', '') or '—'}</td>
          <td style="padding:5px 8px; font-size:12px; color:#555;">{h.get('category', 'Unknown')}</td>
        </tr>"""

    new_table = ""
    if new_devices:
        new_table = f"""
      <div style="font-size:12px; font-weight:bold; color:#dc3545; margin:10px 0 4px 0;">New Devices</div>
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; font-size:12px; margin-bottom:12px;">
        <tr style="background:#ffeaea;">
          <th style="padding:5px 8px; text-align:left; color:#8b0000; font-size:11px;">IP</th>
          <th style="padding:5px 8px; text-align:left; color:#8b0000; font-size:11px;">Hostname</th>
          <th style="padding:5px 8px; text-align:left; color:#8b0000; font-size:11px;">Vendor</th>
          <th style="padding:5px 8px; text-align:left; color:#8b0000; font-size:11px;">Category</th>
        </tr>
        {new_rows}
      </table>"""

    # Gone devices table
    gone_rows = ""
    for h in gone_devices[:20]:
        gone_rows += f"""
        <tr style="border-bottom:1px solid #ffe8d6;">
          <td style="padding:5px 8px; font-size:12px; font-weight:bold; color:#333;">{h.get('ip', '')}</td>
          <td style="padding:5px 8px; font-size:12px; color:#555;">{h.get('hostname', '') or '—'}</td>
          <td style="padding:5px 8px; font-size:12px; color:#555;">{h.get('vendor', '') or '—'}</td>
          <td style="padding:5px 8px; font-size:12px; color:#555;">{h.get('category', 'Unknown')}</td>
        </tr>"""

    gone_table = ""
    if gone_devices:
        gone_table = f"""
      <div style="font-size:12px; font-weight:bold; color:#fd7e14; margin:10px 0 4px 0;">Devices No Longer Seen</div>
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; font-size:12px; margin-bottom:12px;">
        <tr style="background:#fff3e6;">
          <th style="padding:5px 8px; text-align:left; color:#8b4000; font-size:11px;">IP</th>
          <th style="padding:5px 8px; text-align:left; color:#8b4000; font-size:11px;">Hostname</th>
          <th style="padding:5px 8px; text-align:left; color:#8b4000; font-size:11px;">Vendor</th>
          <th style="padding:5px 8px; text-align:left; color:#8b4000; font-size:11px;">Category</th>
        </tr>
        {gone_rows}
      </table>"""

    # Changed devices table
    changed_rows = ""
    for h in changed_devices[:20]:
        changes_str = " &bull; ".join(h.get("changes", []))
        changed_rows += f"""
        <tr style="border-bottom:1px solid #fff3cd;">
          <td style="padding:5px 8px; font-size:12px; font-weight:bold; color:#333;">{h.get('ip', '')}</td>
          <td style="padding:5px 8px; font-size:12px; color:#555;">{h.get('hostname', '') or '—'}</td>
          <td style="padding:5px 8px; font-size:12px; color:#555;">{h.get('category', 'Unknown')}</td>
          <td style="padding:5px 8px; font-size:12px; color:#666;">{changes_str}</td>
        </tr>"""

    changed_table = ""
    if changed_devices:
        changed_table = f"""
      <div style="font-size:12px; font-weight:bold; color:#856404; margin:10px 0 4px 0;">Changed Devices</div>
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; font-size:12px; margin-bottom:12px;">
        <tr style="background:#fff8e0;">
          <th style="padding:5px 8px; text-align:left; color:#5a4000; font-size:11px;">IP</th>
          <th style="padding:5px 8px; text-align:left; color:#5a4000; font-size:11px;">Hostname</th>
          <th style="padding:5px 8px; text-align:left; color:#5a4000; font-size:11px;">Category</th>
          <th style="padding:5px 8px; text-align:left; color:#5a4000; font-size:11px;">Changes</th>
        </tr>
        {changed_rows}
      </table>"""

    return f"""
  <!-- ═══ CHANGES SINCE LAST SCAN ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:#856404; font-size:17px; margin:0 0 8px 0; border-bottom:2px solid #ffc107; padding-bottom:8px;">
        &#9650; Changes Since Last Scan
        <span style="font-size:12px; font-weight:normal; color:#888; margin-left:10px;">compared to {prev_date_fmt}</span>
      </h2>
      <div style="margin-bottom:10px;">{badges}</div>
      {new_table}
      {gone_table}
      {changed_table}
    </td>
  </tr>
"""


def _build_security_section(hosts: list, company_color: str) -> str:
    flagged = [h for h in hosts if h.get("security_flags")]
    if not flagged:
        return """
        <tr><td colspan="3" style="padding:12px; color:#2d6a4f; background:#d8f3dc;">
          &#10003; No significant security observations detected.
        </td></tr>"""

    rows = ""
    for host in flagged:
        for flag in host.get("security_flags", []):
            sev = flag.get("severity", "LOW")
            rows += f"""
            <tr>
              <td style="padding:6px 10px; border-bottom:1px solid #f0f0f0; font-size:12px; font-family:monospace;">
                {host.get('ip', 'N/A')}
              </td>
              <td style="padding:6px 10px; border-bottom:1px solid #f0f0f0; font-size:12px;">
                {host.get('hostname', 'N/A')}
              </td>
              <td style="padding:6px 10px; border-bottom:1px solid #f0f0f0; font-size:12px;">
                {_severity_badge(sev)} {flag.get('flag', '')}
              </td>
            </tr>"""
    return rows


# ── Category summary cards ─────────────────────────────────────────────────

def _build_category_cards(summary: dict, company_color: str) -> str:
    breakdown = summary.get("category_breakdown", {})
    cards = ""
    for cat, count in sorted(breakdown.items(), key=lambda x: -x[1]):
        icon = _cat_icon(cat)
        label = CATEGORY_LABELS.get(cat, cat)
        bg, border, text = CATEGORY_CARD_STYLE.get(cat, ("#f4faff", "#d0eaf8", "#333"))
        cards += f"""
        <td style="padding:4px; text-align:center; vertical-align:top; width:110px;">
          <div style="background:{bg}; border:1px solid {border}; border-radius:6px; padding:10px 6px;">
            <div style="font-size:18px; color:{text};">{icon}</div>
            <div style="font-size:18px; font-weight:bold; color:{text};">{count}</div>
            <div style="font-size:10px; color:{text}; margin-top:2px;">{label}</div>
          </div>
        </td>"""
    return f'<table cellpadding="0" cellspacing="0"><tr>{cards}</tr></table>'


# ── Service breakdown table ────────────────────────────────────────────────

def _build_services_table(summary: dict) -> str:
    services = summary.get("top_services", [])
    if not services:
        return "<p style='color:#888;'>No services detected.</p>"
    rows = ""
    max_count = services[0]["count"] if services else 1
    for item in services:
        width = int(item["count"] / max_count * 100)
        rows += f"""
        <tr>
          <td style="padding:4px 8px; font-size:12px; width:140px;">{item['service']}</td>
          <td style="padding:4px 8px;">
            <div style="background:#e0f0fa; width:{width}%; min-width:20px; height:16px; border-radius:2px;
                        display:inline-block; vertical-align:middle;"></div>
            <span style="font-size:11px; color:#555; margin-left:6px;">{item['count']}</span>
          </td>
        </tr>"""
    return f'<table width="100%" cellpadding="0" cellspacing="0">{rows}</table>'


# ── WiFi Networks section ─────────────────────────────────────────────────

_ENCRYPTION_BADGE = {
    "Open":  ("#dc3545", "#fff"),
    "WEP":   ("#fd7e14", "#fff"),
    "WPA":   ("#ffc107", "#333"),
    "WPA2":  ("#28a745", "#fff"),
    "WPA3":  ("#0d6efd", "#fff"),
}

_SIGNAL_BAR_COLOR = {
    "Excellent": "#28a745",
    "Good":      "#7bc67e",
    "Fair":      "#ffc107",
    "Weak":      "#dc3545",
}


def _build_wifi_section(wifi_results: dict, company_color: str) -> str:
    """Build the WiFi Networks & Channel Analysis report section."""
    if not wifi_results or not wifi_results.get("scan_success"):
        return ""

    networks = wifi_results.get("networks", [])
    if not networks:
        return ""

    summary = wifi_results.get("summary", {})
    channel_analysis = wifi_results.get("channel_analysis", {})
    iface = wifi_results.get("wifi_interface", "wlan0")

    # Network table rows (top 30)
    net_rows = ""
    for i, net in enumerate(networks[:30]):
        bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
        ssid = net.get("ssid", "Unknown")
        enc = net.get("encryption", "Open")
        enc_bg, enc_fg = _ENCRYPTION_BADGE.get(enc, ("#888", "#fff"))
        enc_badge = (
            f'<span style="background:{enc_bg}; color:{enc_fg}; font-size:9px; '
            f'font-weight:bold; padding:1px 5px; border-radius:2px;">{enc}</span>'
        )
        dbm = net.get("signal_dbm", -100)
        quality = net.get("signal_quality", "Weak")
        bar_color = _SIGNAL_BAR_COLOR.get(quality, "#888")
        bar_width = max(5, min(100, int((dbm + 100) * 1.5)))
        hidden_badge = ""
        if net.get("hidden"):
            hidden_badge = (
                ' <span style="background:#6c757d; color:#fff; font-size:8px; '
                'padding:1px 4px; border-radius:2px;">HIDDEN</span>'
            )

        net_rows += f"""
        <tr style="background:{bg};">
          <td style="padding:5px 8px; font-size:12px; border-bottom:1px solid #eef2f7;">
            {ssid}{hidden_badge}
          </td>
          <td style="padding:5px 8px; font-size:11px; font-family:monospace; color:#666; border-bottom:1px solid #eef2f7;">
            {net.get('bssid', '')}
          </td>
          <td style="padding:5px 8px; font-size:12px; text-align:center; border-bottom:1px solid #eef2f7;">
            {net.get('channel', '?')}
          </td>
          <td style="padding:5px 8px; font-size:11px; text-align:center; border-bottom:1px solid #eef2f7;">
            {net.get('band', '')}
          </td>
          <td style="padding:5px 8px; border-bottom:1px solid #eef2f7;">
            <div style="display:inline-block; width:60px; background:#e9ecef; height:10px; border-radius:5px; vertical-align:middle;">
              <div style="background:{bar_color}; width:{bar_width}%; height:10px; border-radius:5px;"></div>
            </div>
            <span style="font-size:10px; color:#666; margin-left:4px;">{dbm} dBm</span>
          </td>
          <td style="padding:5px 8px; border-bottom:1px solid #eef2f7;">{enc_badge}</td>
        </tr>"""

    truncate_note = ""
    if len(networks) > 30:
        truncate_note = (
            f'<div style="color:#888; font-size:11px; margin-top:4px; font-style:italic;">'
            f'Showing 30 of {len(networks)} networks. See attached data for full list.</div>'
        )

    # Open network warning
    open_warning = ""
    open_count = summary.get("open_networks", 0)
    if open_count > 0:
        open_warning = (
            f'<div style="background:#fff3cd; border:1px solid #ffc107; border-left:4px solid #e69900; '
            f'border-radius:3px; padding:8px 12px; margin-bottom:12px; font-size:12px; color:#856404;">'
            f'<strong>&#9888; Security:</strong> {open_count} open (unencrypted) WiFi network{"s" if open_count != 1 else ""} detected.'
            f'</div>'
        )

    # Channel congestion summary for 2.4 GHz
    ch_24 = channel_analysis.get("2.4ghz", {})
    channel_bars = ""
    if ch_24:
        for ch_str in sorted(ch_24.keys(), key=lambda x: int(x)):
            info = ch_24[ch_str]
            count = info.get("count", 0)
            bar_h = max(4, min(60, count * 12))
            color = "#dc3545" if count >= 5 else ("#ffc107" if count >= 3 else "#28a745")
            channel_bars += (
                f'<td style="padding:2px; text-align:center; vertical-align:bottom;">'
                f'<div style="background:{color}; width:20px; height:{bar_h}px; '
                f'border-radius:2px 2px 0 0; margin:0 auto;"></div>'
                f'<div style="font-size:9px; color:#666; margin-top:2px;">Ch{ch_str}</div>'
                f'<div style="font-size:9px; color:#888;">{count}</div>'
                f'</td>'
            )

    recommendation = channel_analysis.get("recommendation", "")

    return f"""
  <!-- ═══ WIFI NETWORKS ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0;
                 border-bottom:2px solid {company_color}; padding-bottom:8px;">
        &#9926; WiFi Networks
        <span style="font-size:12px; font-weight:normal; color:#888; margin-left:8px;">
          {summary.get('total_networks', 0)} networks via {iface}
        </span>
      </h2>
      {open_warning}

      <!-- Summary badges -->
      <div style="margin-bottom:10px;">
        <span style="background:#28a745; color:#fff; font-size:11px; padding:2px 8px; border-radius:3px; margin-right:4px;">WPA2: {summary.get('wpa2_networks', 0)}</span>
        <span style="background:#0d6efd; color:#fff; font-size:11px; padding:2px 8px; border-radius:3px; margin-right:4px;">WPA3: {summary.get('wpa3_networks', 0)}</span>
        <span style="background:#dc3545; color:#fff; font-size:11px; padding:2px 8px; border-radius:3px; margin-right:4px;">Open: {summary.get('open_networks', 0)}</span>
        <span style="background:#fd7e14; color:#fff; font-size:11px; padding:2px 8px; border-radius:3px; margin-right:4px;">WEP: {summary.get('wep_networks', 0)}</span>
        <span style="background:#6c757d; color:#fff; font-size:11px; padding:2px 8px; border-radius:3px;">Hidden: {summary.get('hidden_networks', 0)}</span>
      </div>

      {"" if not channel_bars else f'''
      <!-- 2.4 GHz Channel Congestion -->
      <div style="font-size:12px; font-weight:bold; color:#555; margin:14px 0 6px 0;">2.4 GHz Channel Usage</div>
      <table cellpadding="0" cellspacing="0" style="margin-bottom:6px; background:#f8f9fa; border:1px solid #dee2e6; border-radius:4px; padding:8px;">
        <tr>{channel_bars}</tr>
      </table>
      <div style="font-size:11px; color:#555; margin-bottom:14px; font-style:italic;">
        &#128161; {recommendation}
      </div>
      '''}

      <!-- WiFi network table -->
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; font-size:12px;">
        <tr style="background:{company_color}; color:#fff;">
          <th style="padding:6px 8px; text-align:left;">SSID</th>
          <th style="padding:6px 8px; text-align:left;">BSSID</th>
          <th style="padding:6px 8px; text-align:center; width:40px;">Ch</th>
          <th style="padding:6px 8px; text-align:center; width:50px;">Band</th>
          <th style="padding:6px 8px; text-align:left; width:120px;">Signal</th>
          <th style="padding:6px 8px; text-align:left; width:60px;">Security</th>
        </tr>
        {net_rows}
      </table>
      {truncate_note}
    </td>
  </tr>"""


# ── Network Services (mDNS + SSDP) section ──────────────────────────────

def _build_protocol_discovery_section(
    mdns_results: dict, ssdp_results: dict, company_color: str,
) -> str:
    """Build combined mDNS + SSDP discovery section."""
    mdns_services = (mdns_results or {}).get("services", [])
    ssdp_devices = (ssdp_results or {}).get("devices", [])

    if not mdns_services and not ssdp_devices:
        return ""

    # mDNS table
    mdns_html = ""
    if mdns_services:
        mdns_rows = ""
        for i, svc in enumerate(mdns_services[:25]):
            bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
            mdns_rows += f"""
            <tr style="background:{bg};">
              <td style="padding:4px 8px; font-size:12px; border-bottom:1px solid #eef2f7;">{svc.get('name', '')[:40]}</td>
              <td style="padding:4px 8px; font-size:11px; color:#555; border-bottom:1px solid #eef2f7;">{svc.get('service_type', '')}</td>
              <td style="padding:4px 8px; font-size:11px; color:#666; border-bottom:1px solid #eef2f7;">{svc.get('hostname', '')}</td>
              <td style="padding:4px 8px; font-size:11px; font-family:monospace; border-bottom:1px solid #eef2f7;">{svc.get('ip', '')}</td>
              <td style="padding:4px 8px; font-size:11px; text-align:center; border-bottom:1px solid #eef2f7;">{svc.get('port', '') or ''}</td>
            </tr>"""
        mdns_summary = (mdns_results or {}).get("summary", {})
        mdns_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          mDNS / Bonjour Services ({mdns_summary.get('total_services', 0)} from {mdns_summary.get('unique_hosts', 0)} hosts)
        </div>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; margin-bottom:14px;">
          <tr style="background:#e8f4fb; color:#00628a;">
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Service Name</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Type</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Hostname</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">IP</th>
            <th style="padding:5px 8px; text-align:center; font-size:11px;">Port</th>
          </tr>
          {mdns_rows}
        </table>"""

    # SSDP / UPnP table
    ssdp_html = ""
    if ssdp_devices:
        ssdp_rows = ""
        for i, dev in enumerate(ssdp_devices[:25]):
            bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
            name = dev.get("friendly_name", "") or dev.get("service_type", "")[:40]
            ssdp_rows += f"""
            <tr style="background:{bg};">
              <td style="padding:4px 8px; font-size:12px; border-bottom:1px solid #eef2f7;">{name[:45]}</td>
              <td style="padding:4px 8px; font-size:11px; color:#555; border-bottom:1px solid #eef2f7;">{dev.get('manufacturer', '')[:30]}</td>
              <td style="padding:4px 8px; font-size:11px; color:#666; border-bottom:1px solid #eef2f7;">{dev.get('model_name', '')[:30]}</td>
              <td style="padding:4px 8px; font-size:11px; font-family:monospace; border-bottom:1px solid #eef2f7;">{dev.get('ip', '')}</td>
              <td style="padding:4px 8px; font-size:11px; color:#888; border-bottom:1px solid #eef2f7;">{dev.get('device_type', '').split(':')[-1] if dev.get('device_type') else ''}</td>
            </tr>"""
        ssdp_summary = (ssdp_results or {}).get("summary", {})
        ssdp_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          UPnP / SSDP Devices ({ssdp_summary.get('total_devices', 0)})
        </div>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; margin-bottom:14px;">
          <tr style="background:#f0e8ff; color:#5a3a8a;">
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Device Name</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Manufacturer</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Model</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">IP</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Type</th>
          </tr>
          {ssdp_rows}
        </table>"""

    return f"""
  <!-- ═══ NETWORK SERVICES DISCOVERY ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0;
                 border-bottom:2px solid {company_color}; padding-bottom:8px;">
        &#9672; Network Services Discovery
      </h2>
      {mdns_html}
      {ssdp_html}
    </td>
  </tr>"""


# ── DHCP Infrastructure section ──────────────────────────────────────────

def _build_dhcp_section(dhcp_results: dict, company_color: str) -> str:
    """Build the DHCP Infrastructure report section."""
    if not dhcp_results:
        return ""
    servers = dhcp_results.get("dhcp_servers", [])
    if not servers:
        return ""

    rogue_warning = ""
    if dhcp_results.get("rogue_server_warning"):
        rogue_warning = (
            '<div style="background:#f8d7da; border:1px solid #f5c6cb; border-left:4px solid #dc3545; '
            'border-radius:3px; padding:8px 12px; margin-bottom:12px; font-size:12px; color:#721c24;">'
            '<strong>&#9888; ROGUE DHCP ALERT:</strong> Multiple DHCP servers detected on the network! '
            'This may indicate an unauthorized DHCP server.'
            '</div>'
        )

    server_rows = ""
    for i, srv in enumerate(servers):
        bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
        dns_str = ", ".join(srv.get("dns_servers", [])) or "N/A"
        lease_hours = srv.get("lease_time", 0) / 3600 if srv.get("lease_time") else 0
        lease_str = f"{lease_hours:.0f}h" if lease_hours else "N/A"
        server_rows += f"""
        <tr style="background:{bg};">
          <td style="padding:5px 8px; font-size:12px; font-family:monospace; font-weight:bold; border-bottom:1px solid #eef2f7;">{srv.get('server_ip', 'N/A')}</td>
          <td style="padding:5px 8px; font-size:12px; font-family:monospace; border-bottom:1px solid #eef2f7;">{srv.get('offered_ip', '')}</td>
          <td style="padding:5px 8px; font-size:12px; border-bottom:1px solid #eef2f7;">{srv.get('subnet_mask', '')}</td>
          <td style="padding:5px 8px; font-size:12px; font-family:monospace; border-bottom:1px solid #eef2f7;">{srv.get('gateway', '')}</td>
          <td style="padding:5px 8px; font-size:12px; border-bottom:1px solid #eef2f7;">{dns_str}</td>
          <td style="padding:5px 8px; font-size:12px; text-align:center; border-bottom:1px solid #eef2f7;">{lease_str}</td>
          <td style="padding:5px 8px; font-size:12px; border-bottom:1px solid #eef2f7;">{srv.get('domain_name', '') or ''}</td>
        </tr>"""

    return f"""
  <!-- ═══ DHCP INFRASTRUCTURE ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0;
                 border-bottom:2px solid {company_color}; padding-bottom:8px;">
        &#9654; DHCP Infrastructure
        <span style="font-size:12px; font-weight:normal; color:#888; margin-left:8px;">
          {len(servers)} server{"s" if len(servers) != 1 else ""} detected
        </span>
      </h2>
      {rogue_warning}
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
        <tr style="background:{company_color}; color:#fff;">
          <th style="padding:6px 8px; text-align:left; font-size:11px;">DHCP Server</th>
          <th style="padding:6px 8px; text-align:left; font-size:11px;">Offered IP</th>
          <th style="padding:6px 8px; text-align:left; font-size:11px;">Mask</th>
          <th style="padding:6px 8px; text-align:left; font-size:11px;">Gateway</th>
          <th style="padding:6px 8px; text-align:left; font-size:11px;">DNS</th>
          <th style="padding:6px 8px; text-align:center; font-size:11px;">Lease</th>
          <th style="padding:6px 8px; text-align:left; font-size:11px;">Domain</th>
        </tr>
        {server_rows}
      </table>
    </td>
  </tr>"""


# ── Infrastructure Services (NTP + NAC) section ──────────────────────────

def _build_infrastructure_section(
    ntp_results: dict, nac_results: dict, company_color: str,
) -> str:
    """Build NTP + 802.1X / NAC infrastructure status section."""
    ntp_servers = (ntp_results or {}).get("ntp_servers", [])
    nac_info = nac_results or {}

    if not ntp_servers and not nac_info:
        return ""

    # NTP table
    ntp_html = ""
    if ntp_servers:
        ntp_rows = ""
        for i, srv in enumerate(ntp_servers):
            bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
            ntp_rows += f"""
            <tr style="background:{bg};">
              <td style="padding:4px 8px; font-size:12px; font-family:monospace; border-bottom:1px solid #eef2f7;">{srv.get('ip', '')}</td>
              <td style="padding:4px 8px; font-size:12px; text-align:center; border-bottom:1px solid #eef2f7;">{srv.get('stratum', '?')}</td>
              <td style="padding:4px 8px; font-size:12px; color:#555; border-bottom:1px solid #eef2f7;">{srv.get('reference', '')}</td>
            </tr>"""
        system_ntp = (ntp_results or {}).get("system_ntp", {})
        sync_badge = (
            '<span style="background:#28a745; color:#fff; font-size:10px; padding:1px 6px; border-radius:2px;">Synchronized</span>'
            if system_ntp.get("synchronized")
            else '<span style="background:#ffc107; color:#333; font-size:10px; padding:1px 6px; border-radius:2px;">Not Synchronized</span>'
        )
        ntp_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          NTP Time Servers ({len(ntp_servers)}) &nbsp; {sync_badge}
        </div>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; margin-bottom:14px;">
          <tr style="background:#e8f4fb; color:#00628a;">
            <th style="padding:5px 8px; text-align:left; font-size:11px;">IP Address</th>
            <th style="padding:5px 8px; text-align:center; font-size:11px;">Stratum</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Reference</th>
          </tr>
          {ntp_rows}
        </table>"""

    # NAC status
    nac_html = ""
    if nac_info:
        nac_detected = nac_info.get("nac_detected", False)
        evidence = nac_info.get("evidence", "")
        if nac_detected:
            nac_badge = (
                '<span style="background:#fd7e14; color:#fff; font-size:11px; font-weight:bold; '
                'padding:2px 8px; border-radius:3px;">802.1X / NAC Detected</span>'
            )
            nac_color = "#856404"
            nac_bg = "#fff3cd"
        else:
            nac_badge = (
                '<span style="background:#28a745; color:#fff; font-size:11px; font-weight:bold; '
                'padding:2px 8px; border-radius:3px;">No NAC Enforced</span>'
            )
            nac_color = "#155724"
            nac_bg = "#d4edda"

        nac_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          802.1X / Network Access Control
        </div>
        <div style="background:{nac_bg}; border:1px solid {nac_color}44; border-left:4px solid {nac_color};
                    border-radius:3px; padding:10px 14px; margin-bottom:14px;">
          {nac_badge}
          <div style="font-size:11px; color:{nac_color}; margin-top:6px;">{evidence}</div>
        </div>"""

    return f"""
  <!-- ═══ INFRASTRUCTURE SERVICES ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0;
                 border-bottom:2px solid {company_color}; padding-bottom:8px;">
        &#9632; Infrastructure Services
      </h2>
      {ntp_html}
      {nac_html}
    </td>
  </tr>"""


def _build_osint_section(osint_results: dict, company_color: str) -> str:
    """Build OSINT / External Reconnaissance report section."""
    if not osint_results:
        return ""

    summary = osint_results.get("summary", {})
    company = osint_results.get("company_identification", {})
    whois = osint_results.get("whois", {})
    shodan = osint_results.get("shodan", {})
    dns_security = osint_results.get("dns_security", [])
    crtsh = osint_results.get("crtsh_subdomains", {})

    # Quick check: if we have essentially no data, skip the section
    has_data = (
        company.get("public_ip")
        or whois.get("organization")
        or shodan.get("ports")
        or dns_security
        or crtsh
    )
    if not has_data:
        return ""

    # ── Company Identification card ──
    company_html = ""
    if company.get("public_ip") or whois.get("organization"):
        org_name = whois.get("organization") or company.get("isp", "")
        rows = ""
        if company.get("public_ip"):
            rows += (
                f'<tr><td style="padding:3px 8px; font-size:12px; color:#555; width:140px;">'
                f'Public IP</td>'
                f'<td style="padding:3px 8px; font-size:12px; font-family:monospace;">'
                f'{company["public_ip"]}</td></tr>'
            )
        if org_name:
            rows += (
                f'<tr><td style="padding:3px 8px; font-size:12px; color:#555;">'
                f'Organization (WHOIS)</td>'
                f'<td style="padding:3px 8px; font-size:12px; font-weight:bold;">'
                f'{org_name}</td></tr>'
            )
        if whois.get("net_name"):
            rows += (
                f'<tr><td style="padding:3px 8px; font-size:12px; color:#555;">'
                f'Network Name</td>'
                f'<td style="padding:3px 8px; font-size:12px;">'
                f'{whois["net_name"]}</td></tr>'
            )
        if whois.get("cidr"):
            rows += (
                f'<tr><td style="padding:3px 8px; font-size:12px; color:#555;">'
                f'Netblock (CIDR)</td>'
                f'<td style="padding:3px 8px; font-size:12px; font-family:monospace;">'
                f'{whois["cidr"]}</td></tr>'
            )
        if company.get("isp"):
            rows += (
                f'<tr><td style="padding:3px 8px; font-size:12px; color:#555;">'
                f'ISP / ASN</td>'
                f'<td style="padding:3px 8px; font-size:12px;">'
                f'{company["isp"]}</td></tr>'
            )
        loc_parts = [p for p in [company.get("city"), company.get("region"),
                                  company.get("country")] if p]
        if loc_parts:
            rows += (
                f'<tr><td style="padding:3px 8px; font-size:12px; color:#555;">'
                f'Location</td>'
                f'<td style="padding:3px 8px; font-size:12px;">'
                f'{", ".join(loc_parts)}</td></tr>'
            )
        if company.get("reverse_hostname"):
            rows += (
                f'<tr><td style="padding:3px 8px; font-size:12px; color:#555;">'
                f'Reverse DNS</td>'
                f'<td style="padding:3px 8px; font-size:12px; font-family:monospace;">'
                f'{company["reverse_hostname"]}</td></tr>'
            )
        domains = company.get("domains", [])
        if domains:
            rows += (
                f'<tr><td style="padding:3px 8px; font-size:12px; color:#555;">'
                f'Derived Domains</td>'
                f'<td style="padding:3px 8px; font-size:12px; font-family:monospace;">'
                f'{", ".join(domains)}</td></tr>'
            )

        company_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          Company Identification
        </div>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse; margin-bottom:16px; background:#f8f9fb;
                      border:1px solid #e5e9ef; border-radius:3px;">
          {rows}
        </table>"""

    # ── Shodan External Attack Surface ──
    shodan_html = ""
    ext_ports = shodan.get("ports", [])
    ext_vulns = shodan.get("vulns", [])
    ext_hosts = shodan.get("hostnames", [])
    ext_tags = shodan.get("tags", [])

    if ext_ports or ext_vulns:
        # Severity banner
        if ext_vulns:
            sev_bg = "#fff5f5"
            sev_border = "#dc3545"
            sev_icon = "&#9888;"
            sev_text = (
                f"<strong>{len(ext_vulns)} known CVE(s)</strong> and "
                f"<strong>{len(ext_ports)} externally visible port(s)</strong> "
                f"detected on public IP"
            )
        else:
            sev_bg = "#fff8f0"
            sev_border = "#fd7e14"
            sev_icon = "&#9432;"
            sev_text = (
                f"<strong>{len(ext_ports)} externally visible port(s)</strong> "
                f"detected on public IP"
            )

        port_list = ", ".join(str(p) for p in sorted(ext_ports)[:30])
        vuln_badges = ""
        for v in ext_vulns[:15]:
            vuln_badges += (
                f'<span style="display:inline-block; background:#dc3545; color:#fff; '
                f'font-size:10px; padding:1px 6px; border-radius:2px; margin:1px 2px;">'
                f'{v}</span>'
            )
        if len(ext_vulns) > 15:
            vuln_badges += (
                f'<span style="font-size:10px; color:#888;">... and '
                f'{len(ext_vulns) - 15} more</span>'
            )

        hostname_text = ""
        if ext_hosts:
            hostname_text = (
                f'<div style="font-size:11px; color:#555; margin-top:4px;">'
                f'<strong>Hostnames:</strong> {", ".join(ext_hosts[:10])}</div>'
            )

        tag_text = ""
        if ext_tags:
            tag_badges = ""
            for t in ext_tags:
                tag_badges += (
                    f'<span style="display:inline-block; background:#6c757d; color:#fff; '
                    f'font-size:10px; padding:1px 5px; border-radius:2px; margin:1px 2px;">'
                    f'{t}</span>'
                )
            tag_text = (
                f'<div style="font-size:11px; color:#555; margin-top:4px;">'
                f'<strong>Tags:</strong> {tag_badges}</div>'
            )

        shodan_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          External Attack Surface (Shodan InternetDB)
        </div>
        <div style="background:{sev_bg}; border:1px solid {sev_border}44;
                    border-left:4px solid {sev_border}; border-radius:3px;
                    padding:10px 14px; margin-bottom:14px;">
          <div style="font-size:12px; color:#333;">{sev_icon} {sev_text}</div>
          <div style="font-size:11px; color:#555; margin-top:6px;">
            <strong>Ports:</strong> {port_list}
          </div>
          {"" if not vuln_badges else f'''
          <div style="margin-top:6px;">
            <strong style="font-size:11px; color:#555;">CVEs:</strong><br>
            {vuln_badges}
          </div>'''}
          {hostname_text}
          {tag_text}
        </div>"""
    elif company.get("public_ip"):
        # IP exists but nothing in Shodan — that's actually good
        shodan_html = """
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          External Attack Surface (Shodan InternetDB)
        </div>
        <div style="background:#d4edda; border:1px solid #28a74544;
                    border-left:4px solid #28a745; border-radius:3px;
                    padding:10px 14px; margin-bottom:14px; font-size:12px; color:#155724;">
          &#10004; No externally visible ports or known vulnerabilities detected on public IP.
        </div>"""

    # ── DNS / Email Security ──
    dns_html = ""
    if dns_security:
        dns_rows = ""
        for ds in dns_security:
            domain = ds.get("domain", "")
            mx_text = ", ".join(m.get("server", "") for m in ds.get("mx_records", [])[:3])
            if not mx_text:
                mx_text = "None"
            provider = ds.get("email_provider", "")

            def _check_badge(has_it, label):
                if has_it:
                    return (
                        f'<span style="background:#28a745; color:#fff; font-size:10px; '
                        f'padding:1px 5px; border-radius:2px;">{label} &#10004;</span>'
                    )
                return (
                    f'<span style="background:#dc3545; color:#fff; font-size:10px; '
                    f'padding:1px 5px; border-radius:2px;">{label} &#10008;</span>'
                )

            spf_badge = _check_badge(ds.get("has_spf"), "SPF")
            dkim_badge = _check_badge(ds.get("has_dkim"), "DKIM")
            dmarc_badge = _check_badge(ds.get("has_dmarc"), "DMARC")

            dmarc_policy = ds.get("dmarc_policy", "")
            policy_text = ""
            if dmarc_policy:
                policy_color = {"reject": "#28a745", "quarantine": "#fd7e14",
                                "none": "#ffc107"}.get(dmarc_policy, "#6c757d")
                policy_text = (
                    f' <span style="font-size:10px; color:{policy_color}; '
                    f'font-weight:bold;">(p={dmarc_policy})</span>'
                )

            dns_rows += f"""
            <tr style="border-bottom:1px solid #eef2f7;">
              <td style="padding:5px 8px; font-size:12px; font-family:monospace;
                         font-weight:bold;">{domain}</td>
              <td style="padding:5px 8px; font-size:11px; color:#555;">{mx_text}</td>
              <td style="padding:5px 8px; font-size:11px;">{provider}</td>
              <td style="padding:5px 8px;">{spf_badge} {dkim_badge} {dmarc_badge}{policy_text}</td>
            </tr>"""

        # Email security score summary
        score = summary.get("email_security_score", "")
        score_colors = {"Strong": "#28a745", "Moderate": "#fd7e14",
                        "Weak": "#dc3545", "None": "#dc3545"}
        score_color = score_colors.get(score, "#6c757d")
        score_badge = (
            f'<span style="background:{score_color}; color:#fff; font-size:11px; '
            f'font-weight:bold; padding:2px 8px; border-radius:3px;">'
            f'Email Security: {score}</span>'
        ) if score else ""

        dns_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          Email &amp; DNS Security {score_badge}
        </div>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse; margin-bottom:6px;">
          <tr style="background:#e8f4fb; color:#00628a;">
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Domain</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">MX Records</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Provider</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Auth</th>
          </tr>
          {dns_rows}
        </table>"""

        # Add observations as bullet list
        all_obs = []
        for ds in dns_security:
            for obs in ds.get("observations", []):
                all_obs.append(obs)
        if all_obs:
            obs_items = "".join(
                f'<li style="margin-bottom:2px; color:#555;">{o}</li>'
                for o in all_obs
            )
            dns_html += f"""
        <ul style="font-size:11px; margin:4px 0 14px 16px; padding:0;">
          {obs_items}
        </ul>"""
        else:
            dns_html += '<div style="margin-bottom:14px;"></div>'

    # ── Certificate Transparency (crt.sh) ──
    crtsh_html = ""
    if crtsh:
        total_subs = sum(len(v) for v in crtsh.values())
        crtsh_rows = ""
        for domain, subs in crtsh.items():
            # Show first 20, note if more
            shown = subs[:20]
            sub_text = ", ".join(
                f'<span style="font-family:monospace; font-size:11px;">{s}</span>'
                for s in shown
            )
            if len(subs) > 20:
                sub_text += (
                    f' <span style="font-size:10px; color:#888;">... and '
                    f'{len(subs) - 20} more</span>'
                )
            crtsh_rows += f"""
            <tr style="border-bottom:1px solid #eef2f7;">
              <td style="padding:5px 8px; font-size:12px; font-family:monospace;
                         font-weight:bold; vertical-align:top; width:140px;">
                {domain}
                <div style="font-size:10px; color:#888; font-weight:normal;">
                  {len(subs)} subdomain(s)
                </div>
              </td>
              <td style="padding:5px 8px; font-size:11px; line-height:1.6;">
                {sub_text}
              </td>
            </tr>"""

        crtsh_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          Certificate Transparency (crt.sh) &mdash; {total_subs} Subdomain(s)
        </div>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse; margin-bottom:14px;">
          {crtsh_rows}
        </table>"""

    return f"""
  <!-- ═══ OSINT / EXTERNAL RECONNAISSANCE ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0;
                 border-bottom:2px solid {company_color}; padding-bottom:8px;">
        &#127760; External Reconnaissance (OSINT)
      </h2>
      {company_html}
      {shodan_html}
      {dns_html}
      {crtsh_html}
    </td>
  </tr>"""


def _build_ssl_audit_section(ssl_results: dict, company_color: str) -> str:
    """Build SSL/TLS Certificate Health Audit report section."""
    if not ssl_results:
        return ""

    certs = ssl_results.get("certificates", [])
    summary = ssl_results.get("summary", {})
    internal_cas = ssl_results.get("internal_cas", [])

    if not certs:
        return ""

    total = summary.get("total_certs", len(certs))
    expired = summary.get("expired", 0)
    expiring = summary.get("expiring_30d", 0)
    self_signed = summary.get("self_signed", 0)
    weak_key = summary.get("weak_key", 0)
    sha1 = summary.get("sha1_signature", 0)

    # Summary banner
    healthy = total - expired - expiring - self_signed
    if healthy < 0:
        healthy = 0

    if expired > 0:
        banner_bg = "#fff5f5"
        banner_border = "#dc3545"
        banner_icon = "&#9888;"
    elif expiring > 0:
        banner_bg = "#fff8f0"
        banner_border = "#fd7e14"
        banner_icon = "&#9432;"
    else:
        banner_bg = "#d4edda"
        banner_border = "#28a745"
        banner_icon = "&#10004;"

    parts = []
    if expired:
        parts.append(f'<span style="color:#dc3545; font-weight:bold;">{expired} expired</span>')
    if expiring:
        parts.append(f'<span style="color:#fd7e14; font-weight:bold;">{expiring} expiring soon</span>')
    if self_signed:
        parts.append(f'{self_signed} self-signed')
    if weak_key:
        parts.append(f'{weak_key} weak key')
    if sha1:
        parts.append(f'{sha1} SHA-1')
    summary_text = ", ".join(parts) if parts else "All certificates healthy"

    banner_html = f"""
    <div style="background:{banner_bg}; border:1px solid {banner_border}44;
                border-left:4px solid {banner_border}; border-radius:3px;
                padding:10px 14px; margin-bottom:14px; font-size:12px;">
      {banner_icon} <strong>{total} certificate(s) scanned</strong> &mdash; {summary_text}
    </div>"""

    # Certificate table (limit to 30 inline)
    MAX_INLINE_CERTS = 30
    display_certs = sorted(certs, key=lambda c: (
        0 if (c.get("days_remaining") or 999) < 0 else
        1 if (c.get("days_remaining") or 999) <= 30 else
        2 if c.get("is_self_signed") else 3,
        c.get("days_remaining") or 999,
    ))[:MAX_INLINE_CERTS]

    cert_rows = ""
    for i, c in enumerate(display_certs):
        bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
        days = c.get("days_remaining")
        if days is not None and days < 0:
            exp_badge = (
                f'<span style="background:#dc3545; color:#fff; font-size:10px; '
                f'padding:1px 5px; border-radius:2px;">Expired</span>'
            )
        elif days is not None and days <= 7:
            exp_badge = (
                f'<span style="background:#dc3545; color:#fff; font-size:10px; '
                f'padding:1px 5px; border-radius:2px;">{days}d</span>'
            )
        elif days is not None and days <= 30:
            exp_badge = (
                f'<span style="background:#fd7e14; color:#fff; font-size:10px; '
                f'padding:1px 5px; border-radius:2px;">{days}d</span>'
            )
        elif days is not None:
            exp_badge = (
                f'<span style="background:#28a745; color:#fff; font-size:10px; '
                f'padding:1px 5px; border-radius:2px;">{days}d</span>'
            )
        else:
            exp_badge = '<span style="font-size:10px; color:#888;">?</span>'

        issue_badges = ""
        for iss in c.get("issues", []):
            iss_color = "#dc3545" if "EXPIRED" in iss or "CRITICAL" in iss else (
                "#fd7e14" if "Expires" in iss or "Self-signed" in iss else
                "#6c757d"
            )
            issue_badges += (
                f'<span style="display:inline-block; background:{iss_color}22; '
                f'color:{iss_color}; font-size:9px; padding:0px 4px; '
                f'border-radius:2px; margin:1px 1px;">{iss[:50]}</span> '
            )

        key_text = f'{c.get("key_size", "?")}b' if c.get("key_size") else "?"

        cert_rows += f"""
        <tr style="background:{bg}; border-bottom:1px solid #eef2f7;">
          <td style="padding:4px 6px; font-size:11px; font-family:monospace;">{c.get('ip','')}</td>
          <td style="padding:4px 6px; font-size:11px; text-align:center;">{c.get('port','')}</td>
          <td style="padding:4px 6px; font-size:11px; font-weight:bold;">{c.get('subject_cn','')[:30]}</td>
          <td style="padding:4px 6px; font-size:11px; color:#555;">{c.get('issuer_cn','')[:25]}</td>
          <td style="padding:4px 6px; font-size:11px; text-align:center;">{exp_badge}</td>
          <td style="padding:4px 6px; font-size:11px; text-align:center;">{key_text}</td>
          <td style="padding:4px 6px; font-size:11px;">{issue_badges}</td>
        </tr>"""

    overflow_note = ""
    if len(certs) > MAX_INLINE_CERTS:
        overflow_note = (
            f'<div style="font-size:11px; color:#888; margin-top:4px; font-style:italic;">'
            f'Showing {MAX_INLINE_CERTS} of {len(certs)} certificates. '
            f'See attached CSV for full inventory.</div>'
        )

    # Internal CA note
    ca_note = ""
    if internal_cas:
        ca_list = ", ".join(internal_cas[:5])
        ca_note = f"""
        <div style="background:#e8f4fb; border:1px solid #b8daff; border-left:4px solid {company_color};
                    border-radius:3px; padding:8px 12px; margin-top:10px; font-size:11px; color:#004085;">
          <strong>&#9432; Internal CA(s) Detected:</strong> {ca_list}
          {f' — and {len(internal_cas)-5} more' if len(internal_cas) > 5 else ''}
        </div>"""

    return f"""
  <!-- ═══ SSL/TLS CERTIFICATE HEALTH ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0;
                 border-bottom:2px solid {company_color}; padding-bottom:8px;">
        &#128274; SSL/TLS Certificate Health
      </h2>
      {banner_html}
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse; margin-bottom:6px;">
        <tr style="background:#e8f4fb; color:#00628a;">
          <th style="padding:5px 6px; text-align:left; font-size:10px; width:90px;">IP</th>
          <th style="padding:5px 6px; text-align:center; font-size:10px; width:40px;">Port</th>
          <th style="padding:5px 6px; text-align:left; font-size:10px;">Subject CN</th>
          <th style="padding:5px 6px; text-align:left; font-size:10px;">Issuer</th>
          <th style="padding:5px 6px; text-align:center; font-size:10px; width:50px;">Expiry</th>
          <th style="padding:5px 6px; text-align:center; font-size:10px; width:40px;">Key</th>
          <th style="padding:5px 6px; text-align:left; font-size:10px;">Issues</th>
        </tr>
        {cert_rows}
      </table>
      {overflow_note}
      {ca_note}
    </td>
  </tr>"""


def _build_backup_section(backup_results: dict, company_color: str) -> str:
    """Build Backup & DR Posture Inference report section."""
    if not backup_results:
        return ""

    summary = backup_results.get("summary", {})
    backup_sw = backup_results.get("backup_software", [])
    storage = backup_results.get("storage_targets", [])
    hypers = backup_results.get("hypervisors", [])
    replication = backup_results.get("replication_indicators", [])
    observations = backup_results.get("observations", [])

    # Coverage badge
    coverage = summary.get("estimated_coverage", "None")
    cov_colors = {"Good": "#28a745", "Partial": "#fd7e14", "None": "#dc3545"}
    cov_color = cov_colors.get(coverage, "#6c757d")
    cov_badge = (
        f'<span style="background:{cov_color}; color:#fff; font-size:11px; '
        f'font-weight:bold; padding:2px 8px; border-radius:3px;">'
        f'Coverage: {coverage}</span>'
    )

    offsite_badge = ""
    if summary.get("has_offsite_replication"):
        offsite_badge = (
            ' <span style="background:#28a745; color:#fff; font-size:10px; '
            'padding:1px 6px; border-radius:2px;">Offsite &#10004;</span>'
        )
    else:
        offsite_badge = (
            ' <span style="background:#dc3545; color:#fff; font-size:10px; '
            'padding:1px 6px; border-radius:2px;">No Offsite &#10008;</span>'
        )

    # Backup software table
    sw_html = ""
    if backup_sw:
        sw_rows = ""
        for i, b in enumerate(backup_sw):
            bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
            sw_rows += f"""
            <tr style="background:{bg}; border-bottom:1px solid #eef2f7;">
              <td style="padding:4px 8px; font-size:12px; font-family:monospace;">{b.get('ip','')}</td>
              <td style="padding:4px 8px; font-size:12px;">{b.get('hostname','')}</td>
              <td style="padding:4px 8px; font-size:12px; font-weight:bold;">{b.get('product','')}</td>
              <td style="padding:4px 8px; font-size:11px; color:#555;">{b.get('evidence','')}</td>
            </tr>"""
        sw_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          Backup Software ({len(backup_sw)})
        </div>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse; margin-bottom:14px;">
          <tr style="background:#e8f4fb; color:#00628a;">
            <th style="padding:5px 8px; text-align:left; font-size:11px; width:100px;">IP</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Hostname</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Product</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Evidence</th>
          </tr>
          {sw_rows}
        </table>"""

    # Storage targets table
    stor_html = ""
    if storage:
        stor_rows = ""
        for i, s in enumerate(storage):
            bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
            role_badge = (
                f'<span style="background:#17a2b8; color:#fff; font-size:9px; '
                f'padding:1px 4px; border-radius:2px;">{s.get("role","")}</span>'
            )
            stor_rows += f"""
            <tr style="background:{bg}; border-bottom:1px solid #eef2f7;">
              <td style="padding:4px 8px; font-size:12px; font-family:monospace;">{s.get('ip','')}</td>
              <td style="padding:4px 8px; font-size:12px;">{s.get('hostname','')}</td>
              <td style="padding:4px 8px; font-size:12px; font-weight:bold;">{s.get('product','')}</td>
              <td style="padding:4px 8px; font-size:11px;">{role_badge}</td>
            </tr>"""
        stor_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          Storage Targets ({len(storage)})
        </div>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse; margin-bottom:14px;">
          <tr style="background:#e8f4fb; color:#00628a;">
            <th style="padding:5px 8px; text-align:left; font-size:11px; width:100px;">IP</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Hostname</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Product</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px; width:70px;">Role</th>
          </tr>
          {stor_rows}
        </table>"""

    # Hypervisors table
    hyp_html = ""
    if hypers:
        hyp_rows = ""
        for i, h in enumerate(hypers):
            bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
            hyp_rows += f"""
            <tr style="background:{bg}; border-bottom:1px solid #eef2f7;">
              <td style="padding:4px 8px; font-size:12px; font-family:monospace;">{h.get('ip','')}</td>
              <td style="padding:4px 8px; font-size:12px;">{h.get('hostname','')}</td>
              <td style="padding:4px 8px; font-size:12px; font-weight:bold;">{h.get('product','')[:50]}</td>
              <td style="padding:4px 8px; font-size:11px; color:#555;">{h.get('evidence','')[:60]}</td>
            </tr>"""
        hyp_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">
          Hypervisors ({len(hypers)})
        </div>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse; margin-bottom:14px;">
          <tr style="background:#e8f4fb; color:#00628a;">
            <th style="padding:5px 8px; text-align:left; font-size:11px; width:100px;">IP</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Hostname</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Product</th>
            <th style="padding:5px 8px; text-align:left; font-size:11px;">Evidence</th>
          </tr>
          {hyp_rows}
        </table>"""

    # Observations
    obs_html = ""
    if observations:
        obs_items = "".join(
            f'<li style="margin-bottom:3px; color:#555;">{o}</li>'
            for o in observations
        )
        obs_html = f"""
        <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:4px;">
          Observations
        </div>
        <ul style="font-size:11px; margin:0 0 8px 16px; padding:0;">
          {obs_items}
        </ul>"""

    return f"""
  <!-- ═══ BACKUP & DR POSTURE ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0;
                 border-bottom:2px solid {company_color}; padding-bottom:8px;">
        &#128190; Backup &amp; Disaster Recovery Posture
      </h2>
      <div style="margin-bottom:12px;">{cov_badge} {offsite_badge}</div>
      {sw_html}
      {stor_html}
      {hyp_html}
      {obs_html}
    </td>
  </tr>"""


def _build_eol_section(eol_results: dict, company_color: str) -> str:
    """Build End-of-Life / End-of-Support Detection report section."""
    if not eol_results:
        return ""

    eol_devices = eol_results.get("eol_devices", [])
    approaching = eol_results.get("approaching_eol", [])
    eol_services = eol_results.get("eol_services", [])
    summary = eol_results.get("summary", {})

    all_entries = eol_devices + approaching + eol_services
    if not all_entries:
        return ""

    crit = summary.get("critical_eol_count", 0)
    high = summary.get("high_eol_count", 0)
    med = summary.get("medium_eol_count", 0)
    top_risk = summary.get("top_risk", "")

    # Summary banner
    if crit > 0:
        banner_bg = "#fff5f5"
        banner_border = "#dc3545"
        banner_icon = "&#9888;"
    elif high > 0:
        banner_bg = "#fff8f0"
        banner_border = "#fd7e14"
        banner_icon = "&#9888;"
    else:
        banner_bg = "#fff8f0"
        banner_border = "#ffc107"
        banner_icon = "&#9432;"

    count_parts = []
    if crit:
        count_parts.append(
            f'<span style="color:#dc3545; font-weight:bold;">{crit} CRITICAL</span>'
        )
    if high:
        count_parts.append(
            f'<span style="color:#fd7e14; font-weight:bold;">{high} HIGH</span>'
        )
    if med:
        count_parts.append(f'{med} MEDIUM')
    count_text = ", ".join(count_parts)

    risk_text = ""
    if top_risk:
        risk_text = f'<div style="font-size:11px; color:#555; margin-top:4px;">Top risk: <strong>{top_risk}</strong></div>'

    banner_html = f"""
    <div style="background:{banner_bg}; border:1px solid {banner_border}44;
                border-left:4px solid {banner_border}; border-radius:3px;
                padding:10px 14px; margin-bottom:14px; font-size:12px;">
      {banner_icon} <strong>{len(all_entries)} end-of-life product(s) detected</strong>
      &mdash; {count_text}
      {risk_text}
    </div>"""

    # Aggregate by product for cleaner display
    product_agg = {}
    for e in all_entries:
        key = (e["product"], e["severity"], e["eol_date"])
        if key not in product_agg:
            product_agg[key] = {
                "product": e["product"],
                "severity": e["severity"],
                "eol_date": e["eol_date"],
                "notes": e.get("notes", ""),
                "ips": [],
                "match_source": e.get("match_source", ""),
                "version_sample": e.get("version_detected", ""),
            }
        product_agg[key]["ips"].append(e["ip"])

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_products = sorted(
        product_agg.values(),
        key=lambda p: (severity_order.get(p["severity"], 9), p["product"]),
    )

    rows = ""
    for i, p in enumerate(sorted_products):
        bg = "#ffffff" if i % 2 == 0 else "#f9fbfd"
        sev = p["severity"]
        sev_colors = {
            "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107", "LOW": "#6c757d", "INFO": "#17a2b8",
        }
        sev_color = sev_colors.get(sev, "#6c757d")
        sev_text_color = "#fff" if sev in ("CRITICAL", "HIGH") else "#333"
        sev_badge = (
            f'<span style="background:{sev_color}; color:{sev_text_color}; '
            f'font-size:10px; padding:1px 5px; border-radius:2px;">{sev}</span>'
        )

        ips_display = ", ".join(p["ips"][:4])
        if len(p["ips"]) > 4:
            ips_display += f" +{len(p['ips']) - 4} more"

        rows += f"""
        <tr style="background:{bg}; border-bottom:1px solid #eef2f7;">
          <td style="padding:5px 8px; font-size:11px;">{sev_badge}</td>
          <td style="padding:5px 8px; font-size:12px; font-weight:bold;">{p['product']}</td>
          <td style="padding:5px 8px; font-size:11px; color:#555;">{p['eol_date']}</td>
          <td style="padding:5px 8px; font-size:11px; text-align:center; font-weight:bold;">{len(p['ips'])}</td>
          <td style="padding:5px 8px; font-size:11px; font-family:monospace; color:#555;">{ips_display}</td>
          <td style="padding:5px 8px; font-size:10px; color:#888;">{p['notes'][:60]}</td>
        </tr>"""

    return f"""
  <!-- ═══ END-OF-LIFE DETECTION ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0;
                 border-bottom:2px solid {company_color}; padding-bottom:8px;">
        &#9200; End-of-Life / End-of-Support
      </h2>
      {banner_html}
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse; margin-bottom:8px;">
        <tr style="background:#e8f4fb; color:#00628a;">
          <th style="padding:5px 8px; text-align:left; font-size:10px; width:65px;">Severity</th>
          <th style="padding:5px 8px; text-align:left; font-size:10px;">Product</th>
          <th style="padding:5px 8px; text-align:left; font-size:10px; width:80px;">EOL Date</th>
          <th style="padding:5px 8px; text-align:center; font-size:10px; width:50px;">Count</th>
          <th style="padding:5px 8px; text-align:left; font-size:10px;">Affected Devices</th>
          <th style="padding:5px 8px; text-align:left; font-size:10px;">Notes</th>
        </tr>
        {rows}
      </table>
      <p style="color:#888; font-size:11px; margin:4px 0 0 0; font-style:italic;">
        EOL dates sourced from vendor lifecycle documentation. Products past end-of-support
        no longer receive security patches and represent elevated risk.
      </p>
    </td>
  </tr>"""


# ── Main report builder ────────────────────────────────────────────────────

def build_discovery_report(scan_results: dict, config: dict) -> tuple:
    """
    Build subject + full HTML email report from scan_results dict.
    Returns (subject: str, html: str).
    """
    reporting = config.get("reporting", {})
    company_name = reporting.get("company_name", "Pacific Office Automation Inc.")
    company_color = reporting.get("company_color", "#00A0D9")
    tagline = reporting.get("tagline", "Problem Solved.")
    device_name = config.get("system", {}).get("device_name", "NetDiscovery-Pi")

    hosts = scan_results.get("hosts", [])
    summary = scan_results.get("summary", {})
    recon = scan_results.get("reconnaissance", {})
    topology = scan_results.get("topology", {})

    scan_start = scan_results.get("scan_start", "")
    scan_end = scan_results.get("scan_end", "")
    duration = scan_results.get("duration_seconds", 0)
    scanner_host = scan_results.get("scanner_host", device_name)

    # Parse datetime for display
    try:
        dt = datetime.fromisoformat(scan_start)
        scan_date = dt.strftime("%B %d, %Y %I:%M %p")
    except Exception:
        scan_date = scan_start

    duration_str = f"{int(duration // 60)}m {int(duration % 60)}s"

    total_hosts = summary.get("total_hosts", len(hosts))
    total_ports = summary.get("total_open_ports", 0)
    security_obs = summary.get("security_observations", 0)
    subnet_labels = scan_results.get("subnet_labels", {})

    # Format subnets with labels when available (e.g. "192.168.1.0/24 (Corporate LAN)")
    def _label_cidr(cidr):
        label = subnet_labels.get(cidr, "")
        return f"{cidr} ({label})" if label else cidr

    subnets_scanned = summary.get("subnets_scanned", [])
    subnets = ", ".join(_label_cidr(s) for s in subnets_scanned) or "N/A"
    gateway = recon.get("default_gateway", "N/A")
    dns_servers = ", ".join(recon.get("dns_servers", [])) or "N/A"
    additional_subnets_found = summary.get("additional_subnets_found", 0)
    additional_subnet_names = ", ".join(
        _label_cidr(s.get("cidr", "")) for s in recon.get("additional_subnets", [])
    ) or ""

    # For large networks, truncate the inline device table to stay under
    # Graph API's 4 MB email limit. Prioritize hosts with security flags
    # and the most open ports so the SE sees the most important devices.
    truncated = False
    display_hosts = hosts
    if len(hosts) > MAX_INLINE_DEVICES:
        truncated = True
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        def _host_priority(h):
            flags = h.get("security_flags", [])
            best_sev = min((severity_order.get(f.get("severity", "INFO"), 9) for f in flags), default=9)
            return (best_sev, -len(h.get("open_ports", [])))
        display_hosts = sorted(hosts, key=_host_priority)[:MAX_INLINE_DEVICES]

    device_rows = _build_device_rows(display_hosts, company_color)
    security_rows = _build_security_section(hosts, company_color)
    category_cards = _build_category_cards(summary, company_color)
    services_table = _build_services_table(summary)
    msp_summary = _build_msp_summary(hosts, summary, recon, company_color)
    ad_section = _build_ad_section(hosts, company_color)
    delta_section = _build_delta_section(summary, company_color)

    # Extended discovery sections
    wifi_results = scan_results.get("wifi", {})
    mdns_results = scan_results.get("mdns", {})
    ssdp_results = scan_results.get("ssdp", {})
    dhcp_results = scan_results.get("dhcp_analysis", {})
    ntp_results = scan_results.get("ntp", {})
    nac_results = scan_results.get("nac", {})
    osint_results = scan_results.get("osint", {})
    ssl_audit_results = scan_results.get("ssl_audit", {})
    backup_results = scan_results.get("backup_posture", {})
    eol_results = scan_results.get("eol_detection", {})

    wifi_section = _build_wifi_section(wifi_results, company_color)
    protocol_section = _build_protocol_discovery_section(mdns_results, ssdp_results, company_color)
    dhcp_section = _build_dhcp_section(dhcp_results, company_color)
    infra_section = _build_infrastructure_section(ntp_results, nac_results, company_color)
    osint_section = _build_osint_section(osint_results, company_color)
    ssl_audit_section = _build_ssl_audit_section(ssl_audit_results, company_color)
    backup_section = _build_backup_section(backup_results, company_color)
    eol_section = _build_eol_section(eol_results, company_color)

    critical_count = len(summary.get("critical_hosts", []))
    security_color = "#dc3545" if critical_count > 0 else ("#fd7e14" if security_obs > 5 else "#2d6a4f")
    security_bg = "#fff5f5" if critical_count > 0 else ("#fff8f0" if security_obs > 5 else "#d8f3dc")

    subject = (
        f"[Network Discovery] {company_name} - {total_hosts} Devices Found | {scan_date}"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Discovery Report - {company_name}</title>
</head>
<body style="margin:0; padding:0; background:#f0f2f5; font-family:Arial, Helvetica, sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5; padding:24px 0;">
<tr><td align="center">
<table width="680" cellpadding="0" cellspacing="0" style="background:#fff; border-radius:6px; overflow:hidden; box-shadow:0 3px 12px rgba(0,0,0,0.12);">

  <!-- ═══ HEADER ═══ -->
  <tr>
    <td style="background:{company_color}; padding:30px 36px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td>
            <div style="color:#fff; font-size:24px; font-weight:bold; letter-spacing:0.3px;">
              {company_name}
            </div>
            <div style="color:rgba(255,255,255,0.85); font-size:13px; margin-top:5px;">
              Network Discovery Report &bull; {scan_date}
            </div>
          </td>
          <td align="right" style="vertical-align:top;">
            <div style="color:rgba(255,255,255,0.95); font-size:13px; font-style:italic; text-align:right; margin-top:4px;">
              {tagline}
            </div>
            <div style="color:rgba(255,255,255,0.7); font-size:10px; margin-top:4px; text-align:right;">
              Powered by Yeyland Wutani
            </div>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  {msp_summary}

  <!-- ═══ EXECUTIVE SUMMARY ═══ -->
  <tr>
    <td style="padding:28px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 16px 0; border-bottom:2px solid {company_color}; padding-bottom:8px;">
        Scan Summary
      </h2>
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="width:25%; padding:0 8px 0 0; text-align:center; vertical-align:top;">
            <div style="background:#e8f4fb; border-radius:8px; padding:16px 8px;">
              <div style="font-size:36px; font-weight:bold; color:{company_color};">{total_hosts}</div>
              <div style="font-size:11px; color:#555; margin-top:4px;">Devices Discovered</div>
            </div>
          </td>
          <td style="width:25%; padding:0 8px; text-align:center; vertical-align:top;">
            <div style="background:#f0f8e8; border-radius:8px; padding:16px 8px;">
              <div style="font-size:36px; font-weight:bold; color:#5a9a2b;">{total_ports}</div>
              <div style="font-size:11px; color:#555; margin-top:4px;">Open Ports Found</div>
            </div>
          </td>
          <td style="width:25%; padding:0 8px; text-align:center; vertical-align:top;">
            <div style="background:{security_bg}; border-radius:8px; padding:16px 8px;">
              <div style="font-size:36px; font-weight:bold; color:{security_color};">{security_obs}</div>
              <div style="font-size:11px; color:#555; margin-top:4px;">Security Observations</div>
            </div>
          </td>
          <td style="width:25%; padding:0 0 0 8px; text-align:center; vertical-align:top;">
            <div style="background:#f5f0ff; border-radius:8px; padding:16px 8px;">
              <div style="font-size:26px; font-weight:bold; color:#7b4fa6;">{duration_str}</div>
              <div style="font-size:11px; color:#555; margin-top:4px;">Scan Duration</div>
            </div>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- ═══ NETWORK OVERVIEW ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0; border-bottom:2px solid {company_color}; padding-bottom:8px;">
        Network Overview
      </h2>
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="padding:5px 0; color:#555; font-size:13px; width:160px;">Subnets Scanned</td>
          <td style="padding:5px 0; color:#222; font-size:13px; font-weight:bold;">{subnets}</td>
        </tr>
        <tr>
          <td style="padding:5px 0; color:#555; font-size:13px;">Default Gateway</td>
          <td style="padding:5px 0; color:#222; font-size:13px;">{gateway}</td>
        </tr>
        <tr>
          <td style="padding:5px 0; color:#555; font-size:13px;">DNS Servers</td>
          <td style="padding:5px 0; color:#222; font-size:13px;">{dns_servers}</td>
        </tr>
        <tr>
          <td style="padding:5px 0; color:#555; font-size:13px;">Scanner Device</td>
          <td style="padding:5px 0; color:#222; font-size:13px;">{scanner_host} ({device_name})</td>
        </tr>
        {"" if not additional_subnets_found else f"""
        <tr>
          <td style="padding:5px 0; color:#555; font-size:13px;">Additional Subnets Found</td>
          <td style="padding:5px 0; font-size:13px;">
            <span style="background:#fff3cd; color:#856404; font-weight:bold; padding:1px 6px; border-radius:3px;">{additional_subnets_found}</span>
            {"&nbsp;<span style='color:#888; font-size:11px;'>(" + additional_subnet_names + ")</span>" if additional_subnet_names else ""}
          </td>
        </tr>"""}
      </table>
    </td>
  </tr>

  <!-- ═══ DEVICE CATEGORIES ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0; border-bottom:2px solid {company_color}; padding-bottom:8px;">
        Device Breakdown
      </h2>
      {category_cards}
    </td>
  </tr>

  <!-- ═══ TOP SERVICES ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0; border-bottom:2px solid {company_color}; padding-bottom:8px;">
        Services Summary (Top 10)
      </h2>
      {services_table}
    </td>
  </tr>

  {delta_section}

  {ad_section}

  {wifi_section}

  {protocol_section}

  {dhcp_section}

  {infra_section}

  {osint_section}

  {ssl_audit_section}

  {backup_section}

  {eol_section}

  <!-- ═══ SECURITY OBSERVATIONS ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:#c0392b; font-size:17px; margin:0 0 12px 0; border-bottom:2px solid #c0392b; padding-bottom:8px;">
        Security Observations
      </h2>

      <!-- Rolled-up by issue type -->
      {"" if not summary.get("security_gaps") else f"""
      <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">By Issue Type</div>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse; margin-bottom:16px; font-size:12px;">
        <tr style="background:#f5e6e6; color:#8b0000;">
          <th style="padding:6px 10px; text-align:left; width:80px;">Severity</th>
          <th style="padding:6px 10px; text-align:left;">Issue</th>
          <th style="padding:6px 10px; text-align:left; width:60px;">Count</th>
          <th style="padding:6px 10px; text-align:left;">Affected Devices</th>
        </tr>
        {"".join(
          f'<tr style="border-bottom:1px solid #f0e0e0;">'
          f'<td style="padding:5px 10px;">{_severity_badge(g["severity"])}</td>'
          f'<td style="padding:5px 10px; font-weight:bold; color:#333;">{g["issue"]}</td>'
          f'<td style="padding:5px 10px; color:#555;">{g["count"]}</td>'
          f'<td style="padding:5px 10px; color:#888; font-family:monospace; font-size:11px;">'
          f'{", ".join(g["ips"][:4])}{"..." if len(g["ips"]) > 4 else ""}</td>'
          f'</tr>'
          for g in summary.get("security_gaps", [])
        )}
      </table>
      <div style="font-size:12px; font-weight:bold; color:#555; margin-bottom:6px;">By Device</div>
      """}

      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
        <tr style="background:{company_color}; color:#fff;">
          <th style="padding:8px 10px; text-align:left; font-size:12px; width:120px;">IP Address</th>
          <th style="padding:8px 10px; text-align:left; font-size:12px; width:160px;">Hostname</th>
          <th style="padding:8px 10px; text-align:left; font-size:12px;">Observation</th>
        </tr>
        {security_rows}
      </table>
      <p style="color:#888; font-size:11px; margin:8px 0 0 0; font-style:italic;">
        Note: These observations are informational. All scanning was non-intrusive and performed
        with authorization. Remediation recommendations available upon request.
      </p>
    </td>
  </tr>

  <!-- ═══ ALL DISCOVERED DEVICES ═══ -->
  <tr>
    <td style="padding:24px 36px 0 36px;">
      <h2 style="color:{company_color}; font-size:17px; margin:0 0 12px 0; border-bottom:2px solid {company_color}; padding-bottom:8px;">
        All Discovered Devices ({total_hosts})
      </h2>
      {"" if not truncated else f"""
      <div style="background:#fff3cd; border:1px solid #ffc107; border-left:4px solid #e69900;
                  border-radius:3px; padding:10px 14px; margin-bottom:12px; font-size:12px; color:#856404;">
        <strong>&#9888; Large Network:</strong> Showing top {MAX_INLINE_DEVICES} of {total_hosts} devices
        (prioritized by security flags). See the attached CSV for the full inventory.
      </div>"""}
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; font-size:12px;">
        <tr style="background:{company_color}; color:#fff;">
          <th style="padding:8px 10px; text-align:left; width:100px;">IP Address</th>
          <th style="padding:8px 10px; text-align:left; width:140px;">Type</th>
          <th style="padding:8px 10px; text-align:left; width:140px;">Hostname</th>
          <th style="padding:8px 10px; text-align:left; width:130px;">MAC / Vendor</th>
          <th style="padding:8px 10px; text-align:left;">Open Ports</th>
          <th style="padding:8px 10px; text-align:left; width:80px;">Flags</th>
        </tr>
        {device_rows}
      </table>
    </td>
  </tr>

  <!-- ═══ FOOTER ═══ -->
  <tr>
    <td style="background:#f8f9fa; border-top:2px solid {company_color}; padding:20px 36px; margin-top:28px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="color:#555; font-size:11px;">
            <strong style="color:{company_color};">{company_name}</strong>
            &bull; <em>{tagline}</em>
          </td>
          <td align="right" style="color:#888; font-size:11px;">
            Powered by <strong>Yeyland Wutani</strong> Network Discovery Pi
          </td>
        </tr>
        <tr>
          <td colspan="2" style="color:#aaa; font-size:10px; padding-top:6px;">
            Scan started: {scan_start} &nbsp;&bull;&nbsp;
            Completed: {scan_end} &nbsp;&bull;&nbsp;
            Duration: {duration_str} &nbsp;&bull;&nbsp;
            Scanner: {scanner_host}
          </td>
        </tr>
        <tr>
          <td colspan="2" style="color:#ccc; font-size:10px; padding-top:4px; font-style:italic;">
            This report was generated by an authorized network discovery tool for sales engineering purposes.
            All data collected is confidential and intended for internal use only.
          </td>
        </tr>
      </table>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>"""

    return subject, html


# ── CSV export ─────────────────────────────────────────────────────────────

def build_csv_attachment(hosts: list, scan_results: dict = None) -> bytes:
    """Generate a CSV report of all discovered hosts. Returns bytes.

    When *scan_results* is provided, mDNS and SSDP data are correlated
    with host IPs so the CSV shows which services each host advertises.
    """
    # Pre-build IP -> mDNS/SSDP lookup maps
    mdns_by_ip: dict = {}
    ssdp_by_ip: dict = {}
    ssl_by_ip: dict = {}
    eol_by_ip: dict = {}
    backup_role_by_ip: dict = {}
    if scan_results:
        for svc in (scan_results.get("mdns", {}) or {}).get("services", []):
            ip = svc.get("ip", "")
            if ip:
                mdns_by_ip.setdefault(ip, []).append(
                    f'{svc.get("name", "")}({svc.get("service_type", "")})'
                )
        for dev in (scan_results.get("ssdp", {}) or {}).get("devices", []):
            ip = dev.get("ip", "")
            if ip:
                name = dev.get("friendly_name", "") or dev.get("service_type", "")
                ssdp_by_ip.setdefault(ip, []).append(name)
        # SSL audit data by IP
        for cert in (scan_results.get("ssl_audit", {}) or {}).get("certificates", []):
            ip = cert.get("ip", "")
            if ip:
                ssl_by_ip.setdefault(ip, []).append(cert)
        # EOL data by IP
        for entry in (
            (scan_results.get("eol_detection", {}) or {}).get("eol_devices", [])
            + (scan_results.get("eol_detection", {}) or {}).get("approaching_eol", [])
            + (scan_results.get("eol_detection", {}) or {}).get("eol_services", [])
        ):
            ip = entry.get("ip", "")
            if ip:
                eol_by_ip.setdefault(ip, []).append(entry.get("product", ""))
        # Backup role by IP
        bp = scan_results.get("backup_posture", {}) or {}
        for sw in bp.get("backup_software", []):
            backup_role_by_ip[sw.get("ip", "")] = f'Backup: {sw.get("product", "")}'
        for st in bp.get("storage_targets", []):
            backup_role_by_ip.setdefault(st.get("ip", ""), f'Storage: {st.get("product", "")}')
        for hv in bp.get("hypervisors", []):
            backup_role_by_ip.setdefault(hv.get("ip", ""), f'Hypervisor: {hv.get("product", "")}')

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "IP Address", "Hostname", "MAC Address", "Vendor",
        "Category", "Open Ports", "Port Count",
        "HTTP Title", "SMB Computer", "SMB Domain",
        "Security Flags", "Flag Severities",
        "OS Guess", "SNMP Name", "SNMP Location", "SNMP Working Community",
        "SSL Cert Expires", "SSH Banner", "FTP Banner", "Service Versions",
        "Subnet Source", "Subnet Label", "Gateway Info", "SNMP Interfaces",
        "mDNS Services", "SSDP / UPnP Devices",
        "SSL Cert Issuer", "SSL Cert Days Left", "SSL Issues",
        "EOL Products", "Backup/DR Role",
    ])
    for host in hosts:
        ports = sorted(host.get("open_ports", []))
        services = host.get("services", {})
        flags = host.get("security_flags", [])

        # HTTP title
        http_title = ""
        for port in (80, 443, 8080, 8443):
            svc = services.get(port, {})
            if isinstance(svc, dict) and svc.get("title"):
                http_title = svc["title"]
                break

        # SMB info
        smb = services.get("smb", {}) or {}
        smb_computer = smb.get("smb_computer", "")
        smb_domain = smb.get("smb_domain", "")

        flag_desc = " | ".join(f.get("flag", "") for f in flags)
        flag_sev = " | ".join(f.get("severity", "") for f in flags)

        # New enhanced fields
        snmp = services.get("snmp", {}) or {}
        ssl_cert = services.get("ssl_cert", {}) or {}

        ssh_banner = ""
        svc_22 = services.get(22, {})
        if isinstance(svc_22, dict):
            ssh_banner = svc_22.get("banner", "")

        ftp_banner = ""
        svc_21 = services.get(21, {})
        if isinstance(svc_21, dict):
            ftp_banner = svc_21.get("banner", "")

        # Collect service version strings for key ports
        version_parts = []
        for vport in (22, 80, 443, 21, 25, 3389):
            svc = services.get(vport, {})
            if isinstance(svc, dict) and svc.get("version"):
                version_parts.append(f"{vport}:{svc['version']}")
        service_versions = " | ".join(version_parts)

        ip = host.get("ip", "")

        writer.writerow([
            ip,
            host.get("hostname", ""),
            host.get("mac", ""),
            host.get("vendor", ""),
            host.get("category", ""),
            ",".join(str(p) for p in ports),
            len(ports),
            http_title,
            smb_computer,
            smb_domain,
            flag_desc,
            flag_sev,
            host.get("os_guess", ""),
            snmp.get("sysName", ""),
            snmp.get("sysLocation", ""),
            snmp.get("working_community", ""),
            ssl_cert.get("expires", ""),
            ssh_banner,
            ftp_banner,
            service_versions,
            host.get("subnet_source", "primary"),
            host.get("subnet_label", ""),
            # Gateway firewall model
            (" ".join(filter(None, [
                host.get("gateway_info", {}).get("vendor", ""),
                host.get("gateway_info", {}).get("product", ""),
                host.get("gateway_info", {}).get("model", ""),
            ])) if host.get("gateway_info") else ""),
            # SNMP interface list
            " | ".join(snmp.get("ifDescr", [])),
            # mDNS services for this IP
            " | ".join(mdns_by_ip.get(ip, [])),
            # SSDP/UPnP devices for this IP
            " | ".join(ssdp_by_ip.get(ip, [])),
            # SSL cert issuer (first cert for this IP)
            (ssl_by_ip.get(ip, [{}])[0].get("issuer_cn", "")
             if ssl_by_ip.get(ip) else ""),
            # SSL cert days remaining
            (str(ssl_by_ip.get(ip, [{}])[0].get("days_remaining", ""))
             if ssl_by_ip.get(ip) else ""),
            # SSL issues
            (" | ".join(ssl_by_ip.get(ip, [{}])[0].get("issues", []))
             if ssl_by_ip.get(ip) else ""),
            # EOL products
            " | ".join(sorted(set(eol_by_ip.get(ip, [])))),
            # Backup/DR role
            backup_role_by_ip.get(ip, ""),
        ])

    return output.getvalue().encode("utf-8")


# ── Error notification email ───────────────────────────────────────────────

def build_error_email(error_message: str, config: dict) -> tuple:
    """Build a simple error notification email."""
    reporting = config.get("reporting", {})
    company_name = reporting.get("company_name", "Pacific Office Automation Inc.")
    company_color = reporting.get("company_color", "#00A0D9")
    tagline = reporting.get("tagline", "Problem Solved.")
    device_name = config.get("system", {}).get("device_name", "NetDiscovery-Pi")
    timestamp = datetime.now().isoformat()

    subject = f"[Network Discovery Pi] ERROR on {device_name} - {timestamp}"
    html = f"""<!DOCTYPE html>
<html lang="en">
<body style="margin:0; padding:20px; background:#f4f4f4; font-family:Arial, sans-serif;">
  <table width="600" cellpadding="0" cellspacing="0" style="background:#fff; border-radius:4px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,0.1);">
    <tr><td style="background:{company_color}; padding:24px 28px;">
      <div style="color:#fff; font-size:20px; font-weight:bold;">{company_name}</div>
      <div style="color:rgba(255,255,255,0.85); font-size:12px; margin-top:4px;">
        Network Discovery Pi &bull; Error Notification
      </div>
    </td></tr>
    <tr><td style="background:#fff3f3; border-left:4px solid #dc3545; padding:16px 28px;">
      <strong style="color:#dc3545;">Discovery Failed</strong> &mdash; {timestamp}
    </td></tr>
    <tr><td style="padding:24px 28px;">
      <p style="color:#333; font-size:14px;">The network discovery process on <strong>{device_name}</strong> encountered a critical error and could not complete.</p>
      <div style="background:#f8f8f8; border:1px solid #ddd; border-radius:4px; padding:12px 16px; font-family:monospace; font-size:12px; color:#c0392b; white-space:pre-wrap;">{error_message}</div>
      <p style="color:#555; font-size:13px; margin-top:16px;">Please check the device logs at <code>/opt/network-discovery/logs/</code> for more details.</p>
    </td></tr>
    <tr><td style="background:#f8f8f8; border-top:1px solid #e8e8e8; padding:14px 28px;">
      <span style="color:#888; font-size:11px;">
        Powered by <strong style="color:{company_color};">Yeyland Wutani</strong> Network Discovery Pi
        &bull; {company_name} &bull; <em>{tagline}</em>
      </span>
    </td></tr>
  </table>
</body>
</html>"""
    return subject, html
