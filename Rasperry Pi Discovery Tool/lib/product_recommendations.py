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
    """
    wired      = env["estimated_wired"]
    ports_need = max(8, int(wired * 1.25))  # 25% growth room

    candidates = [s for s in catalog.get("switches", [])
                  if s["ports"] >= min(ports_need, s["ports"])]

    if not candidates:
        candidates = catalog.get("switches", [])

    # Pick the smallest single-switch that covers the need; if none, stack 48-port
    single = [s for s in candidates if s["ports"] >= ports_need]
    if single:
        product = min(single, key=lambda s: s["ports"])
        count = 1
    else:
        # Need multiple switches — use the 48-port model
        product = max(candidates, key=lambda s: s["ports"])
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

    # Pick model: AP25 for dense environments, AP22 for general
    aps = catalog.get("access_points", [])
    indoor_aps = [a for a in aps if a.get("indoor_outdoor") == "Indoor"]
    if not indoor_aps:
        return None

    # Use AP25 if more than 30 wireless devices, otherwise AP22
    if wireless > 30:
        product = next((a for a in indoor_aps if a["model"] == "AP25"), indoor_aps[-1])
    else:
        product = next((a for a in indoor_aps if a["model"] == "AP22"), indoor_aps[0])

    max_clients = product.get("max_clients", 30)
    count = max(1, math.ceil(wireless / max_clients))

    return product, count


def _select_servers(env: dict, catalog: dict) -> Optional[tuple]:
    """
    Return (product_dict, count) or None if no servers detected.
    """
    server_count = env["server_count"]
    if server_count == 0:
        return None

    candidates = [s for s in catalog.get("servers", [])
                  if s["min_servers"] <= server_count <= s["max_servers"]]
    if not candidates:
        candidates = catalog.get("servers", [])
        product = max(candidates, key=lambda s: s["max_servers"]) if candidates else None
    else:
        product = min(candidates, key=lambda s: s["max_servers"])

    if not product:
        return None

    return product, server_count


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
    """
    fw = _select_firewall(env, catalog)
    sw_product, sw_count = _select_switches(env, catalog)
    ap_result = _select_aps(env, catalog)
    sv_result = _select_servers(env, catalog)

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

    sv_signals = [
        f"{env['server_count']} server(s) identified on network",
    ]
    if env["eol_server_count"] > 0:
        sv_signals.append(
            f"{env['eol_server_count']} EOL server(s) — immediate replacement recommended"
        )

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

_NARRATIVE_SECTION_KEYS = ["FIREWALL", "SWITCHING", "WIRELESS", "SERVERS"]


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

    user_msg = (
        "Based on the environment data and recommended products below, write a "
        "2-3 sentence justification for each product category. Use EXACTLY these "
        "section headers with a colon, then the narrative on the next line:\n\n"
        "FIREWALL:\n"
        "SWITCHING:\n"
        "WIRELESS:\n"
        "SERVERS:\n\n"
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

def _static_narratives(env: dict, recommendations: dict) -> dict:
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
            "Contact Yeyland Wutani to schedule a dedicated wireless survey and "
            "receive a tailored access point recommendation."
        )

    if sv:
        sv_product = sv.get("product", {})
        sv_count   = sv.get("count", 1)
        sv_model   = f"{sv_product.get('vendor', 'Dell')} PowerEdge {sv_product.get('model', '')}"
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
            "infrastructure is required in the future, contact Yeyland Wutani "
            "for a current Dell PowerEdge recommendation."
        )

    return {
        "firewall": fw_text,
        "switching": sw_text,
        "wireless": ap_text,
        "servers":  sv_text,
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
        MSRP line
    """
    if not product:
        return y

    vendor   = product.get("vendor", "")
    model    = product.get("model",  "")
    vc       = _hex(VENDOR_COLORS.get(vendor, vendor_color))

    # ── Estimate card height ───────────────────────────────────────────────
    features = product.get("key_features", [])[:4]
    n_specs  = _count_specs(product)
    spec_h   = math.ceil(n_specs / 2) * 18 + 8
    feat_h   = len(features) * 15 + 8
    card_h   = 32 + spec_h + feat_h + 28   # header + specs + features + msrp/padding

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
    sy -= 4
    for feat in features:
        c.setFillColor(vc)
        c.circle(x + 14, sy + 4, 2.5, fill=1, stroke=0)
        c.setFont("Helvetica", 8)
        c.setFillColor(_hex("#222222"))
        _draw_wrapped(c, feat, x + 22, sy, w - 32, size=8, line_h=11)
        sy -= 15

    # ── MSRP ──────────────────────────────────────────────────────────────
    msrp = product.get("msrp_usd", 0)
    if msrp:
        sy -= 4
        c.setFont("Helvetica", 7.5)
        c.setFillColor(_hex("#888888"))
        sub = product.get("subscription_required", "")
        sub_note = f"  + {sub}" if sub else ""
        c.drawString(x + 8, sy, f"Est. MSRP: ${msrp:,} (hardware){sub_note}")

    return y - card_h - 6


def _count_specs(product: dict) -> int:
    """Count how many spec fields are present for grid layout."""
    keys = [
        "stateful_throughput_gbps", "utm_throughput_mbps", "vpn_throughput_mbps",
        "max_devices", "interfaces", "form_factor", "ports", "poe_ports",
        "poe_budget_w", "uplinks", "max_throughput_mbps", "wifi_standard",
        "max_clients", "form_factor", "processor", "max_ram_gb",
    ]
    return sum(1 for k in keys if product.get(k) is not None)


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
    row_h = 17
    for i, (label, value) in enumerate(specs):
        cx  = x + (i % 2) * (col_w + 8)
        cy  = y - (i // 2) * row_h

        # Alternating row shade
        if (i // 2) % 2 == 0:
            c.setFillColor(_hex("#f8f9fa"))
            c.rect(cx - 2, cy - row_h + 3, col_w + 4, row_h, fill=1, stroke=0)

        c.setFont("Helvetica", 7)
        c.setFillColor(_hex("#888888"))
        c.drawString(cx, cy - 4, label.upper())
        c.setFont("Helvetica-Bold", 8.5)
        c.setFillColor(_hex("#111111"))
        # Truncate long values
        disp = value if c.stringWidth(value, "Helvetica-Bold", 8.5) <= col_w - 4 else value[:30] + "..."
        c.drawString(cx, cy - 14, disp)


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
         "Review this report with your Yeyland Wutani sales engineer. We'll walk "
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
         "Yeyland Wutani handles the full deployment: preconfiguration, "
         "on-site installation, user training, and handover documentation. "
         "Most SMB deployments are completed with minimal business disruption."),
        ("5. Ongoing Managed Services",
         "Consider pairing your new infrastructure with Yeyland Wutani managed "
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
                          f"${fw.get('msrp_usd', 0):,}+"))
        sw = recommendations.get("switches", {})
        if sw and sw.get("product"):
            p = sw["product"]
            rows.append(("Switching",
                          f"{sw['count']}x {p.get('vendor','')} {p.get('model','')}",
                          f"${p.get('msrp_usd', 0) * sw['count']:,}+"))
        ap = recommendations.get("access_points") or {}
        if ap and ap.get("product"):
            p = ap["product"]
            rows.append(("Wireless",
                          f"{ap['count']}x {p.get('vendor','')} {p.get('model','')}",
                          f"${p.get('msrp_usd', 0) * ap['count']:,}+"))
        sv = recommendations.get("servers") or {}
        if sv and sv.get("product"):
            p = sv["product"]
            rows.append(("Servers",
                          f"{p.get('vendor','')} {p.get('model','')}",
                          f"${p.get('msrp_usd_base', 0):,}+"))

        col_ws = [90, CONTENT_W - 90 - 80, 80]
        hdr_y  = y
        c.setFillColor(_hex("#343a40"))
        c.rect(MARGIN, hdr_y - 16, CONTENT_W, 16, fill=1, stroke=0)
        for j, (hdr, cw) in enumerate(
                zip(["CATEGORY", "PRODUCT", "EST. HARDWARE"], col_ws)):
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
                c.drawString(cx, y - 12, str(val))
            y -= row_h

        y -= 8
        c.setFont("Helvetica", 7.5)
        c.setFillColor(_hex("#888888"))
        c.drawString(MARGIN, y,
                     "All prices are estimated MSRP hardware costs only. "
                     "Subscriptions, licensing, and professional services are "
                     "quoted separately. Contact Yeyland Wutani for current pricing.")

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
    env     = size_environment(scan_results)
    recs    = select_all_products(env, catalog)

    # ── Narratives (AI or static) ─────────────────────────────────────────
    hatz_key = config.get("hatz_ai", {}).get("api_key", "")
    if hatz_key:
        narratives = get_recommendation_narratives(env, recs, hatz_key)
    else:
        narratives = {}
    if not narratives:
        narratives = _static_narratives(env, recs)

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
