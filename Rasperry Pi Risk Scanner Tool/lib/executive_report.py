#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
executive_report.py - Executive Summary PDF Builder

Generates a non-technical executive summary PDF using ReportLab.
Covers risk score trend, key findings, AI summary, category analysis,
and security posture traffic-light table.
"""

import io
import logging
import math
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ReportLab color constants (defined as tuples for portability)
# Colors are (R,G,B) in 0-1 scale

def _hex_to_rgb(hex_color: str):
    """Convert #RRGGBB to (r,g,b) in 0-1 scale."""
    hex_color = hex_color.lstrip("#")
    r = int(hex_color[0:2], 16) / 255
    g = int(hex_color[2:4], 16) / 255
    b = int(hex_color[4:6], 16) / 255
    return r, g, b

C_CRITICAL = _hex_to_rgb("#dc3545")
C_HIGH     = _hex_to_rgb("#fd7e14")
C_MEDIUM   = _hex_to_rgb("#ffc107")
C_LOW      = _hex_to_rgb("#28a745")
C_WHITE    = (1.0, 1.0, 1.0)
C_BLACK    = (0.0, 0.0, 0.0)
C_DARK     = _hex_to_rgb("#333333")
C_GRAY     = _hex_to_rgb("#666666")
C_LGRAY    = _hex_to_rgb("#f8f9fa")
C_BORDER   = _hex_to_rgb("#dee2e6")

RISK_COLORS = {
    "CRITICAL": C_CRITICAL,
    "HIGH":     C_HIGH,
    "MEDIUM":   C_MEDIUM,
    "LOW":      C_LOW,
}


def _score_to_level(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def generate_executive_pdf(scan_results: dict, config: dict, trend_data: list = None) -> bytes:
    """
    Generate Executive Summary PDF.
    Returns PDF bytes. trend_data is [{date, risk_score, kev_count, ...}].
    """
    try:
        from reportlab.pdfgen import canvas as rl_canvas
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor, Color
    except ImportError:
        logger.error("reportlab not installed — cannot generate PDF")
        return b""

    rep = config.get("reporting", {})
    company_name = rep.get("company_name", "Yeyland Wutani LLC")
    company_color_hex = rep.get("company_color", "#FF6600")
    tagline = rep.get("tagline", "Building Better Systems")
    client_name = rep.get("client_name", "")
    company_color = HexColor(company_color_hex)

    PAGE_W, PAGE_H = letter  # 8.5 x 11 inches
    MARGIN = 0.75 * inch
    CONTENT_W = PAGE_W - 2 * MARGIN

    scan_start = scan_results.get("scan_start", "")
    scan_end = scan_results.get("scan_end", "")
    hosts = scan_results.get("hosts", [])
    risk = scan_results.get("risk", {})
    delta = scan_results.get("delta", {})
    ai_insights = scan_results.get("ai_insights")

    env_score = risk.get("environment_score", 0)
    env_level = _score_to_level(env_score)
    score_color = HexColor({"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#28a745"}.get(env_level,"#28a745"))

    try:
        start_dt = datetime.fromisoformat(scan_start.replace("Z", "+00:00"))
        date_str = start_dt.strftime("%B %d, %Y")
        week_str = f"Week of {start_dt.strftime('%B %d, %Y')}"
    except Exception:
        date_str = datetime.now().strftime("%B %d, %Y")
        week_str = date_str

    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=letter)
    page_num = [0]

    def new_page():
        page_num[0] += 1
        _draw_footer(c, PAGE_W, PAGE_H, MARGIN, company_name, tagline, date_str, page_num[0], company_color)
        c.showPage()

    def _draw_footer(cv, pw, ph, mg, cn, tl, dt, pn, cc):
        cv.saveState()
        cv.setFillColor(HexColor("#f8f8f8"))
        cv.rect(0, 0, pw, 0.4*inch, fill=1, stroke=0)
        cv.setStrokeColor(HexColor("#dee2e6"))
        cv.line(0, 0.4*inch, pw, 0.4*inch)
        cv.setFillColor(HexColor("#888888"))
        cv.setFont("Helvetica", 8)
        cv.drawString(mg, 0.15*inch, f"Powered by Yeyland Wutani Risk Scanner  •  {cn}  •  {tl}  •  CONFIDENTIAL")
        cv.drawRightString(pw - mg, 0.15*inch, f"{dt}  •  Page {pn}")
        cv.restoreState()

    def _draw_brand_header(cv, pw, ph, mg, title, subtitle, cc):
        cv.setFillColor(cc)
        cv.rect(0, ph - 1.2*inch, pw, 1.2*inch, fill=1, stroke=0)
        cv.setFillColor(HexColor("#ffffff"))
        cv.setFont("Helvetica-Bold", 18)
        cv.drawString(mg, ph - 0.5*inch, title)
        cv.setFont("Helvetica", 11)
        cv.drawString(mg, ph - 0.75*inch, subtitle)
        cv.setFont("Helvetica-Oblique", 10)
        cv.drawRightString(pw - mg, ph - 0.55*inch, tagline)

    # ── PAGE 1: Cover ──────────────────────────────────────────────────────
    page_num[0] = 1

    # Header
    c.setFillColor(company_color)
    c.rect(0, PAGE_H - 1.5*inch, PAGE_W, 1.5*inch, fill=1, stroke=0)
    c.setFillColor(HexColor("#ffffff"))
    c.setFont("Helvetica-Bold", 20)
    c.drawString(MARGIN, PAGE_H - 0.65*inch, "Weekly Cyber Risk Assessment")
    c.setFont("Helvetica-Bold", 16)
    c.drawString(MARGIN, PAGE_H - 0.95*inch, "Executive Summary")
    c.setFont("Helvetica-Oblique", 11)
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.75*inch, tagline)

    # Prepared for
    y = PAGE_H - 2.0*inch
    c.setFillColor(HexColor("#333333"))
    c.setFont("Helvetica-Bold", 13)
    c.drawString(MARGIN, y, f"Prepared for: {client_name or 'Client'}")
    c.setFont("Helvetica", 11)
    c.drawString(MARGIN, y - 0.3*inch, week_str)
    c.drawString(MARGIN, y - 0.55*inch, f"Report generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}")

    # Risk Score Gauge (radial dial)
    cx_gauge = PAGE_W / 2
    cy_gauge = PAGE_H / 2 - 0.5*inch
    r_outer = 1.3*inch
    r_inner = 0.85*inch

    # Background arc (gray)
    c.setStrokeColor(HexColor("#e9ecef"))
    c.setLineWidth(2)
    c.arc(
        cx_gauge - r_outer, cy_gauge - r_outer,
        cx_gauge + r_outer, cy_gauge + r_outer,
        startAng=180, extent=-180,
    )

    # Colored arc for score (0=180deg, 100=0deg)
    score_angle = 180 - (env_score / 100.0) * 180
    c.setStrokeColor(score_color)
    c.setLineWidth(20)
    c.arc(
        cx_gauge - r_outer + 10, cy_gauge - r_outer + 10,
        cx_gauge + r_outer - 10, cy_gauge + r_outer - 10,
        startAng=180, extent=-(env_score / 100.0) * 180,
    )

    # Score text
    c.setFillColor(HexColor("#333333"))
    c.setFont("Helvetica-Bold", 48)
    c.drawCentredString(cx_gauge, cy_gauge - 0.2*inch, str(env_score))
    c.setFillColor(score_color)
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(cx_gauge, cy_gauge - 0.55*inch, env_level)
    c.setFillColor(HexColor("#666666"))
    c.setFont("Helvetica", 10)
    c.drawCentredString(cx_gauge, cy_gauge - 0.8*inch, "Environment Risk Score (0-100)")

    # Gauge labels
    c.setFont("Helvetica", 9)
    c.setFillColor(HexColor("#28a745"))
    c.drawString(cx_gauge - r_outer - 0.1*inch, cy_gauge - 0.1*inch, "0")
    c.setFillColor(HexColor("#dc3545"))
    c.drawString(cx_gauge + r_outer - 0.2*inch, cy_gauge - 0.1*inch, "100")

    # Key stats row
    y_stats = cy_gauge - 1.5*inch
    stats = [
        (str(len(hosts)), "Hosts Scanned"),
        (str(sum(len(h.get("cve_matches",[])) for h in hosts)), "CVEs Detected"),
        (str(sum(1 for h in hosts for cv in h.get("cve_matches",[]) if cv.get("kev"))), "CISA KEV Matches"),
        (str(sum(1 for h in hosts if h.get("risk_level") in ("CRITICAL","HIGH"))), "Critical/High Hosts"),
    ]
    stat_w = CONTENT_W / len(stats)
    for i, (val, label) in enumerate(stats):
        x_s = MARGIN + i * stat_w + stat_w / 2
        c.setFillColor(company_color)
        c.setFont("Helvetica-Bold", 22)
        c.drawCentredString(x_s, y_stats, val)
        c.setFillColor(HexColor("#666666"))
        c.setFont("Helvetica", 9)
        c.drawCentredString(x_s, y_stats - 0.25*inch, label)

    _draw_footer(c, PAGE_W, PAGE_H, MARGIN, company_name, tagline, date_str, 1, company_color)
    c.showPage()

    # ── PAGE 2: Risk Score Trend ───────────────────────────────────────────
    page_num[0] = 2
    _draw_brand_header(c, PAGE_W, PAGE_H, MARGIN, "Risk Score Trend", f"Last {len(trend_data or [])} weeks", company_color)

    y = PAGE_H - 1.5*inch - 0.3*inch
    c.setFillColor(HexColor("#333333"))
    c.setFont("Helvetica-Bold", 13)
    c.drawString(MARGIN, y, "Weekly Risk Score History")

    if trend_data:
        chart_h = 2.5*inch
        chart_y = y - chart_h - 0.4*inch
        chart_w = CONTENT_W
        bar_w = max(chart_w / max(len(trend_data), 1) * 0.7, 10)
        bar_spacing = chart_w / max(len(trend_data), 1)

        # Y axis
        c.setStrokeColor(HexColor("#dee2e6"))
        c.setLineWidth(0.5)
        for score_line in (20, 40, 60, 80, 100):
            line_y = chart_y + chart_h * (score_line / 100)
            c.line(MARGIN, line_y, MARGIN + chart_w, line_y)
            c.setFillColor(HexColor("#aaaaaa"))
            c.setFont("Helvetica", 7)
            c.drawString(MARGIN - 0.25*inch, line_y - 3, str(score_line))

        # Bars
        for i, week in enumerate(trend_data):
            score = week.get("risk_score", 0)
            bar_h = chart_h * (score / 100) if score > 0 else 2
            bar_x = MARGIN + i * bar_spacing + (bar_spacing - bar_w) / 2
            bar_y = chart_y

            level = _score_to_level(score)
            bar_color = HexColor({"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#28a745"}.get(level,"#28a745"))
            c.setFillColor(bar_color)
            c.rect(bar_x, bar_y, bar_w, bar_h, fill=1, stroke=0)

            # KEV annotation
            if week.get("kev_count", 0) > 0:
                c.setFillColor(HexColor("#dc3545"))
                c.setFont("Helvetica-Bold", 7)
                c.drawCentredString(bar_x + bar_w/2, bar_y + bar_h + 4, "KEV")

            # Date label
            c.setFillColor(HexColor("#666666"))
            c.setFont("Helvetica", 7)
            date_label = week.get("date", "")[-5:]  # MM-DD
            c.drawCentredString(bar_x + bar_w/2, chart_y - 12, date_label)

        # Trend summary
        if len(trend_data) >= 4:
            recent_4 = [w.get("risk_score", 0) for w in trend_data[-4:]]
            trend_dir = "improving" if recent_4[-1] < recent_4[0] else ("worsening" if recent_4[-1] > recent_4[0] else "stable")
            c.setFillColor(HexColor("#333333"))
            c.setFont("Helvetica-Oblique", 10)
            c.drawString(MARGIN, chart_y - 0.4*inch,
                         f"Trend over last 4 weeks: risk score is {trend_dir}.")
    else:
        c.setFillColor(HexColor("#888888"))
        c.setFont("Helvetica-Oblique", 11)
        c.drawString(MARGIN, y - 0.6*inch, "No trend data available — this is the first scan.")

    _draw_footer(c, PAGE_W, PAGE_H, MARGIN, company_name, tagline, date_str, 2, company_color)
    c.showPage()

    # ── PAGE 3: Key Findings ───────────────────────────────────────────────
    page_num[0] = 3
    _draw_brand_header(c, PAGE_W, PAGE_H, MARGIN, "Key Findings This Week",
                       "Non-technical summary for leadership", company_color)

    y = PAGE_H - 1.5*inch - 0.5*inch
    top_risks = risk.get("top_10_risks", [])[:5]
    new_finding_keys = set()
    if delta.get("has_previous"):
        for ip_findings in delta.get("new_findings", {}).values():
            new_finding_keys.update(ip_findings)

    c.setFillColor(HexColor("#333333"))
    c.setFont("Helvetica-Bold", 13)
    c.drawString(MARGIN, y, "Top Security Findings")
    y -= 0.35*inch

    for i, item in enumerate(top_risks, 1):
        if y < 1.5*inch:
            new_page()
            y = PAGE_H - 1.5*inch - 0.5*inch

        cve_id = item.get("detail", "")
        severity = item.get("severity", "INFO")
        sev_color = HexColor({"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#28a745","INFO":"#17a2b8"}.get(severity,"#6c757d"))
        is_kev = item.get("kev", False)
        is_new = f"CVE:{cve_id}" in new_finding_keys

        # Finding box
        box_h = 0.85*inch
        c.setFillColor(HexColor("#f8f9fa"))
        c.setStrokeColor(sev_color)
        c.setLineWidth(3)
        c.rect(MARGIN, y - box_h, CONTENT_W, box_h, fill=1, stroke=0)
        c.line(MARGIN, y - box_h, MARGIN, y)

        c.setFillColor(sev_color)
        c.rect(MARGIN, y - box_h, 3, box_h, fill=1, stroke=0)

        c.setFillColor(HexColor("#333333"))
        c.setFont("Helvetica-Bold", 11)
        host = item.get("host", "")
        c.drawString(MARGIN + 10, y - 0.25*inch, f"{i}. {cve_id} — {host}")

        if is_kev:
            c.setFillColor(HexColor("#dc3545"))
            c.setFont("Helvetica-Bold", 8)
            kev_x = MARGIN + CONTENT_W - 1.5*inch
            c.rect(kev_x, y - 0.35*inch, 1.3*inch, 0.2*inch, fill=1, stroke=0)
            c.setFillColor(HexColor("#ffffff"))
            c.drawCentredString(kev_x + 0.65*inch, y - 0.27*inch, "ACTIVELY EXPLOITED")

        if is_new:
            c.setFillColor(HexColor("#17a2b8"))
            c.setFont("Helvetica-Bold", 8)
            new_x = MARGIN + CONTENT_W - 3.0*inch
            c.rect(new_x, y - 0.35*inch, 0.9*inch, 0.2*inch, fill=1, stroke=0)
            c.setFillColor(HexColor("#ffffff"))
            c.drawCentredString(new_x + 0.45*inch, y - 0.27*inch, "NEW THIS WEEK")

        c.setFillColor(HexColor("#555555"))
        c.setFont("Helvetica", 9)
        cvss = item.get("score", "")
        cvss_str = f"{cvss:.1f}" if isinstance(cvss, float) else str(cvss)
        c.drawString(MARGIN + 10, y - 0.5*inch, f"Severity: {severity}  |  CVSS: {cvss_str}")

        y -= box_h + 0.15*inch

    # Resolved findings
    if delta.get("has_previous"):
        resolved_count = sum(len(v) for v in delta.get("resolved_findings", {}).values())
        if resolved_count > 0:
            y -= 0.1*inch
            c.setFillColor(HexColor("#28a745"))
            c.rect(MARGIN, y - 0.45*inch, CONTENT_W, 0.4*inch, fill=1, stroke=0)
            c.setFillColor(HexColor("#ffffff"))
            c.setFont("Helvetica-Bold", 11)
            c.drawString(MARGIN + 0.15*inch, y - 0.28*inch,
                         f"  {resolved_count} security finding(s) resolved since last scan")

    _draw_footer(c, PAGE_W, PAGE_H, MARGIN, company_name, tagline, date_str, 3, company_color)
    c.showPage()

    # ── PAGE 4: AI Executive Summary (optional) ────────────────────────────
    if ai_insights:
        page_num[0] = 4
        _draw_brand_header(c, PAGE_W, PAGE_H, MARGIN, "AI Executive Summary",
                           "Generated by Hatz AI  •  Advisory use only", company_color)
        y = PAGE_H - 1.5*inch - 0.4*inch

        sections_map = {
            "## Executive Summary": [],
            "## Critical Actions (This Week)": [],
            "## Risk Trend": [],
            "## Positive Security Controls": [],
        }
        current_section = None
        for line in ai_insights.splitlines():
            line = line.strip()
            if line in sections_map:
                current_section = line
            elif current_section:
                sections_map[current_section].append(line)

        for section_title, lines in sections_map.items():
            if not [l for l in lines if l]:
                continue
            if y < 1.5*inch:
                new_page()
                y = PAGE_H - 1.5*inch - 0.4*inch

            c.setFillColor(company_color)
            c.setFont("Helvetica-Bold", 12)
            c.drawString(MARGIN, y, section_title.lstrip("# "))
            y -= 0.05*inch
            c.setStrokeColor(company_color)
            c.setLineWidth(1)
            c.line(MARGIN, y, MARGIN + CONTENT_W, y)
            y -= 0.2*inch

            for line in lines:
                if not line:
                    y -= 0.1*inch
                    continue
                if y < 1.2*inch:
                    _draw_footer(c, PAGE_W, PAGE_H, MARGIN, company_name, tagline, date_str, page_num[0], company_color)
                    c.showPage()
                    page_num[0] += 1
                    y = PAGE_H - 0.8*inch
                c.setFillColor(HexColor("#333333"))
                c.setFont("Helvetica", 10)
                bullet = ""
                if line.startswith("- ") or line.startswith("* "):
                    bullet = "• "
                    line = line[2:]
                elif line[0].isdigit() and "." in line[:3]:
                    bullet = line[:3]
                    line = line[3:].strip()
                c.drawString(MARGIN + (0.15*inch if bullet else 0), y, bullet + line[:100])
                y -= 0.22*inch

            y -= 0.1*inch

        _draw_footer(c, PAGE_W, PAGE_H, MARGIN, company_name, tagline, date_str, page_num[0], company_color)
        c.showPage()
        page_num[0] += 1

    # ── PAGE 5: Risk by Host Category ─────────────────────────────────────
    _draw_brand_header(c, PAGE_W, PAGE_H, MARGIN, "Risk by Host Category",
                       "Aggregated risk scores by device type", company_color)
    y = PAGE_H - 1.5*inch - 0.5*inch

    # Build category stats
    cat_stats = {}
    for host in hosts:
        cat = host.get("category", "Unknown Device")
        score = host.get("risk_score", 0)
        level = host.get("risk_level", "LOW")
        if cat not in cat_stats:
            cat_stats[cat] = {"count": 0, "scores": [], "max_level": "LOW"}
        cat_stats[cat]["count"] += 1
        cat_stats[cat]["scores"].append(score)
        # Track max risk level
        level_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if level_order.get(level, 0) > level_order.get(cat_stats[cat]["max_level"], 0):
            cat_stats[cat]["max_level"] = level

    sorted_cats = sorted(cat_stats.items(), key=lambda x: max(x[1]["scores"]), reverse=True)

    c.setFillColor(HexColor("#333333"))
    c.setFont("Helvetica-Bold", 11)
    c.drawString(MARGIN, y, "Category")
    c.drawString(MARGIN + 2.5*inch, y, "Hosts")
    c.drawString(MARGIN + 3.0*inch, y, "Avg Score")
    c.drawString(MARGIN + 4.5*inch, y, "Max Risk")
    c.drawString(MARGIN + 5.5*inch, y, "Risk Bar")
    y -= 0.3*inch

    for cat, stats in sorted_cats[:15]:
        if y < 1.2*inch:
            break
        avg_score = int(sum(stats["scores"]) / max(len(stats["scores"]), 1))
        max_level = stats["max_level"]
        bar_color = HexColor({"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#28a745"}.get(max_level,"#28a745"))

        c.setFillColor(HexColor("#333333"))
        c.setFont("Helvetica", 10)
        cat_label = cat[:30]
        c.drawString(MARGIN, y, cat_label)
        c.drawString(MARGIN + 2.5*inch, y, str(stats["count"]))
        c.drawString(MARGIN + 3.0*inch, y, str(avg_score))

        c.setFillColor(HexColor({"CRITICAL":"#dc3545","HIGH":"#fd7e14","MEDIUM":"#ffc107","LOW":"#28a745"}.get(max_level,"#28a745")))
        c.setFont("Helvetica-Bold", 9)
        c.drawString(MARGIN + 4.5*inch, y, max_level)

        # Bar
        bar_max_w = 1.5*inch
        bar_w_actual = bar_max_w * (avg_score / 100)
        c.setFillColor(bar_color)
        c.rect(MARGIN + 5.5*inch, y - 0.02*inch, bar_w_actual, 0.14*inch, fill=1, stroke=0)

        y -= 0.28*inch

    _draw_footer(c, PAGE_W, PAGE_H, MARGIN, company_name, tagline, date_str, page_num[0], company_color)
    c.showPage()
    page_num[0] += 1

    # ── PAGE 6: Security Posture Summary ──────────────────────────────────
    _draw_brand_header(c, PAGE_W, PAGE_H, MARGIN, "Security Posture Summary",
                       "Traffic-light assessment across 10 control areas", company_color)
    y = PAGE_H - 1.5*inch - 0.5*inch

    posture = _assess_posture(hosts, scan_results)

    c.setFillColor(HexColor("#333333"))
    c.setFont("Helvetica-Bold", 11)
    c.drawString(MARGIN, y, "Control Area")
    c.drawString(MARGIN + 3.5*inch, y, "Status")
    c.drawString(MARGIN + 4.5*inch, y, "Notes")
    y -= 0.1*inch
    c.setStrokeColor(HexColor("#dee2e6"))
    c.line(MARGIN, y, MARGIN + CONTENT_W, y)
    y -= 0.3*inch

    status_colors = {"GREEN": "#28a745", "AMBER": "#fd7e14", "RED": "#dc3545"}

    for area, status, notes in posture:
        if y < 1.2*inch:
            break
        c.setFillColor(HexColor("#333333"))
        c.setFont("Helvetica", 10)
        c.drawString(MARGIN, y, area)

        sc = HexColor(status_colors.get(status, "#6c757d"))
        c.setFillColor(sc)
        c.roundRect(MARGIN + 3.5*inch, y - 0.05*inch, 0.7*inch, 0.18*inch, 3, fill=1, stroke=0)
        c.setFillColor(HexColor("#ffffff"))
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(MARGIN + 3.85*inch, y + 0.02*inch, status)

        c.setFillColor(HexColor("#555555"))
        c.setFont("Helvetica", 8)
        c.drawString(MARGIN + 4.5*inch, y, notes[:60])

        y -= 0.32*inch

    _draw_footer(c, PAGE_W, PAGE_H, MARGIN, company_name, tagline, date_str, page_num[0], company_color)
    c.showPage()

    c.save()
    return buf.getvalue()


def _assess_posture(hosts: list, scan_results: dict) -> list:
    """
    Derive traffic-light (GREEN/AMBER/RED) status for 10 control areas.
    Returns list of (area_name, status, notes) tuples.
    """
    posture = []

    # 1. Patch Management
    stale_hosts = [h for h in hosts if (h.get("patch_status") or {}).get("days_since_update", 0) and
                   h.get("patch_status", {}).get("days_since_update", 0) > 90]
    if not stale_hosts:
        posture.append(("Patch Management", "GREEN", "No hosts with patches > 90 days old"))
    elif len(stale_hosts) <= 2:
        posture.append(("Patch Management", "AMBER", f"{len(stale_hosts)} host(s) with stale patches"))
    else:
        posture.append(("Patch Management", "RED", f"{len(stale_hosts)} hosts with patches > 90 days old"))

    # 2. Authentication
    default_cred = any(
        any(f.get("type","") == "default_credentials" for f in h.get("security_flags",[]))
        for h in hosts
    )
    rdp_exposed = any(3389 in h.get("open_ports",[]) for h in hosts)
    if default_cred:
        posture.append(("Authentication", "RED", "Default credentials confirmed on at least one host"))
    elif rdp_exposed:
        posture.append(("Authentication", "AMBER", "RDP exposed — verify MFA/NLA is enforced"))
    else:
        posture.append(("Authentication", "GREEN", "No default credentials or exposed RDP detected"))

    # 3. Firewall
    fw_disabled = any(
        any("disabled" in str(v).lower() for v in h.get("windows_firewall",{}).values())
        for h in hosts
    )
    if fw_disabled:
        posture.append(("Firewall", "RED", "Windows Firewall disabled on one or more hosts"))
    else:
        posture.append(("Firewall", "GREEN", "No disabled firewall profiles detected"))

    # 4. Antivirus / EDR
    av_missing = [h for h in hosts if h.get("antivirus", {}).get("status") in ("missing", "stale")]
    if not av_missing:
        posture.append(("Antivirus / EDR", "GREEN", "AV/EDR coverage looks current"))
    elif len(av_missing) <= 2:
        posture.append(("Antivirus / EDR", "AMBER", f"{len(av_missing)} host(s) with missing or stale AV"))
    else:
        posture.append(("Antivirus / EDR", "RED", f"{len(av_missing)} hosts with AV missing or stale"))

    # 5. Backup & DR (inferred from NAS presence)
    has_nas = any(h.get("category") in ("NAS / Storage",) for h in hosts)
    posture.append(("Backup & DR", "AMBER" if not has_nas else "GREEN",
                    "NAS detected" if has_nas else "No NAS/backup device detected on network"))

    # 6. Encryption (TLS)
    ssl_expired = sum(1 for h in hosts for i in h.get("ssl_issues",[]) if "expired" in i.get("type","").lower())
    telnet_open = sum(1 for h in hosts if 23 in h.get("open_ports",[]))
    if ssl_expired > 0 or telnet_open > 0:
        posture.append(("Encryption", "RED", f"{ssl_expired} expired certs, {telnet_open} Telnet hosts"))
    else:
        posture.append(("Encryption", "GREEN", "No expired certificates or Telnet services detected"))

    # 7. Remote Access
    telnet_count = sum(1 for h in hosts if 23 in h.get("open_ports",[]))
    rdp_count = sum(1 for h in hosts if 3389 in h.get("open_ports",[]))
    if telnet_count > 0:
        posture.append(("Remote Access", "RED", f"{telnet_count} host(s) with Telnet open"))
    elif rdp_count > 3:
        posture.append(("Remote Access", "AMBER", f"{rdp_count} hosts with RDP exposed — verify access controls"))
    else:
        posture.append(("Remote Access", "GREEN", "No Telnet detected; RDP exposure appears limited"))

    # 8. Network Segmentation (infer from subnet count)
    subnets = scan_results.get("summary", {}).get("subnets_scanned", [])
    if len(subnets) >= 2:
        posture.append(("Network Segmentation", "GREEN", f"{len(subnets)} subnets detected — segmentation appears in place"))
    else:
        posture.append(("Network Segmentation", "AMBER", "Only 1 subnet detected — review VLAN/segmentation strategy"))

    # 9. Email Security (inferred from DNS — not directly scannable via LAN)
    posture.append(("Email Security", "AMBER", "SPF/DKIM/DMARC assessment requires DNS inspection (not LAN-scannable)"))

    # 10. EOL Devices
    eol_hosts = [h for h in hosts if
                 any(f.get("type","").lower() == "eol" or "end-of-life" in f.get("description","").lower()
                     for f in h.get("security_flags",[]))]
    if not eol_hosts:
        posture.append(("EOL Devices", "GREEN", "No end-of-life devices detected"))
    elif len(eol_hosts) <= 2:
        posture.append(("EOL Devices", "AMBER", f"{len(eol_hosts)} potential EOL device(s) detected"))
    else:
        posture.append(("EOL Devices", "RED", f"{len(eol_hosts)} end-of-life devices require attention"))

    return posture
