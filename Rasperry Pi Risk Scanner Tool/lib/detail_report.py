#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Pi
detail_report.py - Technical Detail PDF Builder (ReportLab)

Generates a comprehensive multi-page technical PDF for IT staff:
  Page 1  : Cover
  Page 2  : Scan Coverage & Methodology
  Page 3  : Environment Risk Summary
  Pages 4+: Per-host finding pages (CRITICAL & HIGH)
  Grouped : MEDIUM host summary page(s)
  App A   : Full Host Inventory
  App B   : All CVEs Detected
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── ReportLab colour helpers ──────────────────────────────────────────────

def _hex_to_rl(hex_color: str):
    """Convert #RRGGBB hex string to a reportlab Color object."""
    from reportlab.lib.colors import Color
    hex_color = hex_color.lstrip("#")
    r = int(hex_color[0:2], 16) / 255.0
    g = int(hex_color[2:4], 16) / 255.0
    b = int(hex_color[4:6], 16) / 255.0
    return Color(r, g, b)


def _score_to_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


_LEVEL_HEX = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#28a745",
}

_SEV_HEX = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#e6a817",
    "LOW":      "#6c757d",
    "INFO":     "#17a2b8",
}


# ── Public entry point ────────────────────────────────────────────────────

def build_detail_pdf(scan_results: dict, config: dict, output_path: str) -> str:
    """
    Build the Technical Detail PDF and write it to output_path.
    Returns output_path on success.

    scan_results keys (expected):
        hosts, risk, delta, credential_coverage, summary,
        vuln_db_stats, scan_start, scan_end, excluded_hosts,
        phases_completed, phases_skipped, trend_data
    config keys (expected):
        reporting.company_name, reporting.tagline,
        reporting.company_color, reporting.client_name,
        reporting.scanner_version
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.pdfgen import canvas as rl_canvas
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph,
            Spacer, PageBreak, KeepTogether,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError as exc:
        logger.error(f"reportlab not installed — cannot generate detail PDF: {exc}")
        return output_path

    rep = config.get("reporting", {})
    company_name      = rep.get("company_name",   "Yeyland Wutani LLC")
    tagline           = rep.get("tagline",         "Building Better Systems")
    client_name       = rep.get("client_name",     "")
    company_color_hex = rep.get("company_color",   "#FF6600")
    scanner_version   = rep.get("scanner_version", "1.0")

    brand_color = _hex_to_rl(company_color_hex)

    PAGE_W, PAGE_H = A4
    MARGIN_L = 1.8 * cm
    MARGIN_R = 1.8 * cm
    MARGIN_T = 2.2 * cm
    MARGIN_B = 1.8 * cm
    CONTENT_W = PAGE_W - MARGIN_L - MARGIN_R

    hosts                = scan_results.get("hosts", [])
    risk                 = scan_results.get("risk", {})
    delta                = scan_results.get("delta", {})
    credential_coverage  = scan_results.get("credential_coverage", {})
    summary              = scan_results.get("summary", {})
    vuln_db_stats        = scan_results.get("vuln_db_stats", {})
    scan_start           = scan_results.get("scan_start", "")
    scan_end             = scan_results.get("scan_end", "")
    excluded_hosts       = scan_results.get("excluded_hosts", [])
    phases_completed     = scan_results.get("phases_completed", [])
    phases_skipped       = scan_results.get("phases_skipped", [])

    # Date / duration
    try:
        start_dt   = datetime.fromisoformat(scan_start.replace("Z", "+00:00"))
        end_dt     = datetime.fromisoformat(scan_end.replace("Z", "+00:00"))
        date_str   = start_dt.strftime("%B %d, %Y")
        start_str  = start_dt.strftime("%Y-%m-%d %H:%M UTC")
        end_str    = end_dt.strftime("%Y-%m-%d %H:%M UTC")
        dur_sec    = int((end_dt - start_dt).total_seconds())
        dur_str    = f"{dur_sec // 3600}h {(dur_sec % 3600) // 60}m {dur_sec % 60}s"
    except Exception:
        date_str  = datetime.now().strftime("%B %d, %Y")
        start_str = end_str = "N/A"
        dur_str   = "N/A"

    generated_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Mutable page counter shared across callbacks
    _page_state = {"num": 0, "total": 0}

    # ── Canvas callbacks for headers / footers ────────────────────────────

    def _on_first_page(cv, doc):
        _draw_page(cv, doc, is_first=True)

    def _on_later_pages(cv, doc):
        _draw_page(cv, doc, is_first=False)

    def _draw_page(cv, doc, is_first: bool):
        """Draw footer (and optional section header) on every page."""
        cv.saveState()
        # Footer band
        from reportlab.lib.colors import HexColor
        cv.setFillColor(HexColor("#f8f8f8"))
        cv.rect(0, 0, PAGE_W, 1.0 * cm, fill=1, stroke=0)
        cv.setStrokeColor(HexColor("#dee2e6"))
        cv.line(0, 1.0 * cm, PAGE_W, 1.0 * cm)
        cv.setFillColor(HexColor("#888888"))
        cv.setFont("Helvetica", 7.5)
        footer_text = (
            f"{company_name}  |  CONFIDENTIAL  |  {date_str}  |  "
            f"Page {doc.page}"
        )
        cv.drawCentredString(PAGE_W / 2, 0.35 * cm, footer_text)
        cv.restoreState()

    # ── Build story ───────────────────────────────────────────────────────

    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph,
        Spacer, PageBreak, KeepTogether, HRFlowable,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    from reportlab.lib.colors import HexColor, white, black

    styles = getSampleStyleSheet()

    # Custom paragraph styles
    def _style(name, parent="Normal", **kwargs):
        return ParagraphStyle(name, parent=styles[parent], **kwargs)

    h1 = _style("H1", fontSize=20, fontName="Helvetica-Bold",
                leading=24, spaceAfter=6, textColor=HexColor("#ffffff"))
    h2 = _style("H2", fontSize=14, fontName="Helvetica-Bold",
                leading=18, spaceAfter=4, textColor=HexColor("#ffffff"))
    body = _style("Body", fontSize=9, leading=13, textColor=HexColor("#333333"))
    label_s = _style("Label", fontSize=9, fontName="Helvetica-Bold",
                     textColor=HexColor("#555555"))
    small = _style("Small", fontSize=8, leading=11, textColor=HexColor("#666666"))
    section_title = _style("SectionTitle", fontSize=13, fontName="Helvetica-Bold",
                           textColor=brand_color, spaceBefore=12, spaceAfter=4)
    mono = _style("Mono", fontSize=8, fontName="Courier",
                  leading=11, textColor=HexColor("#333333"))
    narrative_style = _style("Narrative", fontSize=9, leading=13,
                             textColor=HexColor("#444444"),
                             backColor=HexColor("#f5f5f5"),
                             borderPadding=(4, 6, 4, 6))

    story = []

    # ══════════════════════════════════════════════════════════════════════
    # PAGE 1: COVER
    # ══════════════════════════════════════════════════════════════════════

    env_score    = risk.get("environment_score", 0)
    env_level    = _score_to_level(env_score)
    total_hosts  = len(hosts)
    total_cves   = sum(len(h.get("cve_matches", [])) for h in hosts)
    kev_count    = sum(
        1 for h in hosts
        for cv in h.get("cve_matches", []) if cv.get("kev")
    )

    # Brand header bar (simulated via a table with coloured background)
    cover_header_data = [[
        Paragraph(
            f"<font color='white'><b>{company_name}</b>   {tagline}</font>",
            _style("CoverHdr", fontSize=11, fontName="Helvetica-Bold",
                   textColor=white, leading=14)
        )
    ]]
    cover_header_tbl = Table(cover_header_data, colWidths=[CONTENT_W])
    cover_header_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), brand_color),
        ("TOPPADDING",    (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
    ]))
    story.append(cover_header_tbl)
    story.append(Spacer(1, 0.6 * cm))

    # Title block
    story.append(Paragraph(
        "<font color='#333333'><b>Weekly Cyber Risk Assessment</b></font>",
        _style("CoverTitle", fontSize=24, fontName="Helvetica-Bold",
               textColor=HexColor("#333333"), leading=28, spaceAfter=4)
    ))
    story.append(Paragraph(
        "<font color='#555555'>Technical Detail Report</font>",
        _style("CoverSub", fontSize=16, fontName="Helvetica",
               textColor=HexColor("#555555"), leading=20, spaceAfter=8)
    ))
    story.append(HRFlowable(width=CONTENT_W, thickness=2,
                            color=brand_color, spaceAfter=10))

    story.append(Paragraph(
        f"<b>Prepared for:</b>  {client_name or 'Client'}",
        _style("CoverFor", fontSize=12, textColor=HexColor("#333333"),
               spaceAfter=4)
    ))
    story.append(Paragraph(
        f"<b>Scan period:</b>  {date_str}",
        _style("CoverDate", fontSize=10, textColor=HexColor("#555555"),
               spaceAfter=2)
    ))
    story.append(Paragraph(
        f"<b>Generated:</b>  {generated_str}",
        _style("CoverGen", fontSize=10, textColor=HexColor("#555555"),
               spaceAfter=14)
    ))

    # Quick-stats table
    def _stat_cell(val, label, hex_c):
        return [
            Paragraph(f"<font color='{hex_c}'><b>{val}</b></font>",
                      _style(f"Stat_{label}", fontSize=28, fontName="Helvetica-Bold",
                             leading=32, textColor=HexColor(hex_c),
                             alignment=TA_CENTER)),
            Paragraph(f"<font color='#666666'>{label}</font>",
                      _style(f"StatL_{label}", fontSize=9,
                             textColor=HexColor("#666666"),
                             alignment=TA_CENTER)),
        ]

    stat_col_w = CONTENT_W / 4
    stats_data = [[
        _stat_cell(str(env_score), "Risk Score",   _LEVEL_HEX.get(env_level, "#28a745")),
        _stat_cell(str(total_hosts), "Hosts",      "#17a2b8"),
        _stat_cell(str(total_cves),  "CVEs",       "#dc3545"),
        _stat_cell(str(kev_count),   "KEV Matches","#dc3545"),
    ]]
    # Flatten: each cell is a list of 2 Paragraphs — put them in rows
    row1 = [_stat_cell(str(env_score), "Risk Score", _LEVEL_HEX.get(env_level, "#28a745")),
            _stat_cell(str(total_hosts), "Hosts",    "#17a2b8"),
            _stat_cell(str(total_cves),  "CVEs",     "#dc3545"),
            _stat_cell(str(kev_count),   "KEV Matches", "#dc3545")]
    stats_row1 = [[cell[0] for cell in row1]]
    stats_row2 = [[cell[1] for cell in row1]]
    stats_combined = stats_row1[0] + stats_row2[0]  # not used directly

    stat_tbl_data = [
        [cell[0] for cell in row1],
        [cell[1] for cell in row1],
    ]
    stat_tbl = Table(stat_tbl_data, colWidths=[stat_col_w] * 4)
    stat_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#f8f9fa")),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#dee2e6")),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, HexColor("#dee2e6")),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, 0),  12),
        ("BOTTOMPADDING", (0, 1), (-1, 1),  12),
    ]))
    story.append(stat_tbl)
    story.append(Spacer(1, 0.8 * cm))

    # Confidentiality notice
    conf_data = [[Paragraph(
        "<font color='#721c24'><b>CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY</b><br/>"
        "This report contains sensitive security information. Do not distribute without "
        "authorization from the named client organization. Retain securely and destroy "
        "when no longer required.</font>",
        _style("Conf", fontSize=8.5, textColor=HexColor("#721c24"),
               leading=13, alignment=TA_CENTER)
    )]]
    conf_tbl = Table(conf_data, colWidths=[CONTENT_W])
    conf_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#f8d7da")),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#f5c6cb")),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    story.append(conf_tbl)
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # PAGE 2: SCAN COVERAGE & METHODOLOGY
    # ══════════════════════════════════════════════════════════════════════

    story.append(Paragraph("Scan Coverage & Methodology", section_title))
    story.append(HRFlowable(width=CONTENT_W, thickness=1,
                            color=brand_color, spaceAfter=8))

    # Scan metadata table
    subnets = summary.get("subnets_scanned", [])
    subnet_labels = summary.get("subnet_labels", {})
    subnet_display = []
    for sn in subnets:
        label = subnet_labels.get(sn, "")
        subnet_display.append(f"{sn}  {('— ' + label) if label else ''}")
    subnets_str = "\n".join(subnet_display) if subnet_display else "N/A"

    nvd_last = str(vuln_db_stats.get("nvd_last_updated", "N/A"))[:19]
    nvd_cve_count = vuln_db_stats.get("nvd_cve_count", "N/A")
    kev_catalog_count = vuln_db_stats.get("kev_cve_count", "N/A")

    # Stale flag: NVD last_updated > 3 days
    nvd_stale = False
    try:
        from datetime import timezone
        nvd_dt = datetime.fromisoformat(
            str(vuln_db_stats.get("nvd_last_updated", "")).replace("Z", "+00:00")
        )
        if (datetime.now(timezone.utc) - nvd_dt).days > 3:
            nvd_stale = True
    except Exception:
        pass

    stale_marker = "  <font color='#dc3545'>[STALE]</font>" if nvd_stale else ""

    meta_rows = [
        [Paragraph("<b>Scan Metadata</b>", label_s), ""],
        ["Start Time",       start_str],
        ["End Time",         end_str],
        ["Duration",         dur_str],
        ["Scanner Version",  scanner_version],
        ["", ""],
        [Paragraph("<b>Target Coverage</b>", label_s), ""],
        ["Subnets Scanned",  subnets_str or "N/A"],
        ["Total Hosts",      str(total_hosts)],
        ["Hosts Excluded",   str(len(excluded_hosts))],
        ["Phases Completed", ", ".join(phases_completed) or "All"],
        ["Phases Skipped",   ", ".join(phases_skipped) or "None"],
    ]

    meta_tbl = Table(
        [[Paragraph(str(r[0]), small) if isinstance(r[0], str) else r[0],
          Paragraph(str(r[1]), body)  if isinstance(r[1], str) else r[1]]
         for r in meta_rows],
        colWidths=[5 * cm, CONTENT_W - 5 * cm],
    )
    meta_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.25, HexColor("#eeeeee")),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.4 * cm))

    # Credential coverage table
    story.append(Paragraph("Credential Coverage", section_title))
    ssh_attempted = len(credential_coverage.get("ssh_attempted", []))
    ssh_success   = len(credential_coverage.get("ssh_success",   []))
    ssh_failed    = ssh_attempted - ssh_success
    wmi_attempted = len(credential_coverage.get("wmi_attempted", []))
    wmi_success   = len(credential_coverage.get("wmi_success",   []))
    wmi_failed    = wmi_attempted - wmi_success
    snmp_attempted= len(credential_coverage.get("snmp_attempted",   []))
    snmp_success  = len(credential_coverage.get("snmp_success",     []))
    snmp_failed   = snmp_attempted - snmp_success

    def _pct(num, den):
        return f"{int(num / den * 100)}%" if den else "N/A"

    cred_header = [
        Paragraph("<b>Protocol</b>",          label_s),
        Paragraph("<b>Hosts Attempted</b>",   label_s),
        Paragraph("<b>Success</b>",           label_s),
        Paragraph("<b>Failed</b>",            label_s),
        Paragraph("<b>Coverage %</b>",        label_s),
    ]
    cred_rows = [
        cred_header,
        ["SSH",       str(ssh_attempted),  str(ssh_success),  str(ssh_failed),  _pct(ssh_success,  ssh_attempted)],
        ["WMI/WinRM", str(wmi_attempted),  str(wmi_success),  str(wmi_failed),  _pct(wmi_success,  wmi_attempted)],
        ["SNMP",      str(snmp_attempted), str(snmp_success), str(snmp_failed), _pct(snmp_success, snmp_attempted)],
    ]
    cred_col_w = CONTENT_W / 5
    cred_tbl = Table(cred_rows, colWidths=[cred_col_w] * 5)
    cred_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  brand_color),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  white),
        ("BACKGROUND",    (0, 1), (-1, -1), HexColor("#f8f9fa")),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [HexColor("#f8f9fa"), white]),
        ("GRID",          (0, 0), (-1, -1), 0.4, HexColor("#dee2e6")),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(cred_tbl)
    story.append(Spacer(1, 0.3 * cm))

    # CVE database status
    story.append(Paragraph("Vulnerability Database Status", section_title))
    nvd_label = Paragraph(
        f"NVD Last Updated:  {nvd_last}{stale_marker}",
        _style("NVDLabel", fontSize=9, textColor=HexColor("#333333"))
    )
    db_rows = [
        ["NVD CVE Count",    str(nvd_cve_count)],
        ["CISA KEV Count",   str(kev_catalog_count)],
        ["NVD Last Updated", Paragraph(f"{nvd_last}{stale_marker}", body)],
        ["OSV Entry Count",  str(vuln_db_stats.get("osv_entry_count", "N/A"))],
    ]
    db_tbl = Table(
        [[Paragraph(str(r[0]), small),
          r[1] if not isinstance(r[1], str) else Paragraph(str(r[1]), body)]
         for r in db_rows],
        colWidths=[5 * cm, CONTENT_W - 5 * cm],
    )
    db_tbl.setStyle(TableStyle([
        ("LINEBELOW",     (0, 0), (-1, -1), 0.25, HexColor("#eeeeee")),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
    ]))
    story.append(db_tbl)
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # PAGE 3: ENVIRONMENT RISK SUMMARY
    # ══════════════════════════════════════════════════════════════════════

    story.append(Paragraph("Environment Risk Summary", section_title))
    story.append(HRFlowable(width=CONTENT_W, thickness=1,
                            color=brand_color, spaceAfter=8))

    # Large risk score box
    score_color_hex = _LEVEL_HEX.get(env_level, "#28a745")
    score_box_data = [[
        Paragraph(
            f"<font color='white'><b>{env_score}</b></font>",
            _style("ScoreVal", fontSize=36, fontName="Helvetica-Bold",
                   textColor=white, alignment=TA_CENTER)
        ),
        Paragraph(
            f"<font color='white'><b>{env_level}</b><br/>Environment Risk Score</font>",
            _style("ScoreLbl", fontSize=13, fontName="Helvetica-Bold",
                   textColor=white, leading=18, alignment=TA_LEFT)
        ),
    ]]
    score_tbl = Table(score_box_data, colWidths=[3 * cm, CONTENT_W - 3 * cm])
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor(score_color_hex)),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 14),
        ("ALIGN",         (0, 0), (0, 0),   "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # Risk level breakdown with bar
    story.append(Paragraph("Host Risk Level Distribution", section_title))
    level_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for h in hosts:
        lv = h.get("risk_level", _score_to_level(h.get("risk_score", 0)))
        level_counts[lv] = level_counts.get(lv, 0) + 1

    bar_max_w = CONTENT_W - 5 * cm
    level_rows = []
    for lv in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        cnt = level_counts.get(lv, 0)
        bar_pct = cnt / max(total_hosts, 1)
        bar_w = max(bar_pct * bar_max_w, 0.1 * cm)
        bar_cell = Table(
            [[Paragraph("", body)]],
            colWidths=[bar_w],
        )
        bar_cell.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), HexColor(_LEVEL_HEX[lv])),
            ("TOPPADDING",    (0, 0), (0, 0), 4),
            ("BOTTOMPADDING", (0, 0), (0, 0), 4),
        ]))
        level_rows.append([
            Paragraph(f"<b>{lv}</b>", _style(f"LV_{lv}", fontSize=9,
                      fontName="Helvetica-Bold",
                      textColor=HexColor(_LEVEL_HEX[lv]))),
            bar_cell,
            Paragraph(str(cnt), body),
        ])
    bar_tbl = Table(level_rows,
                    colWidths=[2.5 * cm, bar_max_w, 1.5 * cm])
    bar_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(bar_tbl)
    story.append(Spacer(1, 0.3 * cm))

    # Total CVEs by severity
    story.append(Paragraph("CVE Count by Severity", section_title))
    all_unique_cves: dict = {}
    for h in hosts:
        for cve in h.get("cve_matches", []):
            cid = cve.get("cve_id", "")
            if cid and cid not in all_unique_cves:
                all_unique_cves[cid] = cve

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for cve in all_unique_cves.values():
        sev = cve.get("severity", "INFO")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    sev_hdr = [Paragraph(f"<b>{s}</b>", label_s)
               for s in ("Severity", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "Total")]
    sev_vals = [
        "Count",
        str(sev_counts.get("CRITICAL", 0)),
        str(sev_counts.get("HIGH",     0)),
        str(sev_counts.get("MEDIUM",   0)),
        str(sev_counts.get("LOW",      0)),
        str(sev_counts.get("INFO",     0)),
        str(len(all_unique_cves)),
    ]
    sev_tbl = Table([sev_hdr, sev_vals],
                    colWidths=[CONTENT_W / 7] * 7)
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), brand_color),
        ("TEXTCOLOR",     (0, 0), (-1, 0), white),
        ("BACKGROUND",    (1, 1), (1, 1),  HexColor("#dc3545")),
        ("BACKGROUND",    (2, 1), (2, 1),  HexColor("#fd7e14")),
        ("BACKGROUND",    (3, 1), (3, 1),  HexColor("#ffc107")),
        ("TEXTCOLOR",     (1, 1), (3, 1),  white),
        ("GRID",          (0, 0), (-1, -1), 0.4, HexColor("#dee2e6")),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sev_tbl)
    story.append(Spacer(1, 0.3 * cm))

    # CISA KEV Matches table
    kev_matches = []
    for h in hosts:
        for cve in h.get("cve_matches", []):
            if cve.get("kev"):
                kev_matches.append({
                    "cve_id":          cve.get("cve_id", ""),
                    "host_ip":         h.get("ip", ""),
                    "hostname":        h.get("hostname", ""),
                    "product":         cve.get("product", ""),
                    "required_action": cve.get("kev_required_action",
                                               cve.get("required_action", "")),
                    "due_date":        cve.get("kev_due_date", ""),
                })

    if kev_matches:
        story.append(Paragraph(
            f"CISA Known Exploited Vulnerabilities — {len(kev_matches)} Match(es)",
            section_title,
        ))
        kev_hdr = [Paragraph(f"<b>{s}</b>", label_s)
                   for s in ("CVE ID", "Affected Host", "Product",
                             "Required Action", "Due Date")]
        kev_rows = [kev_hdr]
        for km in kev_matches[:40]:
            host_display = km["hostname"] or km["host_ip"]
            kev_rows.append([
                Paragraph(km["cve_id"],                       small),
                Paragraph(host_display[:22],                  small),
                Paragraph(km["product"][:22],                 small),
                Paragraph(km["required_action"][:60],         small),
                Paragraph(km["due_date"][:10],                small),
            ])
        kev_col_w = [2.8*cm, 3.5*cm, 3.5*cm, 5.2*cm, 2.0*cm]
        kev_tbl = Table(kev_rows, colWidths=kev_col_w)
        kev_style = [
            ("BACKGROUND",    (0, 0), (-1, 0), HexColor("#dc3545")),
            ("TEXTCOLOR",     (0, 0), (-1, 0), white),
            ("GRID",          (0, 0), (-1, -1), 0.4, HexColor("#f5c6cb")),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]
        # Red background for data rows
        for row_idx in range(1, len(kev_rows)):
            bg = HexColor("#fff0f0") if row_idx % 2 == 1 else HexColor("#ffe8e8")
            kev_style.append(("BACKGROUND", (0, row_idx), (-1, row_idx), bg))
        kev_tbl.setStyle(TableStyle(kev_style))
        story.append(kev_tbl)
        story.append(Spacer(1, 0.3 * cm))

    # Delta summary box
    if delta.get("has_previous"):
        new_f_count = sum(len(v) for v in delta.get("new_findings", {}).values())
        resolved_count = sum(len(v) for v in delta.get("resolved_findings", {}).values())
        recurring_count = sum(len(v) for v in delta.get("recurring_findings", {}).values())
        new_kev_count = len(delta.get("new_kev_cves", []))
        risk_delta = delta.get("risk_score_delta", 0)
        delta_color = HexColor("#dc3545") if risk_delta > 0 else HexColor("#28a745")
        delta_arrow = "▲" if risk_delta > 0 else ("▼" if risk_delta < 0 else "—")

        delta_text = (
            f"<b>Δ vs. Previous Scan:</b>  "
            f"<font color='#dc3545'>{new_f_count} new findings</font>  |  "
            f"<font color='#28a745'>{resolved_count} resolved</font>  |  "
            f"{recurring_count} recurring  |  "
            f"<font color='#dc3545'>{new_kev_count} new KEV CVEs</font>  |  "
            f"Risk score: {delta_arrow}{abs(risk_delta)}"
        )
        delta_data = [[Paragraph(delta_text,
                                 _style("DeltaP", fontSize=9, leading=13,
                                        textColor=HexColor("#333333")))]]
        delta_tbl = Table(delta_data, colWidths=[CONTENT_W])
        delta_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#fff8e1")),
            ("BOX",           (0, 0), (-1, -1), 0.75, HexColor("#ffc107")),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ]))
        story.append(delta_tbl)

    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # PAGES 4+: PER-HOST FINDING PAGES (CRITICAL & HIGH)
    # ══════════════════════════════════════════════════════════════════════

    crit_high_hosts = [
        h for h in hosts
        if h.get("risk_level", _score_to_level(h.get("risk_score", 0)))
        in ("CRITICAL", "HIGH")
    ]

    for host in crit_high_hosts:
        ip       = host.get("ip", "?")
        hostname = host.get("hostname") or ip
        category = host.get("category", "Unknown Device")
        os_v     = host.get("os_version") or host.get("os_guess") or "Unknown"
        score    = host.get("risk_score", 0)
        level    = host.get("risk_level", _score_to_level(score))
        lc_hex   = _LEVEL_HEX.get(level, "#6c757d")

        # Host header bar
        header_data = [[
            Paragraph(
                f"<font color='white'><b>{hostname}</b></font>",
                _style(f"HH_{ip}", fontSize=14, fontName="Helvetica-Bold",
                       textColor=white, leading=18)
            ),
            Paragraph(
                f"<font color='white'>{ip}  |  {category}  |  {os_v[:35]}  |  "
                f"Score: {score}  |  {level}</font>",
                _style(f"HS_{ip}", fontSize=9, textColor=white,
                       leading=12, alignment=TA_RIGHT)
            ),
        ]]
        host_hdr_tbl = Table(header_data,
                             colWidths=[CONTENT_W * 0.45, CONTENT_W * 0.55])
        host_hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), HexColor(lc_hex)),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(host_hdr_tbl)
        story.append(Spacer(1, 0.3 * cm))

        # CVE Table
        cve_matches = host.get("cve_matches", [])
        if cve_matches:
            story.append(Paragraph("Vulnerabilities (CVE Matches)", section_title))
            cve_hdr = [Paragraph(f"<b>{s}</b>", label_s)
                       for s in ("CVE ID", "CVSS v3", "Severity", "KEV",
                                 "Affected Product", "Description", "Fix")]
            cve_rows = [cve_hdr]
            for cve in cve_matches:
                cvss   = cve.get("cvss_v3_score") or cve.get("cvss_v2_score") or 0
                sev    = cve.get("severity", "INFO")
                kev_yn = "YES" if cve.get("kev") else ""
                desc   = (cve.get("description", "") or "")[:60]
                fix    = "Yes" if cve.get("fix_available") else "No"
                sev_c  = HexColor(_SEV_HEX.get(sev, "#6c757d"))
                row = [
                    Paragraph(cve.get("cve_id", "")[:18], mono),
                    Paragraph(f"{cvss:.1f}" if isinstance(cvss, float) else str(cvss), small),
                    Paragraph(f"<font color='{_SEV_HEX.get(sev, '#6c757d')}'><b>{sev}</b></font>",
                              _style(f"SevC_{sev}", fontSize=8,
                                     fontName="Helvetica-Bold")),
                    Paragraph(f"<font color='#dc3545'><b>{kev_yn}</b></font>"
                              if kev_yn else "", small),
                    Paragraph((cve.get("product") or "")[:22], small),
                    Paragraph(desc, small),
                    Paragraph(fix, small),
                ]
                cve_rows.append(row)

            cve_col_w = [2.8*cm, 1.4*cm, 1.8*cm, 1.1*cm, 3.2*cm, 5.2*cm, 1.0*cm]
            cve_tbl = Table(cve_rows, colWidths=cve_col_w, repeatRows=1)
            cve_style = [
                ("BACKGROUND",    (0, 0), (-1, 0),  brand_color),
                ("TEXTCOLOR",     (0, 0), (-1, 0),  white),
                ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#dee2e6")),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING",   (0, 0), (-1, -1), 3),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1),
                 [HexColor("#f8f9fa"), white]),
            ]
            for ri, cve in enumerate(cve_matches, start=1):
                if cve.get("kev"):
                    cve_style.append(
                        ("BACKGROUND", (0, ri), (-1, ri), HexColor("#fff0f0"))
                    )
                elif (cve.get("severity") or "") == "CRITICAL":
                    cve_style.append(
                        ("BACKGROUND", (0, ri), (-1, ri), HexColor("#fff5ec"))
                    )
            cve_tbl.setStyle(TableStyle(cve_style))
            story.append(cve_tbl)
            story.append(Spacer(1, 0.25 * cm))

        # Configuration findings
        config_findings = _get_config_findings(host)
        if config_findings:
            story.append(Paragraph("Configuration Findings", section_title))
            for finding_text in config_findings:
                sev_prefix = ""
                f_lower = finding_text.lower()
                if any(k in f_lower for k in ("critical", "root", "telnet",
                                               "default cred", "eol")):
                    sev_prefix = "<font color='#dc3545'>●</font>  "
                elif any(k in f_lower for k in ("high", "firewall", "patch",
                                                 "antivirus", "rdp")):
                    sev_prefix = "<font color='#fd7e14'>●</font>  "
                else:
                    sev_prefix = "<font color='#ffc107'>●</font>  "
                story.append(Paragraph(
                    f"{sev_prefix}{finding_text}",
                    _style(f"CFinding_{ip}", fontSize=9, leading=13,
                           leftIndent=12, textColor=HexColor("#333333"))
                ))
            story.append(Spacer(1, 0.2 * cm))

        # Patch status
        patch = host.get("patch_status", {})
        if patch:
            days_since = patch.get("days_since_update", 0) or 0
            pending    = patch.get("pending_updates", 0) or 0
            last_upd   = patch.get("last_update_date", "N/A")
            stale_txt  = (f"  <font color='#dc3545'><b>({days_since} days stale)</b></font>"
                          if days_since > 90 else f"  ({days_since} days ago)")
            patch_txt  = (
                f"<b>Patch Status:</b>  Last update: {last_upd}{stale_txt}  |  "
                f"Pending: {pending}"
            )
            patch_color = HexColor("#fff0f0") if days_since > 90 else HexColor("#f8f9fa")
            patch_data  = [[Paragraph(patch_txt, _style("PatchP", fontSize=9,
                                                         textColor=HexColor("#333333")))]]
            patch_tbl   = Table(patch_data, colWidths=[CONTENT_W])
            patch_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), patch_color),
                ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#dee2e6")),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ]))
            story.append(patch_tbl)
            story.append(Spacer(1, 0.2 * cm))

        # Open ports table
        open_ports = host.get("open_ports", [])
        services   = host.get("services", {})  # {port: {service, version, notes}}
        if open_ports:
            story.append(Paragraph(f"Open Ports ({len(open_ports)})", section_title))
            port_hdr = [Paragraph(f"<b>{s}</b>", label_s)
                        for s in ("Port", "Service", "Version", "Notes")]
            port_rows = [port_hdr]
            for port in sorted(open_ports)[:50]:
                svc_info = services.get(str(port), services.get(port, {}))
                port_rows.append([
                    Paragraph(str(port), mono),
                    Paragraph(str(svc_info.get("service", "") or ""), small),
                    Paragraph(str(svc_info.get("version", "") or "")[:30], small),
                    Paragraph(str(svc_info.get("notes",   "") or "")[:50], small),
                ])
            port_col_w = [1.8*cm, 3.5*cm, 5.0*cm, CONTENT_W - 1.8*cm - 3.5*cm - 5.0*cm]
            port_tbl = Table(port_rows, colWidths=port_col_w, repeatRows=1)
            port_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0),  brand_color),
                ("TEXTCOLOR",     (0, 0), (-1, 0),  white),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1),
                 [HexColor("#f8f9fa"), white]),
                ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#dee2e6")),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING",   (0, 0), (-1, -1), 3),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(port_tbl)
            story.append(Spacer(1, 0.2 * cm))

        # AI narrative block
        ai_narrative = host.get("ai_narrative", "")
        if ai_narrative:
            story.append(Paragraph("AI Risk Narrative", section_title))
            ai_data = [[Paragraph(
                ai_narrative[:1200],
                _style("AIBlock", fontSize=8.5, leading=13,
                       textColor=HexColor("#333333"))
            )]]
            ai_tbl = Table(ai_data, colWidths=[CONTENT_W])
            ai_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#f0f4ff")),
                ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#c8d8ff")),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
            ]))
            story.append(ai_tbl)

        story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # MEDIUM HOSTS — grouped summary
    # ══════════════════════════════════════════════════════════════════════

    med_hosts = [
        h for h in hosts
        if h.get("risk_level", _score_to_level(h.get("risk_score", 0))) == "MEDIUM"
    ]

    if med_hosts:
        story.append(Paragraph(
            f"Medium Risk Hosts ({len(med_hosts)} hosts)", section_title
        ))
        story.append(HRFlowable(width=CONTENT_W, thickness=1,
                                color=brand_color, spaceAfter=6))
        med_hdr = [Paragraph(f"<b>{s}</b>", label_s)
                   for s in ("IP", "Hostname", "Risk Score", "Top Finding", "CVE Count")]
        med_rows = [med_hdr]
        for h in med_hosts:
            ip_m  = h.get("ip", "?")
            hn_m  = h.get("hostname") or ""
            sc_m  = h.get("risk_score", 0)
            cvc_m = len(h.get("cve_matches", []))
            top_f = ""
            if h.get("security_flags"):
                top_f = h["security_flags"][0].get("description", "")[:50]
            elif h.get("cve_matches"):
                top_f = h["cve_matches"][0].get("cve_id", "")
            med_rows.append([
                Paragraph(ip_m,        small),
                Paragraph(hn_m[:25],   small),
                Paragraph(str(sc_m),   small),
                Paragraph(top_f[:50],  small),
                Paragraph(str(cvc_m),  small),
            ])
        med_col_w = [3.0*cm, 4.5*cm, 2.5*cm, CONTENT_W - 3.0*cm - 4.5*cm - 2.5*cm - 2.0*cm, 2.0*cm]
        med_tbl = Table(med_rows, colWidths=med_col_w, repeatRows=1)
        med_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  HexColor("#ffc107")),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  HexColor("#333333")),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1),
             [HexColor("#fffcf0"), white]),
            ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#dee2e6")),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(med_tbl)
        story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # APPENDIX A: FULL HOST INVENTORY
    # ══════════════════════════════════════════════════════════════════════

    story.append(Paragraph("Appendix A — Full Host Inventory", section_title))
    story.append(HRFlowable(width=CONTENT_W, thickness=1,
                            color=brand_color, spaceAfter=6))

    inv_hdr = [Paragraph(f"<b>{s}</b>", label_s)
               for s in ("IP", "Hostname", "Category", "OS",
                         "Risk Level", "CVE Count", "Top CVE ID", "Cred Type")]
    inv_rows = [inv_hdr]

    hosts_sorted = sorted(hosts,
                          key=lambda h: h.get("risk_score", 0),
                          reverse=True)
    for h in hosts_sorted:
        lv   = h.get("risk_level", _score_to_level(h.get("risk_score", 0)))
        lv_c = _LEVEL_HEX.get(lv, "#6c757d")
        cves = h.get("cve_matches", [])
        top_cve_id = cves[0].get("cve_id", "—") if cves else "—"
        cred_type = h.get("cred_type", h.get("credential_type", "—"))
        os_short = (h.get("os_version") or h.get("os_guess") or "")[:20]
        inv_rows.append([
            Paragraph(h.get("ip", ""),                          mono),
            Paragraph((h.get("hostname") or "")[:20],           small),
            Paragraph((h.get("category") or "")[:20],           small),
            Paragraph(os_short,                                  small),
            Paragraph(
                f"<font color='{lv_c}'><b>{lv}</b></font>",
                _style(f"InvLV_{lv}", fontSize=8, fontName="Helvetica-Bold")
            ),
            Paragraph(str(len(cves)),                            small),
            Paragraph(top_cve_id[:18],                           mono),
            Paragraph(str(cred_type)[:12],                       small),
        ])

    inv_col_w = [2.8*cm, 3.2*cm, 3.2*cm, 3.0*cm, 2.2*cm, 1.6*cm, 2.8*cm, 2.2*cm]
    # Trim to CONTENT_W
    inv_col_w_sum = sum(inv_col_w)
    inv_col_w = [w / inv_col_w_sum * CONTENT_W for w in inv_col_w]

    inv_tbl = Table(inv_rows, colWidths=inv_col_w, repeatRows=1,
                    splitByRow=True)
    inv_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  brand_color),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  white),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),
         [HexColor("#f8f9fa"), white]),
        ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#dee2e6")),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 3),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(inv_tbl)
    story.append(PageBreak())

    # ══════════════════════════════════════════════════════════════════════
    # APPENDIX B: ALL CVEs DETECTED
    # ══════════════════════════════════════════════════════════════════════

    story.append(Paragraph("Appendix B — All CVEs Detected", section_title))
    story.append(HRFlowable(width=CONTENT_W, thickness=1,
                            color=brand_color, spaceAfter=6))

    # Build deduplicated CVE map with affected host IPs
    cve_map: dict = {}
    for h in hosts:
        for cve in h.get("cve_matches", []):
            cid = cve.get("cve_id", "")
            if not cid:
                continue
            if cid not in cve_map:
                cve_map[cid] = dict(cve)
                cve_map[cid]["_host_ips"] = []
            cve_map[cid]["_host_ips"].append(h.get("ip", ""))

    # Sort: KEV first, then CVSS descending
    all_cves_sorted = sorted(
        cve_map.values(),
        key=lambda x: (not x.get("kev"),
                       -(x.get("cvss_v3_score") or x.get("cvss_v2_score") or 0)),
    )

    cve_b_hdr = [Paragraph(f"<b>{s}</b>", label_s)
                 for s in ("CVE ID", "CVSS", "Severity", "KEV",
                           "Affected Hosts", "Product", "Fix")]
    cve_b_rows = [cve_b_hdr]

    for cve in all_cves_sorted:
        cvss  = cve.get("cvss_v3_score") or cve.get("cvss_v2_score") or 0
        sev   = cve.get("severity", "INFO")
        kev_yn = "YES" if cve.get("kev") else ""
        ips   = cve.get("_host_ips", [])
        hosts_str = ", ".join(ips[:3])
        if len(ips) > 3:
            hosts_str += f" +{len(ips) - 3}"
        fix = "Yes" if cve.get("fix_available") else "No"

        cve_b_rows.append([
            Paragraph(cve.get("cve_id", "")[:18], mono),
            Paragraph(f"{cvss:.1f}" if isinstance(cvss, float) else str(cvss), small),
            Paragraph(
                f"<font color='{_SEV_HEX.get(sev, '#6c757d')}'><b>{sev}</b></font>",
                _style(f"BAppSev", fontSize=8, fontName="Helvetica-Bold")
            ),
            Paragraph(
                f"<font color='#dc3545'><b>{kev_yn}</b></font>" if kev_yn else "",
                small
            ),
            Paragraph(hosts_str[:35], small),
            Paragraph((cve.get("product") or "")[:25], small),
            Paragraph(fix, small),
        ])

    cve_b_col_w = [2.8*cm, 1.4*cm, 2.0*cm, 1.1*cm, 4.5*cm, 4.0*cm, 1.2*cm]
    cve_b_col_w_sum = sum(cve_b_col_w)
    cve_b_col_w = [w / cve_b_col_w_sum * CONTENT_W for w in cve_b_col_w]

    cve_b_tbl = Table(cve_b_rows, colWidths=cve_b_col_w,
                      repeatRows=1, splitByRow=True)
    cve_b_style = [
        ("BACKGROUND",    (0, 0), (-1, 0),  brand_color),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  white),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1),
         [HexColor("#f8f9fa"), white]),
        ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#dee2e6")),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 3),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]
    for ri, cve in enumerate(all_cves_sorted, start=1):
        if cve.get("kev"):
            cve_b_style.append(
                ("BACKGROUND", (0, ri), (-1, ri), HexColor("#fff0f0"))
            )
    cve_b_tbl.setStyle(TableStyle(cve_b_style))
    story.append(cve_b_tbl)

    # ── Build the document ────────────────────────────────────────────────
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN_L,
        rightMargin=MARGIN_R,
        topMargin=MARGIN_T,
        bottomMargin=MARGIN_B,
        title="Technical Detail Report",
        author=company_name,
        subject=f"Cyber Risk Assessment — {client_name or 'Client'}",
    )

    doc.build(story,
              onFirstPage=_on_first_page,
              onLaterPages=_on_later_pages)

    logger.info(f"Detail PDF written: {output_path}")
    return output_path


# ── Internal helpers ──────────────────────────────────────────────────────

def _get_config_findings(host: dict) -> list:
    """Extract human-readable configuration finding strings from a host dict."""
    findings = []

    ssh = host.get("ssh_config_audit", {})
    if ssh.get("permit_root_login"):
        findings.append(
            "SSH: PermitRootLogin is enabled — disable to prevent direct root access"
        )
    if ssh.get("password_auth"):
        findings.append(
            "SSH: Password authentication enabled — prefer SSH key-only authentication"
        )
    if ssh.get("weak_ciphers"):
        ciphers = ", ".join(ssh["weak_ciphers"])
        findings.append(f"SSH: Weak ciphers configured: {ciphers}")
    if ssh.get("protocol_v1"):
        findings.append("SSH: Protocol v1 still listed in sshd_config — remove immediately")

    patch = host.get("patch_status", {})
    days  = patch.get("days_since_update", 0) or 0
    pend  = patch.get("pending_updates", "?")
    if days > 90:
        findings.append(
            f"Patches: Last updated {days} days ago — {pend} pending updates"
        )

    fw = host.get("windows_firewall", {})
    for profile, state in fw.items():
        if isinstance(state, str) and "disabled" in state.lower():
            findings.append(f"Windows Firewall: {profile} profile is disabled")

    av = host.get("antivirus", {})
    if av.get("status") == "missing":
        findings.append("Antivirus: No antivirus product detected")
    elif av.get("status") == "stale":
        findings.append(
            f"Antivirus: {av.get('product', '')} definitions are stale"
        )

    for share in host.get("smb_shares", []):
        access = share.get("access", "").lower()
        if "everyone" in access or "anonymous" in access or "unauthenticated" in access:
            findings.append(
                f"SMB: Share '{share.get('name', '')}' accessible without authentication"
            )

    if 23 in host.get("open_ports", []):
        findings.append("Telnet (port 23) is open — use SSH instead")

    if host.get("rdp_enabled") and 3389 in host.get("open_ports", []):
        findings.append(
            "RDP is enabled and port 3389 is open — verify NLA and MFA are enforced"
        )

    if host.get("uac_enabled") is False:
        findings.append("UAC (User Account Control) is disabled")

    for issue in host.get("ssl_issues", []):
        findings.append(
            f"SSL/TLS: {issue.get('issue', '')} on port {issue.get('port', '')}"
        )

    # Also include any security_flags items that weren't covered above
    for flag in host.get("security_flags", []):
        desc = flag.get("description", "")
        if desc and desc not in findings:
            sev = flag.get("severity", "")
            if sev in ("CRITICAL", "HIGH"):
                findings.append(desc)

    return findings
