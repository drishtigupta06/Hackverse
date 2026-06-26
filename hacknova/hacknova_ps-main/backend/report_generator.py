#!/usr/bin/env python3
"""
PDF report generator using reportlab.
Generates comprehensive vulnerability scan reports.
"""
import io
import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics import renderPDF

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#D97706"),
    "low": colors.HexColor("#65A30D"),
    "info": colors.HexColor("#0891B2"),
}

DARK_BG = colors.HexColor("#0F172A")
ACCENT = colors.HexColor("#6366F1")
LIGHT_GRAY = colors.HexColor("#F1F5F9")
TEXT_COLOR = colors.HexColor("#1E293B")


def generate_pdf_report(
    scan_id: str,
    target: str,
    vulnerabilities: List[Dict[str, Any]],
    graph_data: Optional[Dict] = None,
    created_at: Optional[str] = None,
    output_path: Optional[str] = None,
) -> bytes:
    """
    Generate a comprehensive PDF vulnerability report.
    Returns PDF as bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer if not output_path else output_path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"CyberGuard Vulnerability Report — {target}",
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        "CyberGuardTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=ACCENT,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=11,
        textColor=TEXT_COLOR,
        spaceAfter=20,
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=14, textColor=ACCENT,
        spaceBefore=16, spaceAfter=8,
    )
    h3_style = ParagraphStyle(
        "H3", parent=styles["Heading3"],
        fontSize=11, textColor=TEXT_COLOR,
        spaceBefore=10, spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9, textColor=TEXT_COLOR,
        spaceAfter=4, leading=14,
    )
    code_style = ParagraphStyle(
        "Code", parent=styles["Code"],
        fontSize=8, backColor=LIGHT_GRAY,
        spaceAfter=4, leading=12,
    )

    story = []

    # ── Cover section ──────────────────────────────────────────────────────
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("🛡️ CyberGuard", title_style))
    story.append(Paragraph("AI-Assisted Vulnerability Assessment Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    story.append(Spacer(1, 0.5 * cm))

    # Meta table
    scan_date = created_at or datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    meta_data = [
        ["Target:", target],
        ["Scan ID:", scan_id],
        ["Report Date:", scan_date],
        ["Total Findings:", str(len(vulnerabilities))],
    ]
    
    # Count by severity
    sev_counts = {}
    for v in vulnerabilities:
        sev = v.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sev_counts.get(sev, 0)
        if count:
            meta_data.append([f"{sev.capitalize()}:", str(count)])

    meta_table = Table(meta_data, colWidths=[4 * cm, 12 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), ACCENT),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [LIGHT_GRAY, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── Executive Summary ──────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2_style))
    
    critical_count = sev_counts.get("critical", 0)
    high_count = sev_counts.get("high", 0)
    risk_level = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "MEDIUM" if sev_counts.get("medium", 0) > 0 else "LOW"
    
    summary_text = (
        f"A vulnerability assessment was performed against <b>{target}</b>. "
        f"The scan identified <b>{len(vulnerabilities)} security findings</b> with an overall risk level of "
        f"<b>{risk_level}</b>. "
        f"Immediate attention is required for {critical_count} critical and {high_count} high severity findings. "
        f"Detailed remediation guidance is provided for each vulnerability."
    )
    story.append(Paragraph(summary_text, body_style))

    # ── Vulnerability Table ────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Vulnerability Findings", h2_style))

    table_data = [["#", "CVE ID", "Vulnerability", "Severity", "Host", "Port"]]
    
    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(vulnerabilities, key=lambda v: sev_order.get(v.get("severity", "info"), 5))
    
    for i, v in enumerate(sorted_vulns[:50], 1):  # Max 50 in table
        sev = v.get("severity", "info")
        cve_id = v.get("cve_id") or "N/A"
        name = (v.get("name") or "")[:45]
        host = v.get("host") or ""
        port = str(v.get("port") or "")
        table_data.append([str(i), cve_id, name, sev.upper(), host, port])

    col_widths = [1*cm, 3.5*cm, 6*cm, 2.5*cm, 3*cm, 1.5*cm]
    vuln_table = Table(table_data, colWidths=col_widths, repeatRows=1)
    
    table_style = [
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GRAY]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    
    # Color severity cells
    for row_idx, v in enumerate(sorted_vulns[:50], 1):
        sev = v.get("severity", "info")
        sev_col = SEVERITY_COLORS.get(sev, colors.gray)
        table_style.append(("BACKGROUND", (3, row_idx), (3, row_idx), sev_col))
        table_style.append(("TEXTCOLOR", (3, row_idx), (3, row_idx), colors.white))
        table_style.append(("FONTNAME", (3, row_idx), (3, row_idx), "Helvetica-Bold"))
    
    vuln_table.setStyle(TableStyle(table_style))
    story.append(vuln_table)

    # ── Detailed Findings ──────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Detailed Findings", h2_style))

    for i, v in enumerate(sorted_vulns[:20], 1):  # Detail for top 20
        sev = v.get("severity", "info")
        cve_id = v.get("cve_id") or ""
        name = v.get("name") or "Unknown"
        
        finding_title = f"{i}. {name}"
        if cve_id:
            finding_title += f" ({cve_id})"
        story.append(Paragraph(finding_title, h3_style))
        
        detail_data = [
            ["Severity", sev.upper(), "Host", v.get("host") or ""],
            ["Port", str(v.get("port") or "N/A"), "Service", v.get("service") or ""],
            ["Source", v.get("source") or "", "CVSS Score", str(v.get("cvss_score") or "N/A")],
        ]
        detail_table = Table(detail_data, colWidths=[3*cm, 5*cm, 3*cm, 5.5*cm])
        detail_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(detail_table)
        
        if v.get("description"):
            story.append(Paragraph(f"<b>Description:</b> {v['description'][:500]}", body_style))
        if v.get("remediation"):
            story.append(Paragraph(f"<b>Remediation:</b> {v['remediation'][:300]}", body_style))
        if v.get("references"):
            refs = v["references"][:2]
            story.append(Paragraph(f"<b>References:</b> {', '.join(refs)}", body_style))
        
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0")))
        story.append(Spacer(1, 0.2 * cm))

    # ── Attack Paths ───────────────────────────────────────────────────────
    if graph_data:
        story.append(PageBreak())
        story.append(Paragraph("Attack Path Analysis", h2_style))
        story.append(Paragraph(
            f"The following attack graph contains <b>{len(graph_data.get('nodes', []))} nodes</b> and "
            f"<b>{len(graph_data.get('edges', []))} edges</b>. High-severity paths are highlighted below:",
            body_style,
        ))
        
        # Summarize nodes by type
        node_types = {}
        for n in graph_data.get("nodes", []):
            ntype = n.get("type", "unknown")
            node_types[ntype] = node_types.get(ntype, 0) + 1
        
        path_data = [["Node Type", "Count"]] + [[k.capitalize(), str(v)] for k, v in node_types.items()]
        pt = Table(path_data, colWidths=[8*cm, 8*cm])
        pt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GRAY]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(pt)

    # ── Recommendations ────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("General Recommendations", h2_style))
    
    recommendations = [
        ("1. Immediate Patching", "Apply security patches for all critical and high severity findings immediately. Prioritize internet-facing services."),
        ("2. Network Segmentation", "Restrict access to sensitive ports using firewall rules. Only expose services that are absolutely necessary."),
        ("3. Disable Unused Services", "Shut down any services running on open ports that are not required for business operations."),
        ("4. Enable Security Headers", "For web services, implement security headers: Content-Security-Policy, X-Frame-Options, HSTS."),
        ("5. Regular Scanning", "Schedule weekly vulnerability scans and monthly penetration tests to catch new vulnerabilities."),
        ("6. Monitoring & Alerting", "Implement SIEM/IDS to detect exploitation attempts. Configure alerts for anomalous behaviors."),
        ("7. Credential Hygiene", "Rotate all service credentials. Use unique, strong passwords and enable MFA where possible."),
        ("8. Update Dependencies", "Keep all software, libraries, and OS packages updated. Subscribe to security advisories for used software."),
    ]
    
    for title, text in recommendations:
        story.append(Paragraph(f"<b>{title}</b>", body_style))
        story.append(Paragraph(text, body_style))
        story.append(Spacer(1, 0.2 * cm))

    # Footer note
    story.append(Spacer(1, 1 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Paragraph(
        f"<i>Report generated by CyberGuard AI Platform — {scan_date}. "
        f"This report is confidential and intended for authorized personnel only.</i>",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.gray, alignment=TA_CENTER),
    ))

    doc.build(story)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
