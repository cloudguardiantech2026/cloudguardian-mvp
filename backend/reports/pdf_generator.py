from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, PageBreak, HRFlowable
)
from datetime import datetime, timezone


def generate_control_pdf(results, score_data,
                         output_path="backend/reports/cloudguardian_evidence_pack.pdf"):

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CGTitle',
        parent=styles['Title'],
        fontSize=22,
        textColor=colors.HexColor('#1F3D6B'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'CGSubtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#555566'),
        spaceAfter=2
    )
    section_style = ParagraphStyle(
        'CGSection',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=colors.HexColor('#2E75B6'),
        spaceBefore=16,
        spaceAfter=8
    )
    body_style = ParagraphStyle(
        'CGBody',
        parent=styles['BodyText'],
        fontSize=10,
        textColor=colors.HexColor('#1A1A2E'),
        spaceAfter=6
    )
    control_name_style = ParagraphStyle(
        'CGControlName',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#1F3D6B'),
        fontName='Helvetica-Bold',
        spaceBefore=12,
        spaceAfter=4
    )
    label_style = ParagraphStyle(
        'CGLabel',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#555566'),
        fontName='Helvetica-Bold',
        spaceAfter=2
    )
    value_style = ParagraphStyle(
        'CGValue',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#1A1A2E'),
        spaceAfter=6,
        leftIndent=10
    )

    story = []

    # ── HEADER ──────────────────────────────────────────────
    story.append(Paragraph("CloudGuardian", title_style))
    story.append(Paragraph("Cyber Essentials Cloud Compliance Evidence Pack", subtitle_style))
    generated = datetime.now(timezone.utc).strftime("%d %B %Y at %H:%M UTC")
    story.append(Paragraph(f"Generated: {generated}", subtitle_style))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=2,
                             color=colors.HexColor('#2E75B6'), spaceAfter=16))

    # ── EXECUTIVE SUMMARY ────────────────────────────────────
    story.append(Paragraph("Executive Summary", section_style))

    score = score_data.get("score", 0)
    risk = score_data.get("risk_level", "UNKNOWN")
    passed = [cid for cid, d in results.items() if d.get("status") == "PASS"]
    failed = [cid for cid, d in results.items() if d.get("status") == "FAIL"]

    # Colour-coded score row
    score_color = colors.HexColor('#1A7A4A') if score >= 80 else \
                  colors.HexColor('#BA7517') if score >= 50 else \
                  colors.HexColor('#A32D2D')
    risk_color = colors.HexColor('#A32D2D') if risk == "HIGH" else \
                 colors.HexColor('#BA7517') if risk == "MEDIUM" else \
                 colors.HexColor('#1A7A4A')

    summary_data = [
        ["Metric", "Value"],
        ["Compliance Score", f"{score}%"],
        ["Risk Level", risk],
        ["Controls Passed", str(len(passed))],
        ["Controls Failed", str(len(failed))],
        ["Assessment Framework", "Cyber Essentials"],
        ["Overall Status", "COMPLIANT" if len(failed) == 0 else "NON-COMPLIANT"],
    ]

    summary_table = Table(summary_data, colWidths=[160, 300])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1F3D6B')),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor('#EEF3FB')),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, -1), 10),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor('#1A1A2E')),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor('#EEF3FB'), colors.white]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8))

    # Risk interpretation
    if risk == "HIGH":
        meaning = ("One or more HIGH severity issues were identified. These represent "
                   "significant compliance gaps that must be addressed before Cyber Essentials "
                   "certification can be achieved. Immediate remediation is recommended.")
    elif risk == "MEDIUM":
        meaning = ("Some issues were identified that should be improved to strengthen "
                   "your security posture. Cyber Essentials certification may be achievable "
                   "after addressing these findings.")
    else:
        meaning = ("No major issues were identified in the areas assessed. Your environment "
                   "demonstrates a strong Cyber Essentials compliance posture.")

    story.append(Paragraph(meaning, body_style))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor('#CCCCCC'), spaceAfter=8))

    # ── CONTROL RESULTS ──────────────────────────────────────
    story.append(Paragraph("Control Evaluation Results", section_style))
    story.append(Paragraph(
        "The following section details the outcome of each Cyber Essentials control "
        "assessed during this scan, including the specific resources evaluated and "
        "remediation guidance where applicable.",
        body_style
    ))

    for control_id, data in results.items():
        status = data.get("status", "UNKNOWN")
        name = data.get("name", control_id)
        severity = data.get("severity", "UNKNOWN")

        # Status colour
        status_color = colors.HexColor('#1A7A4A') if status == "PASS" \
            else colors.HexColor('#A32D2D')
        status_bg = colors.HexColor('#E8F5EE') if status == "PASS" \
            else colors.HexColor('#FDEAEA')

        # Control header row
        header_data = [[
            Paragraph(f"<b>{control_id} — {name}</b>",
                      ParagraphStyle('ch', parent=styles['Normal'],
                                     fontSize=11, textColor=colors.white,
                                     fontName='Helvetica-Bold')),
            Paragraph(f"<b>{status}</b>",
                      ParagraphStyle('cs', parent=styles['Normal'],
                                     fontSize=11, textColor=colors.white,
                                     fontName='Helvetica-Bold',
                                     alignment=1)),
            Paragraph(f"Severity: {severity}",
                      ParagraphStyle('cv', parent=styles['Normal'],
                                     fontSize=10, textColor=colors.white,
                                     alignment=2)),
        ]]
        header_table = Table(header_data, colWidths=[260, 80, 120])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor('#1F3D6B')),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0, colors.white),
        ]))
        story.append(Spacer(1, 10))
        story.append(header_table)

        if status == "PASS":
            pass_data = [[
                Paragraph("✓  This control is currently passing. "
                          "No compliance issues were detected in this area.",
                          ParagraphStyle('pp', parent=styles['Normal'],
                                         fontSize=10,
                                         textColor=colors.HexColor('#1A7A4A')))
            ]]
            pass_table = Table(pass_data, colWidths=[460])
            pass_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor('#E8F5EE')),
                ("PADDING", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
            ]))
            story.append(pass_table)

        else:
            # Detail rows for failed controls
            detail_rows = []

            plain = data.get("plain_english_fail", "")
            if plain:
                detail_rows.append([
                    Paragraph("<b>Finding:</b>", ParagraphStyle(
                        'dl', parent=styles['Normal'], fontSize=9,
                        textColor=colors.HexColor('#555566'),
                        fontName='Helvetica-Bold')),
                    Paragraph(plain, ParagraphStyle(
                        'dv', parent=styles['Normal'], fontSize=10,
                        textColor=colors.HexColor('#1A1A2E')))
                ])

            risk_text = data.get("risk", "")
            if risk_text:
                detail_rows.append([
                    Paragraph("<b>Business Risk:</b>", ParagraphStyle(
                        'dl2', parent=styles['Normal'], fontSize=9,
                        textColor=colors.HexColor('#555566'),
                        fontName='Helvetica-Bold')),
                    Paragraph(risk_text, ParagraphStyle(
                        'dv2', parent=styles['Normal'], fontSize=10,
                        textColor=colors.HexColor('#A32D2D')))
                ])

            rec = data.get("recommendation", "")
            if rec:
                detail_rows.append([
                    Paragraph("<b>Recommendation:</b>", ParagraphStyle(
                        'dl3', parent=styles['Normal'], fontSize=9,
                        textColor=colors.HexColor('#555566'),
                        fontName='Helvetica-Bold')),
                    Paragraph(rec, ParagraphStyle(
                        'dv3', parent=styles['Normal'], fontSize=10,
                        textColor=colors.HexColor('#1F3D6B')))
                ])

            affected = data.get("affected_resources", [])
            if affected:
                detail_rows.append([
                    Paragraph("<b>Affected Resources:</b>", ParagraphStyle(
                        'dl4', parent=styles['Normal'], fontSize=9,
                        textColor=colors.HexColor('#555566'),
                        fontName='Helvetica-Bold')),
                    Paragraph(", ".join(affected), ParagraphStyle(
                        'dv4', parent=styles['Normal'], fontSize=10,
                        textColor=colors.HexColor('#1A1A2E'),
                        fontName='Helvetica-Oblique'))
                ])

            signals = data.get("triggered_signals", [])
            if signals:
                detail_rows.append([
                    Paragraph("<b>Triggered By:</b>", ParagraphStyle(
                        'dl5', parent=styles['Normal'], fontSize=9,
                        textColor=colors.HexColor('#555566'),
                        fontName='Helvetica-Bold')),
                    Paragraph(", ".join(signals), ParagraphStyle(
                        'dv5', parent=styles['Normal'], fontSize=9,
                        textColor=colors.HexColor('#555566')))
                ])

            if detail_rows:
                detail_table = Table(detail_rows, colWidths=[120, 340])
                detail_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor('#FDEAEA')),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor('#F5D5D5')),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                     [colors.HexColor('#FDEAEA'), colors.HexColor('#FDF0F0')]),
                ]))
                story.append(detail_table)

    # ── FOOTER NOTE ─────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor('#CCCCCC'), spaceAfter=8))
    story.append(Paragraph(
        "<b>About this report:</b> This evidence pack was generated automatically by "
        "CloudGuardian, a compliance reasoning platform for Cyber Essentials. "
        "Findings are based on a live scan of your AWS environment at the time of generation. "
        "This report is intended to support Cyber Essentials self-assessment and "
        "should be reviewed alongside formal certification guidance from the NCSC.",
        ParagraphStyle('footer', parent=styles['Normal'],
                       fontSize=8, textColor=colors.HexColor('#555566'))
    ))

    doc.build(story)
    return output_path