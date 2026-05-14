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

    scan_time = datetime.now(timezone.utc)
    scan_timestamp = scan_time.strftime("%d %B %Y at %H:%M:%S UTC")
    scan_date = scan_time.strftime("%d %B %Y")
    scan_time_only = scan_time.strftime("%H:%M:%S UTC")
    validity_note = "This assessment reflects the live state of your AWS environment at the time of scan. Assessment validity: 24 hours."

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('CGTitle', parent=styles['Title'],
        fontSize=22, textColor=colors.HexColor('#1F3D6B'), spaceAfter=4)
    subtitle_style = ParagraphStyle('CGSubtitle', parent=styles['Normal'],
        fontSize=11, textColor=colors.HexColor('#555566'), spaceAfter=2)
    section_style = ParagraphStyle('CGSection', parent=styles['Heading2'],
        fontSize=13, textColor=colors.HexColor('#2E75B6'), spaceBefore=16, spaceAfter=8)
    body_style = ParagraphStyle('CGBody', parent=styles['BodyText'],
        fontSize=10, textColor=colors.HexColor('#1A1A2E'), spaceAfter=6)
    small_style = ParagraphStyle('CGSmall', parent=styles['Normal'],
        fontSize=8, textColor=colors.HexColor('#555566'), spaceAfter=4)
    autofail_style = ParagraphStyle('CGAutofail', parent=styles['Normal'],
        fontSize=9, textColor=colors.white, fontName='Helvetica-Bold')

    story = []

    # ── HEADER ──────────────────────────────────────────────
    story.append(Paragraph("CloudGuardian", title_style))
    story.append(Paragraph("Cyber Essentials Cloud Compliance Evidence Pack", subtitle_style))
    story.append(Paragraph("Framework: Cyber Essentials v3.3 — Danzell (April 2026)", subtitle_style))
    story.append(Spacer(1, 6))

    # Timestamp banner
    ts_data = [[
        Paragraph(f"<b>Scan performed:</b> {scan_timestamp}", ParagraphStyle(
            'tsb', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#1A1A2E'))),
        Paragraph(f"<b>Assessment valid until:</b> {scan_time.strftime('%d %B %Y at %H:%M UTC')} +24hrs", ParagraphStyle(
            'tsv', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#1A1A2E'), alignment=2)),
    ]]
    ts_table = Table(ts_data, colWidths=[270, 190])
    ts_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor('#EEF3FB')),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
    ]))
    story.append(ts_table)
    story.append(Spacer(1, 4))
    story.append(Paragraph(validity_note, small_style))
    story.append(HRFlowable(width="100%", thickness=2,
                             color=colors.HexColor('#2E75B6'), spaceAfter=16))

    # ── EXECUTIVE SUMMARY ────────────────────────────────────
    story.append(Paragraph("Executive Summary", section_style))

    score = score_data.get("score", 0)
    risk = score_data.get("risk_level", "UNKNOWN")
    cert_status = score_data.get("certification_status", "UNKNOWN")
    auto_fail_triggered = score_data.get("auto_fail_triggered", False)
    passed = [cid for cid, d in results.items() if d.get("status") == "PASS"]
    failed = [cid for cid, d in results.items() if d.get("status") == "FAIL"]
    auto_fail_controls = [cid for cid, d in results.items() if d.get("auto_fail", False)]

    score_color = colors.HexColor('#1A7A4A') if score >= 80 else \
                  colors.HexColor('#BA7517') if score >= 50 else \
                  colors.HexColor('#A32D2D')

    summary_data = [
        ["Metric", "Value"],
        ["Compliance Score", f"{score}%"],
        ["Risk Level", risk],
        ["Controls Passed", str(len(passed))],
        ["Controls Failed", str(len(failed))],
        ["Auto-fail Conditions", str(len(auto_fail_controls)) if auto_fail_controls else "None"],
        ["Assessment Framework", "Cyber Essentials v3.3 (Danzell)"],
        ["Certification Status", cert_status],
        ["Scan Timestamp", scan_timestamp],
        ["Assessment Valid For", "24 hours from scan time"],
    ]

    summary_table = Table(summary_data, colWidths=[160, 300])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1F3D6B')),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
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

    # Auto-fail warning banner
    if auto_fail_triggered:
        af_data = [[Paragraph(
            f"⚠ AUTO-FAIL CONDITION DETECTED — Cyber Essentials v3.3 certification is blocked. "
            f"The following controls triggered automatic failure criteria: {', '.join(auto_fail_controls)}. "
            f"These must be resolved before certification can be achieved.",
            ParagraphStyle('afb', parent=styles['Normal'], fontSize=10,
                           textColor=colors.white, fontName='Helvetica-Bold'))]]
        af_table = Table(af_data, colWidths=[460])
        af_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor('#A32D2D')),
            ("PADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(af_table)
        story.append(Spacer(1, 8))

    # Risk interpretation
    if auto_fail_triggered:
        meaning = ("One or more AUTO-FAIL conditions have been detected. Under Cyber Essentials v3.3 "
                   "(Danzell, April 2026), these conditions result in immediate certification failure "
                   "regardless of other controls. Immediate remediation is required before any "
                   "Cyber Essentials assessment can succeed.")
    elif risk == "HIGH":
        meaning = ("One or more HIGH severity issues were identified. These represent significant "
                   "compliance gaps that must be addressed before Cyber Essentials v3.3 certification "
                   "can be achieved. Immediate remediation is recommended.")
    elif risk == "MEDIUM":
        meaning = ("Some issues were identified that should be improved to strengthen your security "
                   "posture. Cyber Essentials v3.3 certification may be achievable after addressing "
                   "these findings.")
    else:
        meaning = ("No major issues were identified in the areas assessed. Your environment "
                   "demonstrates a strong Cyber Essentials v3.3 compliance posture.")

    story.append(Paragraph(meaning, body_style))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor('#CCCCCC'), spaceAfter=8))

    # ── CONTROL RESULTS ──────────────────────────────────────
    story.append(Paragraph("Control Evaluation Results", section_style))
    story.append(Paragraph(
        "The following section details the outcome of each Cyber Essentials v3.3 control "
        "assessed during this scan, including the specific resources evaluated and "
        "remediation guidance where applicable.",
        body_style
    ))

    for control_id, data in results.items():
        status = data.get("status", "UNKNOWN")
        name = data.get("name", control_id)
        severity = data.get("severity", "UNKNOWN")
        is_auto_fail = data.get("auto_fail", False)

        header_label = f"{control_id} — {name}"
        status_label = status
        if is_auto_fail:
            status_label = "FAIL ⚠ AUTO-FAIL"

        header_bg = colors.HexColor('#A32D2D') if is_auto_fail else colors.HexColor('#1F3D6B')

        header_data = [[
            Paragraph(f"<b>{header_label}</b>",
                      ParagraphStyle('ch', parent=styles['Normal'],
                                     fontSize=11, textColor=colors.white,
                                     fontName='Helvetica-Bold')),
            Paragraph(f"<b>{status_label}</b>",
                      ParagraphStyle('cs', parent=styles['Normal'],
                                     fontSize=10, textColor=colors.white,
                                     fontName='Helvetica-Bold', alignment=1)),
            Paragraph(f"Severity: {severity}",
                      ParagraphStyle('cv', parent=styles['Normal'],
                                     fontSize=10, textColor=colors.white,
                                     alignment=2)),
        ]]

        header_table = Table(header_data, colWidths=[260, 100, 100])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), header_bg),
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
            detail_rows = []

            if is_auto_fail:
                detail_rows.append([
                    Paragraph("<b>⚠ Auto-fail:</b>", ParagraphStyle(
                        'dlaf', parent=styles['Normal'], fontSize=9,
                        textColor=colors.white, fontName='Helvetica-Bold',
                        backColor=colors.HexColor('#A32D2D'))),
                    Paragraph("This control has triggered an automatic failure condition under "
                               "Cyber Essentials v3.3 (Danzell). Certification cannot be achieved "
                               "until this is resolved.", ParagraphStyle(
                        'dvaf', parent=styles['Normal'], fontSize=10,
                        textColor=colors.white,
                        backColor=colors.HexColor('#A32D2D')))
                ])

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

            fm = data.get("framework_mappings", {}).get("cyber_essentials", {})
            version = fm.get("version", "")
            if version:
                detail_rows.append([
                    Paragraph("<b>CE Version:</b>", ParagraphStyle(
                        'dlv', parent=styles['Normal'], fontSize=9,
                        textColor=colors.HexColor('#555566'),
                        fontName='Helvetica-Bold')),
                    Paragraph(version, ParagraphStyle(
                        'dvv', parent=styles['Normal'], fontSize=9,
                        textColor=colors.HexColor('#555566')))
                ])

            if detail_rows:
                row_bg = colors.HexColor('#FDEAEA')
                row_label_bg = colors.HexColor('#F5D5D5')
                if is_auto_fail:
                    row_bg = colors.HexColor('#F9E0E0')
                    row_label_bg = colors.HexColor('#EFC0C0')

                detail_table = Table(detail_rows, colWidths=[120, 340])
                detail_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), row_bg),
                    ("BACKGROUND", (0, 0), (0, -1), row_label_bg),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                     [row_bg, colors.HexColor('#FDF0F0')]),
                ]))
                story.append(detail_table)

    # ── VULNERABILITY TIMELINE ───────────────────────────────
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor('#CCCCCC'), spaceAfter=8))
    story.append(Paragraph("Vulnerability Assessment Timeline", section_style))
    story.append(Paragraph(
        "This section demonstrates to your Cyber Essentials assessor that CloudGuardian "
        "performs continuous compliance monitoring — not a one-time point-in-time snapshot. "
        "Each check was performed against your live AWS environment at the time shown below.",
        body_style
    ))

    timeline_data = [
        ["Check", "AWS API Called", "Performed At", "Valid Until"],
        ["S3 Public Access", "s3api get-public-access-block", scan_timestamp,
         scan_time.strftime("%d %B %Y at %H:%M UTC") + " +24hrs"],
        ["IAM MFA Status", "iam list-mfa-devices", scan_timestamp,
         scan_time.strftime("%d %B %Y at %H:%M UTC") + " +24hrs"],
        ["IAM Privilege Check", "iam list-attached-user-policies", scan_timestamp,
         scan_time.strftime("%d %B %Y at %H:%M UTC") + " +24hrs"],
        ["Security Groups", "ec2 describe-security-groups", scan_timestamp,
         scan_time.strftime("%d %B %Y at %H:%M UTC") + " +24hrs"],
        ["Internet Gateway", "ec2 describe-internet-gateways", scan_timestamp,
         scan_time.strftime("%d %B %Y at %H:%M UTC") + " +24hrs"],
        ["Route Tables", "ec2 describe-route-tables", scan_timestamp,
         scan_time.strftime("%d %B %Y at %H:%M UTC") + " +24hrs"],
    ]

    timeline_table = Table(timeline_data, colWidths=[100, 140, 130, 90])
    timeline_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor('#1F3D6B')),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor('#1A1A2E')),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor('#CCCCCC')),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor('#EEF3FB'), colors.white]),
    ]))
    story.append(timeline_table)
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "<b>Note for assessors:</b> CloudGuardian performs automated AWS API calls on each scan "
        "cycle. All calls are read-only (Describe, List, Get). No changes are made to the "
        "customer environment. Scans can be triggered on-demand or scheduled for continuous "
        "monitoring. Each evidence pack is timestamped to the second and reflects the live "
        "infrastructure state at the moment of generation. This satisfies the Cyber Essentials "
        "v3.3 requirement for demonstrable, current evidence of control implementation.",
        ParagraphStyle('assessor_note', parent=styles['Normal'],
                       fontSize=8, textColor=colors.HexColor('#555566'),
                       backColor=colors.HexColor('#EEF3FB'),
                       leftIndent=8, rightIndent=8, spaceBefore=4, spaceAfter=4)
    ))

    # ── FOOTER ──────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor('#CCCCCC'), spaceAfter=8))
    story.append(Paragraph(
        f"<b>About this report:</b> Generated by CloudGuardian (OputGuard Technologies Ltd) — "
        f"a compliance reasoning platform for Cyber Essentials. Assessment performed against "
        f"Cyber Essentials Requirements for IT Infrastructure v3.3 (Danzell, April 2026). "
        f"Scan completed: {scan_timestamp}. Findings are based on a live read-only scan of "
        f"your AWS environment. This report is intended to support Cyber Essentials "
        f"self-assessment and Cyber Essentials Plus preparation. Review alongside formal "
        f"certification guidance from the NCSC and IASME.",
        ParagraphStyle('footer', parent=styles['Normal'],
                       fontSize=8, textColor=colors.HexColor('#555566'))
    ))

    doc.build(story)
    return output_path
