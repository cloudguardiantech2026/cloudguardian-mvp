from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)



def generate_control_pdf(results, score_data, output_path="backend/reports/cloudguardian_evidence_pack.pdf"):
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()

    story = []

    title = Paragraph("<b>CloudGuardian Evidence Pack</b>", styles["Title"])
    subtitle = Paragraph(
        "Cyber Essentials cloud posture assessment summary",
        styles["Heading2"]
    )

    story.append(title)
    story.append(Spacer(1, 12))
    story.append(subtitle)
    story.append(Spacer(1, 24))

    score = score_data.get("score", 0)
    risk = score_data.get("risk_level", "UNKNOWN")

    summary_table = Table([
        ["Compliance Score", f"{score}%"],
        ["Overall Risk Level", risk],
    ], colWidths=[200, 250])

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>What this means</b>", styles["Heading2"]))

    if risk == "HIGH":
        meaning = (
            "CloudGuardian identified one or more issues that may expose your systems or information to unnecessary risk. "
            "These should be addressed before relying on this environment for normal business use."
        )
    elif risk == "MEDIUM":
        meaning = (
            "CloudGuardian identified some issues that should be improved to strengthen your security posture."
        )
    else:
        meaning = (
            "CloudGuardian did not identify any major issues in the areas checked during this assessment."
        )

    story.append(Paragraph(meaning, styles["BodyText"]))
    story.append(Spacer(1, 20))

    return output_path
