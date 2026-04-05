from fpdf import FPDF
from datetime import datetime
import os


OUTPUT_PATH = "backend/reports/cloudguardian_evidence_pack.pdf"


class EvidencePDF(FPDF):
    pass


def generate_control_pdf(results, score_data, framework_name="Cyber Essentials", output_path=OUTPUT_PATH):
    pdf = EvidencePDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "CloudGuardian Evidence Pack", ln=1)

    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Framework: {framework_name}", ln=1)
    pdf.cell(0, 8, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", ln=1)
    pdf.ln(5)

    # Summary
    total_controls = len(results)
    failed_controls = sum(1 for r in results.values() if r["status"] == "FAIL")
    passed_controls = total_controls - failed_controls
    overall_status = "NON-COMPLIANT" if failed_controls > 0 else "COMPLIANT"
    
    pdf.cell(0, 7, f"Compliance Score: {score_data['score']}%", ln=1)
    pdf.cell(0, 7, f"Risk Level: {score_data['risk_level']}", ln=1)

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Executive Summary", ln=1)

    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 7, f"Overall Status: {overall_status}", ln=1)
    pdf.cell(0, 7, f"Controls Passed: {passed_controls}", ln=1)
    pdf.cell(0, 7, f"Controls Failed: {failed_controls}", ln=1)
    pdf.ln(5)

    # Control details
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Control Evaluation Results", ln=1)

    for control_id, data in results.items():
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, f"{control_id} - {data['name']}: {data['status']} [{data['severity']}]", ln=1)

        pdf.set_font("Arial", "", 11)

        if data["status"] == "FAIL":
            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 7, "Issue Summary:", ln=1)

            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 7, f"{data['plain_english_fail']}")

            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 7, "Risk Impact:", ln=1)

            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 7, f"{data['risk']}")

            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 7, "Recommended Action:", ln=1)

            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 7, f"{data['recommendation']}")

            pdf.set_font("Arial", "B", 11)
            pdf.cell(0, 7, "Technical Evidence:", ln=1)

            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 7, f"Triggered Signals: {', '.join(data['triggered_signals'])}")
        else:
            pdf.multi_cell(0, 7, "Status Explanation: No failing signals detected for this control.")

        pdf.ln(3)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    return output_path
