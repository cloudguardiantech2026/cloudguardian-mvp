from flask import Flask, render_template, request, send_file
from backend.scanners.aws_s3 import get_s3_signals
from backend.scanners.aws_iam import get_iam_signals
from backend.scanners.aws_network import get_network_signals
from backend.engine.framework_engine import (
    load_controls,
    evaluate_controls,
    calculate_compliance_score,
)
from backend.engine.drift_engine import (
    load_previous_state,
    save_current_state,
    detect_drift,
)
from backend.engine.conversation_engine import handle_query
from backend.reports.pdf_generator import generate_control_pdf



@app.route("/download-pdf")
def download_pdf():
    pdf_path = "backend/reports/cloudguardian_evidence_pack.pdf"
    return send_file(pdf_path, as_attachment=True)
