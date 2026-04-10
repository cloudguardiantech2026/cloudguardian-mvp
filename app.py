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


app = Flask(__name__)


def run_scan():
    signals = {}

    # Collect live AWS signals
    signals.update(get_s3_signals(profile_name="cloudguardian-demo"))
    signals.update(get_iam_signals(profile_name="cloudguardian-demo"))
    signals.update(
        get_network_signals(
            profile_name="cloudguardian-demo",
            region_name="eu-west-2",
        )
    )

    # Drift detection
    previous_signals = load_previous_state()
    drift = detect_drift(previous_signals, signals)

    # Compliance evaluation
    controls = load_controls()
    results = evaluate_controls(signals, controls)
    score_data = calculate_compliance_score(results)

    # Save latest state for future drift comparison
    save_current_state(signals)

    # Generate evidence pack
    pdf_path = generate_control_pdf(results, score_data)

    return signals, results, score_data, drift, pdf_path


@app.route("/download-pdf")
def download_pdf():
    pdf_path = "backend/reports/cloudguardian_evidence_pack.pdf"
    return send_file(pdf_path, as_attachment=True)


@app.route("/", methods=["GET", "POST"])
def index():
    signals = {}
    results = {}
    score_data = None
    drift = []
    pdf_path = None
    response = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "scan":
            signals, results, score_data, drift, pdf_path = run_scan()

        elif action == "ask":
            query = request.form.get("query", "").strip()
            signals, results, score_data, drift, pdf_path = run_scan()
            response = handle_query(query, results, drift, score_data)

    return render_template(
        "index.html",
        signals=signals,
        results=results,
        score_data=score_data,
        drift=drift,
        pdf_path=pdf_path,
        response=response,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=true)
