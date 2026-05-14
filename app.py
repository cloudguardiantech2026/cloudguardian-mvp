

import json
import os
import markdown
from flask import Flask, render_template, request, send_file, session
from backend.scanners.aws_s3 import get_s3_signals
from backend.scanners.aws_iam import get_iam_signals
from backend.scanners.aws_network import get_network_signals
from backend.scanners.aws_ssm import get_ssm_signals
from backend.scanners.aws_guardduty import get_guardduty_signals
from backend.engine.framework_engine import (
    load_controls, evaluate_controls, calculate_compliance_score,
)
from backend.engine.drift_engine import (
    load_previous_state, save_current_state, detect_drift,
)
from backend.engine.conversation_engine import handle_query
from backend.reports.pdf_generator import generate_control_pdf

app = Flask(__name__)
app.secret_key = "cloudguardian-secret-2026"

SCAN_CACHE_PATH = "backend/state/scan_cache.json"


def save_scan_cache(results, score_data, drift, profile_name):
    os.makedirs(os.path.dirname(SCAN_CACHE_PATH), exist_ok=True)
    with open(SCAN_CACHE_PATH, "w") as f:
        json.dump({
            "results": results,
            "score_data": score_data,
            "drift": drift,
            "profile_name": profile_name,
        }, f)


def load_scan_cache(current_profile):
    """Load cache only if it belongs to the current profile."""
    try:
        with open(SCAN_CACHE_PATH, "r") as f:
            data = json.load(f)
        # Only return cache if it matches the active profile
        if data.get("profile_name", "").strip() == current_profile.strip():
            return data
        return None
    except Exception:
        return None


def clear_scan_cache():
    try:
        if os.path.exists(SCAN_CACHE_PATH):
            os.remove(SCAN_CACHE_PATH)
    except Exception:
        pass


def merge_scan_output(scan_output, signals, resources_map):
    signals.update(scan_output.get("signals", {}))
    for key, value in scan_output.get("resources", {}).items():
        if key not in resources_map:
            resources_map[key] = []
        resources_map[key].extend(value)


def run_scan(profile_name, access_key, secret_key, region_name):
    """Run a full scan with explicit credentials — no session dependency."""
    signals = {}
    resources_map = {}

    for scanner in [get_s3_signals, get_iam_signals, get_network_signals,
                get_ssm_signals, get_guardduty_signals]:
        merge_scan_output(
            scanner(
                profile_name=profile_name or None,
                access_key=access_key or None,
                secret_key=secret_key or None,
                region_name=region_name or "eu-west-2",
            ),
            signals,
            resources_map,
        )

    previous_signals = load_previous_state(profile_name)
    drift = detect_drift(previous_signals, signals)
    controls = load_controls()
    results = evaluate_controls(signals, controls, resources_map)
    score_data = calculate_compliance_score(results)
    save_current_state(signals, profile_name)
    generate_control_pdf(results, score_data)

    return results, score_data, drift


@app.route("/download-pdf")
def download_pdf():
    current_profile = session.get("profile_name", "")
    cache = load_scan_cache(current_profile)
    if cache:
        generate_control_pdf(cache["results"], cache["score_data"])
    pdf_path = "backend/reports/cloudguardian_evidence_pack.pdf"
    return send_file(pdf_path, as_attachment=True)


@app.route("/", methods=["GET", "POST"])
def index():
    response = None
    error = None

    if request.method == "POST":
        action = request.form.get("action")

        # ── Save connection ────────────────────────────────────────
        if action == "set_connection":
            profile_name = request.form.get("profile_name", "").strip()
            access_key   = request.form.get("access_key",   "").strip()
            secret_key   = request.form.get("secret_key",   "").strip()
            region_name  = request.form.get("region_name",  "").strip() or "eu-west-2"

            session.clear()
            session.modified = True
            session["profile_name"] = profile_name
            session["access_key"]   = access_key
            session["secret_key"]   = secret_key
            session["region_name"]  = region_name
            clear_scan_cache()

        # ── Run scan ───────────────────────────────────────────────
        elif action == "scan":
            profile_name = session.get("profile_name", "").strip()
            access_key   = session.get("access_key",   "").strip()
            secret_key   = session.get("secret_key",   "").strip()
            region_name  = session.get("region_name",  "eu-west-2").strip()

            try:
                results, score_data, drift = run_scan(
                    profile_name, access_key, secret_key, region_name
                )
                save_scan_cache(results, score_data, drift, profile_name)
            except Exception as e:
                error = f"Scan failed: {str(e)}"

        # ── Ask question ───────────────────────────────────────────
        elif action == "ask":
            query = request.form.get("query", "").strip()
            current_profile = session.get("profile_name", "").strip()
            cache = load_scan_cache(current_profile)
            if cache:
                try:
                    response = handle_query(
                        query,
                        cache["results"],
                        cache["drift"],
                        cache["score_data"],
                    )
                    response = markdown.markdown(response)
                except Exception as e:
                    error = f"Query failed: {str(e)}"
            else:
                error = "Please run a compliance scan first before asking questions."

    # ── Render ─────────────────────────────────────────────────────
    current_profile = session.get("profile_name", "").strip()
    cache = load_scan_cache(current_profile)

    results    = cache["results"]    if cache else {}
    score_data = cache["score_data"] if cache else None
    drift      = cache["drift"]      if cache else []

    return render_template(
        "index.html",
        results=results,
        score_data=score_data,
        drift=drift,
        response=response,
        error=error,
        current_profile=current_profile,
        current_access_key=session.get("access_key", ""),
        current_region=session.get("region_name", "eu-west-2"),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
