import json
import os
import markdown
from flask import Flask, render_template, request, send_file, session, jsonify

from backend.scanners.aws_s3 import get_s3_signals
from backend.scanners.aws_iam import get_iam_signals
from backend.scanners.aws_network import get_network_signals
from backend.scanners.aws_ssm import get_ssm_signals
from backend.scanners.aws_guardduty import get_guardduty_signals

from backend.scanners.azure.azure_ce1_firewall import scan as azure_ce1
from backend.scanners.azure.azure_ce2_secure_config import scan as azure_ce2
from backend.scanners.azure.azure_ce3_access_control import scan as azure_ce3
from backend.scanners.azure.azure_ce4_malware import scan as azure_ce4
from backend.scanners.azure.azure_ce5_patching import scan as azure_ce5

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


# ── Cache helpers ──────────────────────────────────────────────────────────────

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
    try:
        with open(SCAN_CACHE_PATH, "r") as f:
            data = json.load(f)
        if data.get("profile_name", "").strip() == current_profile.strip():
            return data
        return None
    except Exception:
        return None


def save_azure_cache(azure_results, azure_score_data):
    """Store Azure results separately so they survive alongside AWS cache."""
    path = "backend/state/azure_cache.json"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump({
            "azure_results": azure_results,
            "azure_score_data": azure_score_data,
        }, f)


def load_azure_cache():
    try:
        with open("backend/state/azure_cache.json", "r") as f:
            return json.load(f)
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


# ── Azure score + LLM helpers ──────────────────────────────────────────────────

def calculate_azure_score(azure_results):
    """
    Convert flat Azure results list into a score_data dict
    compatible with the existing score/risk shape.
    """
    total = len(azure_results)
    if total == 0:
        return {
            "score": 0,
            "risk_level": "UNKNOWN",
            "auto_fail_triggered": False,
            "certification_status": "No Azure results — run a scan first",
        }

    passed = sum(1 for r in azure_results if r.get("status") == "PASS")
    failed = sum(1 for r in azure_results if r.get("status") == "FAIL")
    warned = sum(1 for r in azure_results if r.get("status") == "WARN")
    score  = round((passed / total) * 100, 2)

    # CE3 MFA FAIL is an auto-fail under CE v3.3 Danzell
    auto_fail = any(
        r.get("status") == "FAIL" and "CE3" in r.get("control", "")
        for r in azure_results
    )

    if auto_fail:
        risk_level  = "HIGH"
        cert_status = "CERTIFICATION BLOCKED — MFA auto-fail condition present"
    elif failed > 0:
        risk_level  = "HIGH"
        cert_status = "NOT READY — failing controls present"
    elif warned > 0:
        risk_level  = "MEDIUM"
        cert_status = "NEEDS IMPROVEMENT — warnings present"
    else:
        risk_level  = "LOW"
        cert_status = "READY — no blocking issues detected"

    return {
        "score": score,
        "risk_level": risk_level,
        "auto_fail_triggered": auto_fail,
        "certification_status": cert_status,
    }


def azure_results_for_llm(azure_results):
    """
    Convert flat Azure list into the dict shape handle_query() expects.
    Mirrors the AWS results dict structure.
    """
    out = {}
    for r in azure_results:
        key = f"{r.get('control', 'unknown')}_{r.get('resource', 'unknown')}"
        out[key] = {
            "name":              r.get("control", ""),
            "status":            r.get("status", "UNKNOWN"),
            "severity":          "HIGH" if r.get("status") == "FAIL" else "MEDIUM",
            "weight":            20,
            "auto_fail":         "CE3" in r.get("control", "") and r.get("status") == "FAIL",
            "signals_checked":   [],
            "triggered_signals": [],
            "signal_states":     {},
            "affected_resources": [r.get("resource", "")] if r.get("resource") else [],
            "plain_english_fail": r.get("detail", ""),
            "risk":              r.get("detail", ""),
            "recommendation":    "",
            "framework_mappings": {},
        }
    return out


def generate_azure_pdf(azure_results, azure_score_data):
    """Generate a PDF evidence pack from Azure results."""
    llm_shaped = azure_results_for_llm(azure_results)
    generate_control_pdf(llm_shaped, azure_score_data)


# ── AWS scan ───────────────────────────────────────────────────────────────────

def run_scan(profile_name, access_key, secret_key, region_name):
    signals      = {}
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
    drift            = detect_drift(previous_signals, signals)
    controls         = load_controls()
    results          = evaluate_controls(signals, controls, resources_map)
    score_data       = calculate_compliance_score(results)
    save_current_state(signals, profile_name)
    generate_control_pdf(results, score_data)
    return results, score_data, drift


# ── Azure scan ─────────────────────────────────────────────────────────────────

def run_azure_scan(tenant_id, client_id, client_secret, subscription_id):
    os.environ["AZURE_TENANT_ID"]       = tenant_id
    os.environ["AZURE_CLIENT_ID"]       = client_id
    os.environ["AZURE_CLIENT_SECRET"]   = client_secret
    os.environ["AZURE_SUBSCRIPTION_ID"] = subscription_id

    results = []
    for scanner in [azure_ce1, azure_ce2, azure_ce3, azure_ce4, azure_ce5]:
        try:
            results.extend(scanner())
        except Exception as e:
            results.append({
                "provider": "azure",
                "control":  scanner.__name__,
                "resource": "scanner",
                "status":   "ERROR",
                "detail":   str(e),
            })
    return results


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/download-pdf")
def download_pdf():
    current_profile = session.get("profile_name", "")
    cache = load_scan_cache(current_profile)
    if cache:
        generate_control_pdf(cache["results"], cache["score_data"])
    pdf_path = "backend/reports/cloudguardian_evidence_pack.pdf"
    return send_file(pdf_path, as_attachment=True)


@app.route("/download-pdf/azure")
def download_pdf_azure():
    cache = load_azure_cache()
    if not cache:
        return "No Azure scan results found. Run an Azure scan first.", 404
    generate_azure_pdf(cache["azure_results"], cache["azure_score_data"])
    pdf_path = "backend/reports/cloudguardian_evidence_pack.pdf"
    return send_file(pdf_path, as_attachment=True,
                     download_name="cloudguardian_azure_evidence_pack.pdf")


@app.route("/scan/azure", methods=["POST"])
def scan_azure():
    data            = request.get_json(silent=True) or {}
    tenant_id       = data.get("tenant_id",       "").strip()
    client_id       = data.get("client_id",       "").strip()
    client_secret   = data.get("client_secret",   "").strip()
    subscription_id = data.get("subscription_id", "").strip()

    if not all([tenant_id, client_id, client_secret, subscription_id]):
        return jsonify({"error": "All four Azure credentials are required."}), 400

    try:
        azure_results    = run_azure_scan(tenant_id, client_id, client_secret, subscription_id)
        azure_score_data = calculate_azure_score(azure_results)
        save_azure_cache(azure_results, azure_score_data)
        return jsonify({
            "provider":   "azure",
            "results":    azure_results,
            "score_data": azure_score_data,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/ask/azure", methods=["POST"])
def ask_azure():
    data  = request.get_json(silent=True) or {}
    query = data.get("query", "").strip()

    if not query:
        return jsonify({"error": "No query provided."}), 400

    cache = load_azure_cache()
    if not cache:
        return jsonify({"error": "No Azure scan results found. Run an Azure scan first."}), 404

    try:
        llm_results = azure_results_for_llm(cache["azure_results"])
        response    = handle_query(query, llm_results, [], cache["azure_score_data"])
        return jsonify({"response": markdown.markdown(response)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/", methods=["GET", "POST"])
def index():
    response = None
    error    = None

    if request.method == "POST":
        action = request.form.get("action")

        if action == "set_connection":
            profile_name = request.form.get("profile_name", "").strip()
            access_key   = request.form.get("access_key",   "").strip()
            secret_key   = request.form.get("secret_key",   "").strip()
            region_name  = request.form.get("region_name",  "").strip() or "eu-west-2"

            session.clear()
            session.modified        = True
            session["profile_name"] = profile_name
            session["access_key"]   = access_key
            session["secret_key"]   = secret_key
            session["region_name"]  = region_name
            clear_scan_cache()

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

        elif action == "ask":
            query           = request.form.get("query", "").strip()
            current_profile = session.get("profile_name", "").strip()
            cache           = load_scan_cache(current_profile)

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

    current_profile = session.get("profile_name", "").strip()
    cache           = load_scan_cache(current_profile)
    results         = cache["results"]    if cache else {}
    score_data      = cache["score_data"] if cache else None
    drift           = cache["drift"]      if cache else []

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
