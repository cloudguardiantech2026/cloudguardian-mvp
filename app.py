import json
import os
import base64
import secrets
import markdown
import requests

from flask import Flask, render_template, request, send_file, send_from_directory, session, jsonify, Response, redirect
from urllib.parse import urlencode, quote
from botocore.exceptions import ClientError

from backend.db.customer_db import generate_external_id, create_customer

from backend.scanners.aws_s3        import get_s3_signals
from backend.scanners.aws_iam       import get_iam_signals
from backend.scanners.aws_network   import get_network_signals
from backend.scanners.aws_ssm       import get_ssm_signals
from backend.scanners.aws_guardduty import get_guardduty_signals

from backend.scanners.azure.azure_ce1_firewall       import scan as azure_ce1
from backend.scanners.azure.azure_ce2_secure_config  import scan as azure_ce2
from backend.scanners.azure.azure_ce3_access_control import scan as azure_ce3
from backend.scanners.azure.azure_ce4_malware        import scan as azure_ce4
from backend.scanners.azure.azure_ce5_patching       import scan as azure_ce5

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

# Azure OAuth constants
AZURE_CLIENT_ID     = os.environ.get("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")
AZURE_REDIRECT_URI  = "https://cloudguardian-mvp.onrender.com/connect/azure/callback"
AZURE_SCOPES        = "https://management.azure.com/user_impersonation offline_access openid profile"

CF_TEMPLATE_URL      = "https://cloudguardian-templates.s3.eu-west-2.amazonaws.com/cloudguardian_aws.yaml"
CF_QUICK_CREATE_BASE = "https://console.aws.amazon.com/cloudformation/home#/stacks/create/review"


def save_scan_cache(results, score_data, drift, role_arn):
    os.makedirs(os.path.dirname(SCAN_CACHE_PATH), exist_ok=True)
    with open(SCAN_CACHE_PATH, "w") as f:
        json.dump({"results": results, "score_data": score_data, "drift": drift, "role_arn": role_arn}, f)

def load_scan_cache(current_role_arn):
    try:
        with open(SCAN_CACHE_PATH, "r") as f:
            data = json.load(f)
        if data.get("role_arn", "").strip() == current_role_arn.strip():
            return data
        return None
    except Exception:
        return None

def save_azure_cache(azure_results, azure_score_data):
    path = "backend/state/azure_cache.json"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump({"azure_results": azure_results, "azure_score_data": azure_score_data}, f)

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

def calculate_azure_score(azure_results):
    total = len(azure_results)
    if total == 0:
        return {"score": 0, "risk_level": "UNKNOWN", "auto_fail_triggered": False,
                "certification_status": "No Azure results — run a scan first"}
    passed    = sum(1 for r in azure_results if r.get("status") == "PASS")
    failed    = sum(1 for r in azure_results if r.get("status") == "FAIL")
    warned    = sum(1 for r in azure_results if r.get("status") == "WARN")
    score     = round((passed / total) * 100, 2)
    auto_fail = any(r.get("status") == "FAIL" and "CE3" in r.get("control", "") for r in azure_results)
    if auto_fail:
        risk_level, cert_status = "HIGH", "CERTIFICATION BLOCKED — MFA auto-fail condition present"
    elif failed > 0:
        risk_level, cert_status = "HIGH", "NOT READY — failing controls present"
    elif warned > 0:
        risk_level, cert_status = "MEDIUM", "NEEDS IMPROVEMENT — warnings present"
    else:
        risk_level, cert_status = "LOW", "READY — no blocking issues detected"
    return {"score": score, "risk_level": risk_level, "auto_fail_triggered": auto_fail,
            "certification_status": cert_status}

def azure_results_for_llm(azure_results):
    out = {}
    for i, r in enumerate(azure_results):
        key = f"{r.get('control', 'unknown')}_{i:03d}"
        out[key] = {
            "name": r.get("control", ""), "status": r.get("status", "UNKNOWN"),
            "severity": "HIGH" if r.get("status") == "FAIL" else "MEDIUM",
            "weight": 20, "auto_fail": "CE3" in r.get("control", "") and r.get("status") == "FAIL",
            "signals_checked": [], "triggered_signals": [], "signal_states": {},
            "affected_resources": [r.get("resource", "")] if r.get("resource") else [],
            "plain_english_fail": r.get("detail", ""), "risk": r.get("detail", ""),
            "recommendation": "", "framework_mappings": {},
        }
    return out

def generate_azure_pdf(azure_results, azure_score_data):
    llm_shaped = azure_results_for_llm(azure_results)
    generate_control_pdf(llm_shaped, azure_score_data, provider="Azure")

def run_scan(role_arn: str, external_id: str, region_name: str = "eu-west-2"):
    signals, resources_map = {}, {}
    for scanner in [get_s3_signals, get_iam_signals, get_network_signals,
                    get_ssm_signals, get_guardduty_signals]:
        merge_scan_output(scanner(role_arn=role_arn, external_id=external_id,
                                  region_name=region_name), signals, resources_map)
    previous_signals = load_previous_state(role_arn)
    drift            = detect_drift(previous_signals, signals)
    controls         = load_controls()
    results          = evaluate_controls(signals, controls, resources_map)
    score_data       = calculate_compliance_score(results)
    save_current_state(signals, role_arn)
    generate_control_pdf(results, score_data, provider="AWS")
    return results, score_data, drift

def run_azure_scan(tenant_id: str, subscription_id: str):
    """
    Runs Azure CE scanners using CloudGuardian platform credentials
    scoped to the customer tenant via OAuth consent.
    """
    os.environ["AZURE_TENANT_ID"]       = tenant_id
    os.environ["AZURE_CLIENT_ID"]       = os.environ.get("AZURE_CLIENT_ID", "")
    os.environ["AZURE_CLIENT_SECRET"]   = os.environ.get("AZURE_CLIENT_SECRET", "")
    os.environ["AZURE_SUBSCRIPTION_ID"] = subscription_id
    results = []
    for scanner in [azure_ce1, azure_ce2, azure_ce3, azure_ce4, azure_ce5]:
        try:
            results.extend(scanner())
        except Exception as e:
            results.append({"provider": "azure", "control": scanner.__name__,
                            "resource": "scanner", "status": "ERROR", "detail": str(e)})
    return results


# ── Static pages ───────────────────────────────────────────────────────────────

@app.route("/")
def landing():
    return send_from_directory("templates", "landing.html")

@app.route("/privacy")
def privacy():
    return send_from_directory("templates", "privacy.html")


# ── AWS onboarding ─────────────────────────────────────────────────────────────

@app.route("/connect/aws")
def connect_aws():
    external_id = generate_external_id()
    create_customer(external_id)
    session["external_id"] = external_id
    params = {
        "templateURL":                   CF_TEMPLATE_URL,
        "stackName":                     "CloudGuardian-Audit-Stack",
        "param_CloudGuardianExternalId": external_id,
    }
    return redirect(f"{CF_QUICK_CREATE_BASE}?{urlencode(params)}")

@app.route("/connect/aws/id")
def connect_aws_id():
    return jsonify({"external_id": session.get("external_id", "")})

@app.route("/verify/aws", methods=["POST"])
def verify_aws():
    from backend.scanners.aws_auth import build_session
    data        = request.get_json(silent=True) or {}
    role_arn    = data.get("role_arn",    "").strip()
    external_id = data.get("external_id", "").strip()
    if not role_arn or not external_id:
        return jsonify({"success": False, "error": "Role ARN and External ID are required."}), 400
    try:
        session_obj = build_session(role_arn, external_id)
        session_obj.client("iam").get_account_summary()
        return jsonify({"success": True})
    except RuntimeError as e:
        return jsonify({"success": False, "error": str(e)})
    except ClientError as e:
        return jsonify({"success": False, "error": e.response["Error"]["Message"]})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ── Azure OAuth onboarding ─────────────────────────────────────────────────────

@app.route("/connect/azure")
def connect_azure():
    """
    Redirects customer to Microsoft OAuth2 consent screen.
    One click — no scripts, no terminal, no credentials to paste.
    """
    state = secrets.token_urlsafe(32)
    session["azure_oauth_state"] = state
    params = {
        "client_id":     AZURE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri":  AZURE_REDIRECT_URI,
        "scope":         AZURE_SCOPES,
        "state":         state,
        "prompt":        "select_account",
    }
    return redirect(f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{urlencode(params)}")

@app.route("/connect/azure/callback")
def connect_azure_callback():
    """
    OAuth2 callback — exchanges auth code for tokens, extracts tenant ID,
    discovers subscriptions automatically.
    """
    state = request.args.get("state", "")
    if state != session.get("azure_oauth_state", ""):
        return "Invalid state parameter. Please try connecting again.", 400

    error = request.args.get("error")
    if error:
        return redirect(f"/dashboard?azure_error={quote(request.args.get('error_description', error))}&tab=azure")

    code = request.args.get("code")
    if not code:
        return redirect("/dashboard?azure_error=No+authorisation+code+received&tab=azure")

    token_resp = requests.post(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        data={
            "client_id":     AZURE_CLIENT_ID,
            "client_secret": AZURE_CLIENT_SECRET,
            "code":          code,
            "redirect_uri":  AZURE_REDIRECT_URI,
            "grant_type":    "authorization_code",
            "scope":         AZURE_SCOPES,
        },
        timeout=30,
    )
    token_json = token_resp.json()

    if "error" in token_json:
        msg = token_json.get("error_description", token_json.get("error", "Token exchange failed"))
        return redirect(f"/dashboard?azure_error={quote(msg)}&tab=azure")

    access_token  = token_json.get("access_token", "")
    refresh_token = token_json.get("refresh_token", "")

    # Extract tenant ID from JWT payload
    try:
        payload_b64 = access_token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload   = json.loads(base64.urlsafe_b64decode(payload_b64))
        tenant_id = payload.get("tid", "")
    except Exception:
        tenant_id = ""

    if not tenant_id:
        return redirect("/dashboard?azure_error=Could+not+determine+tenant+ID&tab=azure")

    session["azure_tenant_id"]     = tenant_id
    session["azure_access_token"]  = access_token
    session["azure_refresh_token"] = refresh_token
    session["azure_connected"]     = True

    # Auto-discover subscriptions
    try:
        subs = requests.get(
            "https://management.azure.com/subscriptions?api-version=2022-12-01",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        ).json().get("value", [])
        session["azure_subscription_id"] = subs[0]["subscriptionId"] if subs else ""
        session["azure_subscriptions"]   = [
            {"id": s["subscriptionId"], "name": s.get("displayName", s["subscriptionId"])}
            for s in subs
        ]
    except Exception:
        session["azure_subscription_id"] = ""
        session["azure_subscriptions"]   = []

    return redirect("/dashboard?tab=azure&azure_connected=1")

@app.route("/connect/azure/status")
def connect_azure_status():
    return jsonify({
        "connected":       session.get("azure_connected", False),
        "tenant_id":       session.get("azure_tenant_id", ""),
        "subscription_id": session.get("azure_subscription_id", ""),
        "subscriptions":   session.get("azure_subscriptions", []),
    })

@app.route("/connect/azure/disconnect")
def connect_azure_disconnect():
    for key in ["azure_tenant_id", "azure_access_token", "azure_refresh_token",
                "azure_connected", "azure_subscription_id", "azure_subscriptions",
                "azure_oauth_state"]:
        session.pop(key, None)
    return redirect("/dashboard?tab=azure")


# ── Scan routes ────────────────────────────────────────────────────────────────

@app.route("/scan/azure", methods=["POST"])
def scan_azure():
    tenant_id       = session.get("azure_tenant_id", "").strip()
    subscription_id = session.get("azure_subscription_id", "").strip()

    data = request.get_json(silent=True) or {}
    if data.get("subscription_id"):
        subscription_id = data["subscription_id"].strip()
        session["azure_subscription_id"] = subscription_id

    if not tenant_id:
        return jsonify({"error": "Azure account not connected. Please click 'Connect Azure Account' first."}), 400
    if not subscription_id:
        return jsonify({"error": "No Azure subscription found. Please reconnect your Azure account."}), 400

    try:
        azure_results    = run_azure_scan(tenant_id, subscription_id)
        azure_score_data = calculate_azure_score(azure_results)
        save_azure_cache(azure_results, azure_score_data)
        return jsonify({"provider": "azure", "results": azure_results, "score_data": azure_score_data})
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
        response = handle_query(query, azure_results_for_llm(cache["azure_results"]),
                                [], cache["azure_score_data"])
        return jsonify({"response": markdown.markdown(response)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PDF downloads ──────────────────────────────────────────────────────────────

@app.route("/download-pdf")
def download_pdf():
    current_role_arn = session.get("role_arn", "")
    cache = load_scan_cache(current_role_arn)
    if cache:
        generate_control_pdf(cache["results"], cache["score_data"], provider="AWS")
    return send_file("backend/reports/cloudguardian_evidence_pack.pdf",
                     as_attachment=True, download_name="cloudguardian_aws_evidence_pack.pdf")

@app.route("/download-pdf/azure")
def download_pdf_azure():
    cache = load_azure_cache()
    if not cache:
        return "No Azure scan results found. Run an Azure scan first.", 404
    generate_azure_pdf(cache["azure_results"], cache["azure_score_data"])
    return send_file("backend/reports/cloudguardian_evidence_pack.pdf",
                     as_attachment=True, download_name="cloudguardian_azure_evidence_pack.pdf")

@app.route("/download-pdf/ce-prep")
def download_pdf_ce_prep():
    current_role_arn = session.get("role_arn", "")
    cache = load_scan_cache(current_role_arn)
    if not cache:
        return "No AWS scan results found. Run a scan first.", 404
    from backend.reports.pdf_generator import generate_ce_prep_report
    generate_ce_prep_report(cache["results"], cache["score_data"], provider="AWS")
    return send_file("backend/reports/cloudguardian_ce_prep_report.pdf",
                     as_attachment=True, download_name="cloudguardian_ce_prep_report_aws.pdf")

@app.route("/download-pdf/ce-prep/azure")
def download_pdf_ce_prep_azure():
    cache = load_azure_cache()
    if not cache:
        return "No Azure scan results found. Run an Azure scan first.", 404
    from backend.reports.pdf_generator import generate_ce_prep_report
    llm_shaped = azure_results_for_llm(cache["azure_results"])
    generate_ce_prep_report(llm_shaped, cache["azure_score_data"], provider="Azure")
    return send_file("backend/reports/cloudguardian_ce_prep_report.pdf",
                     as_attachment=True, download_name="cloudguardian_ce_prep_report_azure.pdf")


# ── Dashboard ──────────────────────────────────────────────────────────────────

@app.route("/dashboard", methods=["GET", "POST"])
def index():
    response    = None
    error       = None
    azure_error = request.args.get("azure_error", "")
    if azure_error:
        error = f"Azure connection failed: {azure_error}"

    if request.method == "POST":
        action = request.form.get("action")

        if action == "set_connection":
            role_arn    = request.form.get("role_arn",    "").strip()
            external_id = request.form.get("external_id", "").strip()
            region_name = request.form.get("region_name", "").strip() or "eu-west-2"

            # Preserve Azure session when updating AWS connection
            azure_keys = {k: session[k] for k in [
                "azure_tenant_id", "azure_access_token", "azure_refresh_token",
                "azure_connected", "azure_subscription_id", "azure_subscriptions",
            ] if k in session}

            session.clear()
            session.modified       = True
            session["role_arn"]    = role_arn
            session["external_id"] = external_id
            session["region_name"] = region_name
            session.update(azure_keys)
            clear_scan_cache()

        elif action == "scan":
            role_arn    = session.get("role_arn",    "").strip()
            external_id = session.get("external_id", "").strip()
            region_name = session.get("region_name", "eu-west-2").strip()
            if not role_arn or not external_id:
                error = "AWS Role ARN and External ID are required. Please connect your AWS account first."
            else:
                try:
                    results, score_data, drift = run_scan(role_arn, external_id, region_name)
                    save_scan_cache(results, score_data, drift, role_arn)
                except Exception as e:
                    error = f"Scan failed: {str(e)}"

        elif action == "ask":
            query            = request.form.get("query", "").strip()
            current_role_arn = session.get("role_arn", "").strip()
            cache            = load_scan_cache(current_role_arn)
            if cache:
                try:
                    response = markdown.markdown(handle_query(
                        query, cache["results"], cache["drift"], cache["score_data"]
                    ))
                except Exception as e:
                    error = f"Query failed: {str(e)}"
            else:
                error = "Please run a compliance scan first before asking questions."

    current_role_arn = session.get("role_arn", "").strip()
    cache            = load_scan_cache(current_role_arn)

    return render_template(
        "index.html",
        results=cache["results"]    if cache else {},
        score_data=cache["score_data"] if cache else None,
        drift=cache["drift"]        if cache else [],
        response=response,
        error=error,
        current_role_arn=current_role_arn,
        current_region=session.get("region_name", "eu-west-2"),
        azure_connected=session.get("azure_connected", False),
        azure_tenant_id=session.get("azure_tenant_id", ""),
        azure_subscription_id=session.get("azure_subscription_id", ""),
        azure_subscriptions=session.get("azure_subscriptions", []),
    )


# ── Invite ─────────────────────────────────────────────────────────────────────

@app.route("/invite/it-provider", methods=["POST"])
def invite_it_provider():
    data          = request.get_json(silent=True) or {}
    email         = data.get("email",         "").strip()
    business_name = data.get("business_name", "").strip()
    client_token  = data.get("client_token",  "").strip()
    if not email or "@" not in email:
        return jsonify({"success": False, "error": "Invalid email"}), 400
    dashboard_link = f"https://cloudguardian-mvp.onrender.com/dashboard?client={client_token}"
    print(f"[INVITE] To: {email} | Business: {business_name or 'unknown'} | Link: {dashboard_link}")
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)