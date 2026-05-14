import yaml

def load_controls(path="backend/mappings/framework_controls.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)["controls"]

def evaluate_controls(signals, controls, resources_map=None):
    if resources_map is None:
        resources_map = {}

    results = {}

    for control_id, control in controls.items():
        required_signals = control.get("requires", [])
        logic = control.get("logic")
        triggered_signals = []
        signal_states = {}
        affected_resources = []

        for sig in required_signals:
            value = signals.get(sig, False)
            signal_states[sig] = value
            if value is True:
                triggered_signals.append(sig)
                affected_resources.extend(resources_map.get(sig, []))

        if logic == "ALL":
            status = all(not signals.get(sig, False) for sig in required_signals)
        elif logic == "ANY_FAIL":
            status = not any(signals.get(sig, False) for sig in required_signals)
        else:
            status = False

        auto_fail = control.get("auto_fail", False)
        is_fail = not status

        results[control_id] = {
            "name": control["name"],
            "status": "PASS" if status else "FAIL",
            "severity": control.get("severity", "MEDIUM"),
            "weight": control.get("weight", 0),
            "auto_fail": auto_fail and is_fail,
            "signals_checked": required_signals,
            "triggered_signals": triggered_signals,
            "signal_states": signal_states,
            "affected_resources": sorted(list(set(affected_resources))),
            "plain_english_fail": control.get("plain_english_fail", ""),
            "risk": control.get("risk", ""),
            "recommendation": control.get("recommendation", ""),
            "framework_mappings": control.get("framework_mappings", {})
        }

    return results

def calculate_compliance_score(results):
    total_weight = sum(item.get("weight", 0) for item in results.values())
    passed_weight = sum(
        item.get("weight", 0) for item in results.values()
        if item["status"] == "PASS"
    )

    if total_weight == 0:
        score = 0
    else:
        score = round((passed_weight / total_weight) * 100, 2)

    auto_fail_triggered = any(
        item.get("auto_fail", False) for item in results.values()
    )

    failed_high = any(
        item["status"] == "FAIL" and item.get("severity") == "HIGH"
        for item in results.values()
    )

    failed_medium = any(
        item["status"] == "FAIL" and item.get("severity") == "MEDIUM"
        for item in results.values()
    )

    if auto_fail_triggered:
        risk_level = "HIGH"
        certification_status = "CERTIFICATION BLOCKED — auto-fail condition present"
    elif failed_high:
        risk_level = "HIGH"
        certification_status = "NOT READY — high severity issues present"
    elif failed_medium:
        risk_level = "MEDIUM"
        certification_status = "NEEDS IMPROVEMENT — medium severity issues present"
    else:
        risk_level = "LOW"
        certification_status = "READY — no blocking issues detected"

    return {
        "score": score,
        "risk_level": risk_level,
        "auto_fail_triggered": auto_fail_triggered,
        "certification_status": certification_status
    }
