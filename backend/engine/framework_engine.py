import yaml


def load_controls(path="backend/mappings/framework_controls.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)["controls"]


def evaluate_controls(signals, controls):
    results = {}

    for control_id, control in controls.items():
        required_signals = control.get("requires", [])
        logic = control.get("logic")

        triggered_signals = []
        signal_states = {}

        for sig in required_signals:
            value = signals.get(sig, False)
            signal_states[sig] = value
            if value is True:
                triggered_signals.append(sig)

        if logic == "ALL":
            status = all(not signals.get(sig, False) for sig in required_signals)
        elif logic == "ANY_FAIL":
            status = not any(signals.get(sig, False) for sig in required_signals)
        else:
            status = False

        results[control_id] = {
            "name": control["name"],
            "status": "PASS" if status else "FAIL",
            "severity": control.get("severity", "MEDIUM"),
            "weight": control.get("weight", 0),
            "signals_checked": required_signals,
            "triggered_signals": triggered_signals,
            "signal_states": signal_states,
            "plain_english_fail": control.get("plain_english_fail", ""),
            "risk": control.get("risk", ""),
            "recommendation": control.get("recommendation", "")
        }

    return results


def calculate_compliance_score(results):
    total_weight = sum(item.get("weight", 0) for item in results.values())
    passed_weight = sum(
        item.get("weight", 0) for item in results.values() if item["status"] == "PASS"
    )

    if total_weight == 0:
        score = 0
    else:
        score = round((passed_weight / total_weight) * 100, 2)

    failed_high = any(
        item["status"] == "FAIL" and item.get("severity") == "HIGH"
        for item in results.values()
    )
    failed_medium = any(
        item["status"] == "FAIL" and item.get("severity") == "MEDIUM"
        for item in results.values()
    )

    if failed_high:
        risk_level = "HIGH"
    elif failed_medium:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "score": score,
        "risk_level": risk_level
    }
