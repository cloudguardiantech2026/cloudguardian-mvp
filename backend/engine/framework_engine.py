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
            "signals_checked": required_signals,
            "triggered_signals": triggered_signals,
            "signal_states": signal_states,
            "plain_english_fail": control.get("plain_english_fail", ""),
            "risk": control.get("risk", ""),
            "recommendation": control.get("recommendation", "")
        }

    return results
