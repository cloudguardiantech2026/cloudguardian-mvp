import json
import os

STATE_FILE = "backend/state/last_snapshot.json"


def load_previous_state():
    if not os.path.exists(STATE_FILE):
        return {}

    if os.path.getsize(STATE_FILE) == 0:
        return {}

    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def save_current_state(signals):
    with open(STATE_FILE, "w") as f:
        json.dump(signals, f, indent=2)


def detect_drift(old_signals, new_signals):
    drift_results = []

    all_keys = set(old_signals.keys()).union(new_signals.keys())

    for key in all_keys:
        old_val = old_signals.get(key)
        new_val = new_signals.get(key)

        if old_val != new_val:
            if old_val is False and new_val is True:
                drift_results.append({
                    "type": "NEW_RISK",
                    "signal": key,
                    "from": old_val,
                    "to": new_val
                })
            elif old_val is True and new_val is False:
                drift_results.append({
                    "type": "RESOLVED",
                    "signal": key,
                    "from": old_val,
                    "to": new_val
                })
            else:
                drift_results.append({
                    "type": "CHANGED",
                    "signal": key,
                    "from": old_val,
                    "to": new_val
                })

    return drift_results
