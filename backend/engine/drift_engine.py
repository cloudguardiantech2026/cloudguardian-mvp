import json
import os
import re

STATE_DIR = "backend/state"


def _state_file(profile_name="default"):
    safe = re.sub(r'[^a-zA-Z0-9_\-]', '_', profile_name or "default")
    return os.path.join(STATE_DIR, f"snapshot_{safe}.json")


def load_previous_state(profile_name="default"):
    path = _state_file(profile_name)
    if not os.path.exists(path):
        return {}
    if os.path.getsize(path) == 0:
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def save_current_state(signals, profile_name="default"):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(_state_file(profile_name), "w") as f:
        json.dump(signals, f, indent=2)


def detect_drift(old_signals, new_signals):
    drift_results = []
    all_keys = set(old_signals.keys()).union(new_signals.keys())
    for key in all_keys:
        old_val = old_signals.get(key, False)
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