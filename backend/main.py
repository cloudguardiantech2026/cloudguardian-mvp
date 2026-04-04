from scanners.aws_s3 import get_s3_signals
from scanners.aws_iam import get_iam_signals
from scanners.aws_network import get_network_signals
from engine.framework_engine import load_controls, evaluate_controls

signals = {}

signals.update(get_s3_signals(profile_name="cloudguardian-demo"))
signals.update(get_iam_signals(profile_name="cloudguardian-demo"))
signals.update(get_network_signals(profile_name="cloudguardian-demo", region_name="eu-west-2"))

print("\n=== Signals Collected ===")
for key, value in signals.items():
    print(f"{key}: {value}")

controls = load_controls()
results = evaluate_controls(signals, controls)

print("\n=== Compliance Results ===\n")
for cid, data in results.items():
    print(f"{cid} - {data['name']}: {data['status']}")

    if data["status"] == "FAIL":
        print(f"  Reason: {data['plain_english_fail']}")
        print(f"  Risk: {data['risk']}")
        print(f"  Recommendation: {data['recommendation']}")
        print(f"  Triggered Signals: {data['triggered_signals']}")
        print()
