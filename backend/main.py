from engine.conversation_engine import handle_query
from engine.drift_engine import load_previous_state, save_current_state, detect_drift
from scanners.aws_s3 import get_s3_signals
from scanners.aws_iam import get_iam_signals
from scanners.aws_network import get_network_signals
from engine.framework_engine import load_controls, evaluate_controls
from reports.pdf_generator import generate_control_pdf


signals = {}

signals.update(get_s3_signals(profile_name="cloudguardian-demo"))
signals.update(get_iam_signals(profile_name="cloudguardian-demo"))
signals.update(get_network_signals(profile_name="cloudguardian-demo", region_name="eu-west-2"))
previous_signals = load_previous_state()
drift = detect_drift(previous_signals, signals)

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

print("\n=== Drift Detection ===\n")

if not drift:
    print("No changes detected since last scan.")
else:
    for change in drift:
        print(f"{change['type']}: {change['signal']} changed from {change['from']} → {change['to']}")

pdf_path = generate_control_pdf(results)
print(f"\nEvidence pack generated: {pdf_path}")

print("\n=== Conversational Compliance Engine ===")
print("Type 'help' for available commands. Type 'exit' to quit.\n")

while True:
    user_query = input("CloudGuardian> ").strip()
    if user_query.lower() == "exit":
        print("Exiting CloudGuardian conversation.")
        break

    response = handle_query(user_query, results, drift)
    print("\n" + response + "\n")

save_current_state(signals)
