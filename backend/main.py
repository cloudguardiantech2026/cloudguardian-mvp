import os
import argparse
parser = argparse.ArgumentParser(description="Run CloudGuardian AWS scan")
parser.add_argument("--profile", default=os.getenv("AWS_PROFILE", "default"))
parser.add_argument("--region", default=os.getenv("AWS_REGION", "eu-west-2"))

args = parser.parse_args()

profile_name = args.profile
region_name = args.region

print(f"Using AWS profile: {profile_name}")
print(f"Using AWS region: {region_name}")
from .scanners.aws_s3 import get_s3_signals
from .scanners.aws_iam import get_iam_signals
from .scanners.aws_network import get_network_signals
from .scanners.aws_ssm import get_ssm_signals
from .scanners.aws_guardduty import get_guardduty_signals
from .engine.framework_engine import load_controls, evaluate_controls, calculate_compliance_score
from .engine.drift_engine import load_previous_state, save_current_state, detect_drift
from .engine.conversation_engine import handle_query
from .reports.pdf_generator import generate_control_pdf


def merge_scan_output(scan_output, signals, resources_map):
    signals.update(scan_output.get("signals", {}))

    for key, value in scan_output.get("resources", {}).items():
        if key not in resources_map:
            resources_map[key] = []
        resources_map[key].extend(value)


signals = {}
resources_map = {}

merge_scan_output(get_s3_signals(profile_name=profile_name), signals, resources_map)
merge_scan_output(get_iam_signals(profile_name=profile_name), signals, resources_map)
merge_scan_output(
    get_network_signals(profile_name=profile_name, region_name=region_name),
    signals,
    resources_map
)

merge_scan_output(
    get_ssm_signals(profile_name=profile_name,
                    region_name=region_name),
    signals,
    resources_map
)
merge_scan_output(
    get_guardduty_signals(profile_name=profile_name,
                          region_name=region_name),
    signals,
    resources_map
)

previous_signals = load_previous_state()
drift = detect_drift(previous_signals, signals)

controls = load_controls()
results = evaluate_controls(signals, controls, resources_map)
score_data = calculate_compliance_score(results)

print("\n=== Signals Collected ===")
for key, value in signals.items():
    print(f"{key}: {value}")

print("\n=== Compliance Summary ===\n")
print(f"Overall Compliance Score: {score_data['score']}%")
print(f"Risk Level: {score_data['risk_level']}")

print("\n=== Compliance Results ===\n")
for cid, data in results.items():
    print(f"{cid} - {data['name']}: {data['status']} [{data['severity']}]")

    if data["status"] == "FAIL":
        print(f"  Reason: {data['plain_english_fail']}")
        print(f"  Risk: {data['risk']}")
        print(f"  Recommendation: {data['recommendation']}")
        print(f"  Triggered Signals: {data['triggered_signals']}")
        print(f"  Affected Resources: {data['affected_resources']}")
        print()

print("\n=== Drift Detection ===\n")
if not drift:
    print("No changes detected since last scan.")
else:
    for change in drift:
        print(f"{change['type']}: {change['signal']} changed from {change['from']} → {change['to']}")

save_current_state(signals)

pdf_path = generate_control_pdf(results, score_data)
print(f"\nEvidence pack generated: {pdf_path}")

print("\n=== Conversational Compliance Engine ===")
print("Type 'help' for available commands. Type 'exit' to quit.\n")

while True:
    user_query = input("CloudGuardian> ").strip()
    if user_query.lower() == "exit":
        print("Exiting CloudGuardian conversation.")
        break

    response = handle_query(user_query, results, drift, score_data)
    print("\n" + response + "\n")
