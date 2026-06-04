import boto3
from backend.scanners.aws_auth import build_session

ADMIN_POLICIES = {
    "AdministratorAccess"
}

def get_iam_signals(role_arn: str, external_id: str, region_name: str = "eu-west-2") -> dict:
    """
    Checks IAM posture against CE_1_2 (MFA / Access Control).

    Signals raised:
      ROOT_MFA_DISABLED      — root account has no MFA device
      IAM_USER_MFA_MISSING   — one or more IAM users have no MFA device
      IAM_USER_ADMIN_POLICY  — one or more IAM users have AdministratorAccess attached

    Parameters
    ----------
    role_arn    : ARN of the CloudGuardian-ReadOnly-AuditRole in the customer account.
    external_id : Per-customer External ID generated at onboarding.
    region_name : AWS region (IAM is global but session region is still required).
    """

    session = build_session(role_arn, external_id, region_name)
    iam = session.client("iam")

    signals = {
        "ROOT_MFA_DISABLED":    False,
        "IAM_USER_MFA_MISSING": False,
        "IAM_USER_ADMIN_POLICY": False,
    }

    resources = {
        "ROOT_MFA_DISABLED":    [],
        "IAM_USER_MFA_MISSING": [],
        "IAM_USER_ADMIN_POLICY": [],
    }

    # ── 1. Root account MFA ───────────────────────────────────────────────────
    try:
        summary = iam.get_account_summary()
        mfa_enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
        if mfa_enabled == 0:
            signals["ROOT_MFA_DISABLED"] = True
            resources["ROOT_MFA_DISABLED"].append("AWS Root Account")
    except Exception as e:
        print(f"[IAM SUMMARY ERROR] {e}")

    # ── 2. Per-user MFA and admin policy checks ───────────────────────────────
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]

                # MFA check
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                if len(mfa_devices) == 0:
                    signals["IAM_USER_MFA_MISSING"] = True
                    resources["IAM_USER_MFA_MISSING"].append(username)

                # Admin policy check
                attached = iam.list_attached_user_policies(
                    UserName=username
                ).get("AttachedPolicies", [])
                for policy in attached:
                    if policy.get("PolicyName") in ADMIN_POLICIES:
                        signals["IAM_USER_ADMIN_POLICY"] = True
                        resources["IAM_USER_ADMIN_POLICY"].append(username)
                        break

    except Exception as e:
        print(f"[IAM USER CHECK ERROR] {e}")

    return {
        "signals":   signals,
        "resources": resources,
    }