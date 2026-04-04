import boto3


ADMIN_POLICIES = {
    "AdministratorAccess"
}


def get_iam_signals(profile_name="cloudguardian-demo"):
    """
    Returns IAM-related compliance signals.

    Signals:
    - ROOT_MFA_DISABLED
    - IAM_USER_MFA_MISSING
    - IAM_USER_ADMIN_POLICY
    """
    session = boto3.Session(profile_name=profile_name)
    iam = session.client("iam")

    signals = {
        "ROOT_MFA_DISABLED": False,
        "IAM_USER_MFA_MISSING": False,
        "IAM_USER_ADMIN_POLICY": False
    }

    try:
        summary = iam.get_account_summary()
        mfa_enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
        signals["ROOT_MFA_DISABLED"] = (mfa_enabled == 0)
    except Exception as e:
        print(f"[IAM SUMMARY ERROR] {e}")

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]

                # Check MFA devices
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                if len(mfa_devices) == 0:
                    signals["IAM_USER_MFA_MISSING"] = True

                # Check directly attached user policies
                attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                for policy in attached:
                    if policy.get("PolicyName") in ADMIN_POLICIES:
                        signals["IAM_USER_ADMIN_POLICY"] = True

    except Exception as e:
        print(f"[IAM USER CHECK ERROR] {e}")

    return signals
