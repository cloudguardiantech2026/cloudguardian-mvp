import boto3


ADMIN_POLICIES = {
    "AdministratorAccess"
}


def build_session(profile_name=None, access_key=None, secret_key=None, region_name=None):
    if access_key and secret_key:
        return boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region_name,
        )

    return boto3.Session(
        profile_name=profile_name,
        region_name=region_name,
    )


def get_iam_signals(profile_name=None, access_key=None, secret_key=None, region_name=None):
    session = build_session(
        profile_name=profile_name,
        access_key=access_key,
        secret_key=secret_key,
        region_name=region_name,
    )
    iam = session.client("iam")

    signals = {
        "ROOT_MFA_DISABLED": False,
        "IAM_USER_MFA_MISSING": False,
        "IAM_USER_ADMIN_POLICY": False
    }

    resources = {
        "ROOT_MFA_DISABLED": [],
        "IAM_USER_MFA_MISSING": [],
        "IAM_USER_ADMIN_POLICY": []
    }

    try:
        summary = iam.get_account_summary()
        mfa_enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
        if mfa_enabled == 0:
            signals["ROOT_MFA_DISABLED"] = True
            resources["ROOT_MFA_DISABLED"].append("AWS Root Account")
    except Exception as e:
        print(f"[IAM SUMMARY ERROR] {e}")

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]

                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                if len(mfa_devices) == 0:
                    signals["IAM_USER_MFA_MISSING"] = True
                    resources["IAM_USER_MFA_MISSING"].append(username)

                attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                for policy in attached:
                    if policy.get("PolicyName") in ADMIN_POLICIES:
                        signals["IAM_USER_ADMIN_POLICY"] = True
                        resources["IAM_USER_ADMIN_POLICY"].append(username)
                        break

    except Exception as e:
        print(f"[IAM USER CHECK ERROR] {e}")

    return {
        "signals": signals,
        "resources": resources
    }