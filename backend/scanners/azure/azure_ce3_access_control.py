import requests
from ..azure_auth import get_azure_credential

def scan(credential=None, subscription_id=None):
    credential = credential or get_azure_credential()
    findings = []

    try:
        token = credential.get_token("https://graph.microsoft.com/.default").token
        headers = {"Authorization": f"Bearer {token}"}

        r = requests.get(
            "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled",
            headers=headers, timeout=15
        )

        if r.status_code == 401 or r.status_code == 403:
            findings.append({
                "provider": "azure",
                "control": "CE3 – User Access Control",
                "resource": "Microsoft Graph",
                "status": "ERROR",
                "detail": (
                    "CloudGuardian does not currently have permission to read user accounts "
                    "(Microsoft Graph access not granted). This control cannot be checked until "
                    "Directory.Read.All and User.Read.All permissions are consented to separately."
                )
            })
            return findings

        r.raise_for_status()
        users = r.json().get("value", [])

        for user in users:
            if not user.get("accountEnabled"):
                continue

            try:
                mfa_r = requests.get(
                    f"https://graph.microsoft.com/v1.0/users/{user['id']}/authentication/methods",
                    headers=headers, timeout=15
                )
                methods = mfa_r.json().get("value", [])
                mfa_types = [m.get("@odata.type", "") for m in methods]
                has_mfa = any(
                    "microsoft.graph.microsoftAuthenticatorAuthenticationMethod" in t
                    or "phoneAuthenticationMethod" in t
                    for t in mfa_types
                )
            except Exception:
                has_mfa = False

            findings.append({
                "provider": "azure",
                "control": "CE3 – User Access Control",
                "resource": user.get("userPrincipalName", user["id"]),
                "status": "PASS" if has_mfa else "FAIL",
                "detail": "MFA registered" if has_mfa else "No MFA method registered"
            })

    except Exception as e:
        findings.append({
            "provider": "azure",
            "control": "CE3 – User Access Control",
            "resource": "scanner",
            "status": "ERROR",
            "detail": str(e)
        })

    if not findings:
        findings.append({
            "provider": "azure",
            "control": "CE3 – User Access Control",
            "resource": "subscription",
            "status": "INFO",
            "detail": "No enabled user accounts found in this tenant."
        })

    return findings
