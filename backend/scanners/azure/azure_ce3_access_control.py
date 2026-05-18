import requests
from ..azure_auth import get_azure_credential

def scan(credential=None, subscription_id=None):
    credential = credential or get_azure_credential()
    token = credential.get_token("https://graph.microsoft.com/.default").token
    headers = {"Authorization": f"Bearer {token}"}
    findings = []

    # Fetch users
    r = requests.get(
        "https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled",
        headers=headers, timeout=15
    )
    users = r.json().get("value", [])

    for user in users:
        if not user.get("accountEnabled"):
            continue

        # Check MFA registration
        mfa_r = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{user['id']}/authentication/methods",
            headers=headers, timeout=15
        )
        methods = mfa_r.json().get("value", [])
        mfa_types = [m.get("@odata.type", "") for m in methods]
        has_mfa = any("microsoft.graph.microsoftAuthenticatorAuthenticationMethod"
                      in t or "phoneAuthenticationMethod" in t for t in mfa_types)

        findings.append({
            "provider": "azure",
            "control": "CE3 – User Access Control",
            "resource": user.get("userPrincipalName", user["id"]),
            "status": "PASS" if has_mfa else "FAIL",
            "detail": "MFA registered" if has_mfa else "No MFA method registered"
        })

    return findings