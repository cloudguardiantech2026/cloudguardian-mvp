from azure.mgmt.compute import ComputeManagementClient
from ..azure_auth import get_azure_credential, get_subscription_id

def scan(credential=None, subscription_id=None):
    credential = credential or get_azure_credential()
    subscription_id = subscription_id or get_subscription_id()
    client = ComputeManagementClient(credential, subscription_id)
    findings = []

    try:
        for vm in client.virtual_machines.list_all():
            patch_mode = "Unknown"
            os_profile = vm.os_profile
            if os_profile:
                if os_profile.windows_configuration:
                    wc = os_profile.windows_configuration
                    patch_mode = getattr(
                        getattr(wc, "patch_settings", None), "patch_mode", "Unknown"
                    )
                elif os_profile.linux_configuration:
                    lc = os_profile.linux_configuration
                    patch_mode = getattr(
                        getattr(lc, "patch_settings", None), "patch_mode", "Unknown"
                    )

            is_auto = patch_mode in ("AutomaticByOS", "AutomaticByPlatform", "ImageDefault")

            findings.append({
                "provider": "azure",
                "control": "CE5 – Patch Management",
                "resource": vm.name,
                "status": "PASS" if is_auto else "FAIL",
                "detail": f"Patch mode: {patch_mode}"
            })
    except Exception as e:
        findings.append({
            "provider": "azure",
            "control": "CE5 – Patch Management",
            "resource": "scanner",
            "status": "ERROR",
            "detail": str(e)
        })

    if not findings:
        findings.append({
            "provider": "azure",
            "control": "CE5 – Patch Management",
            "resource": "subscription",
            "status": "INFO",
            "detail": (
                "No virtual machines found in this subscription. "
                "This control cannot be fully assessed until compute resources exist — "
                "deploy a VM to enable patch management checks."
            )
        })

    return findings
