from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from ..azure_auth import get_azure_credential, get_subscription_id

def scan(credential=None, subscription_id=None):
    credential = credential or get_azure_credential()
    subscription_id = subscription_id or get_subscription_id()
    compute = ComputeManagementClient(credential, subscription_id)
    network = NetworkManagementClient(credential, subscription_id)
    findings = []

    try:
        for vm in compute.virtual_machines.list_all():
            rg = vm.id.split("/")[4]
            nics = vm.network_profile.network_interfaces if vm.network_profile else []
            has_public_ip = False

            for nic_ref in nics:
                nic_name = nic_ref.id.split("/")[-1]
                try:
                    nic = network.network_interfaces.get(rg, nic_name)
                    for ip_config in (nic.ip_configurations or []):
                        if ip_config.public_ip_address:
                            has_public_ip = True
                except Exception:
                    pass

            detail = []
            if has_public_ip:
                detail.append("VM has a public IP — verify management ports are restricted")

            findings.append({
                "provider": "azure",
                "control": "CE2 – Secure Configuration",
                "resource": vm.name,
                "status": "WARN" if detail else "PASS",
                "detail": "; ".join(detail) if detail else "No public IP exposure detected"
            })
    except Exception as e:
        findings.append({
            "provider": "azure",
            "control": "CE2 – Secure Configuration",
            "resource": "scanner",
            "status": "ERROR",
            "detail": str(e)
        })

    if not findings:
        findings.append({
            "provider": "azure",
            "control": "CE2 – Secure Configuration",
            "resource": "subscription",
            "status": "INFO",
            "detail": (
                "No virtual machines found in this subscription. "
                "This control cannot be fully assessed until compute resources exist — "
                "deploy a VM to enable secure configuration checks."
            )
        })

    return findings
