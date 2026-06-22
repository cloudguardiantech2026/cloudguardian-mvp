from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from ..azure_auth import get_azure_credential, get_subscription_id


def _extract_resource_group(resource_id):
    """Safely extracts the resource group from an ARM resource ID, regardless
    of casing (Azure ARM IDs are case-insensitive for path segments)."""
    parts = resource_id.split("/")
    for i, part in enumerate(parts):
        if part.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return None


def scan(credential=None, subscription_id=None):
    credential = credential or get_azure_credential()
    subscription_id = subscription_id or get_subscription_id()
    compute = ComputeManagementClient(credential, subscription_id)
    network = NetworkManagementClient(credential, subscription_id)
    findings = []

    try:
        vms = list(compute.virtual_machines.list_all())

        for vm in vms:
            issues = []

            # --- Public IP exposure ---
            has_public_ip = False
            nics = vm.network_profile.network_interfaces if vm.network_profile else []
            for nic_ref in nics:
                nic_rg = _extract_resource_group(nic_ref.id)
                nic_name = nic_ref.id.split("/")[-1]
                if not nic_rg:
                    issues.append(f"Could not parse resource group from NIC reference: {nic_ref.id}")
                    continue
                try:
                    nic = network.network_interfaces.get(nic_rg, nic_name)
                    for ip_config in (nic.ip_configurations or []):
                        if ip_config.public_ip_address:
                            has_public_ip = True
                except Exception as nic_err:
                    issues.append(f"Could not retrieve NIC '{nic_name}': {nic_err}")

            if has_public_ip:
                issues.append(
                    "VM has a public IP address. Confirm direct internet exposure is "
                    "required for this workload — see CE1 findings for firewall rule detail."
                )

            # --- OS disk encryption ---
            disk_encrypted = True  # assume compliant unless we find evidence otherwise
            if vm.storage_profile and vm.storage_profile.os_disk:
                encryption = getattr(vm.storage_profile.os_disk, "encryption_settings", None)
                if encryption is None or not getattr(encryption, "enabled", False):
                    # Note: Azure-managed disks are encrypted at rest by platform default
                    # (SSE) even without explicit encryption_settings — this only flags
                    # the absence of *customer-managed* or *ADE* encryption, which is a
                    # softer signal. Treat as INFO-level, not a hard FAIL.
                    disk_encrypted = False

            if not disk_encrypted:
                issues.append(
                    "No explicit OS disk encryption (ADE/CMK) detected. Azure Storage "
                    "Service Encryption applies by default, but customer-managed "
                    "encryption is not configured — verify this meets your data "
                    "protection requirements."
                )

            # --- Boot diagnostics / monitoring baseline ---
            boot_diag = getattr(vm.diagnostics_profile, "boot_diagnostics", None) if vm.diagnostics_profile else None
            if not boot_diag or not boot_diag.enabled:
                issues.append("Boot diagnostics not enabled — limits visibility into VM startup issues.")

            findings.append({
                "provider": "azure",
                "control": "CE2 – Secure Configuration",
                "resource": vm.name,
                "status": "WARN" if issues else "PASS",
                "detail": "; ".join(issues) if issues else "No secure configuration issues detected"
            })

        if not vms:
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

    except Exception as e:
        findings.append({
            "provider": "azure",
            "control": "CE2 – Secure Configuration",
            "resource": "scanner",
            "status": "ERROR",
            "detail": str(e)
        })

    return findings