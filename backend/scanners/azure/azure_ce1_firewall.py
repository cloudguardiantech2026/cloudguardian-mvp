from azure.mgmt.network import NetworkManagementClient
from ..azure_auth import get_azure_credential, get_subscription_id

def scan(credential=None, subscription_id=None):
    credential = credential or get_azure_credential()
    subscription_id = subscription_id or get_subscription_id()
    client = NetworkManagementClient(credential, subscription_id)
    findings = []

    for nsg in client.network_security_groups.list_all():
        issues = []
        for rule in (nsg.security_rules or []):
            if (rule.access == "Allow"
                    and rule.direction == "Inbound"
                    and rule.source_address_prefix in ("*", "Internet", "0.0.0.0/0")
                    and rule.destination_port_range in ("*", "0-65535")):
                issues.append(f"Rule '{rule.name}' allows all inbound traffic")

        findings.append({
            "provider": "azure",
            "control": "CE1 – Boundary Firewalls",
            "resource": nsg.name,
            "status": "FAIL" if issues else "PASS",
            "detail": "; ".join(issues) if issues else "No overly permissive inbound rules found"
        })

    return findings