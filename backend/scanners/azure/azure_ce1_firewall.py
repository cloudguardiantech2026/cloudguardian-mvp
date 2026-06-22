from azure.mgmt.network import NetworkManagementClient
from ..azure_auth import get_azure_credential, get_subscription_id

# Ports considered high-risk when exposed to any source.
# CE assessors generally expect remote-admin and database ports flagged explicitly.
SENSITIVE_PORTS = {
    "22",    # SSH
    "23",    # Telnet
    "3389",  # RDP
    "1433",  # MS SQL
    "3306",  # MySQL
    "5432",  # PostgreSQL
    "5900",  # VNC
    "6379",  # Redis
    "27017", # MongoDB
}

OPEN_SOURCE_VALUES = {"*", "internet", "any", "0.0.0.0/0", "::/0"}


def _normalize(value):
    """Lowercase + strip for case-insensitive comparisons (Azure tags like
    'Internet' can appear in mixed case depending on how the rule was created)."""
    return (value or "").strip().lower()


def _is_open_source(rule):
    """
    Checks both the singular source_address_prefix and the plural
    source_address_prefixes list. Azure populates exactly one of the two
    depending on how the rule was authored (Portal singular UI vs
    CLI/ARM multi-prefix array).
    """
    prefixes = []
    if rule.source_address_prefix:
        prefixes.append(rule.source_address_prefix)
    if rule.source_address_prefixes:
        prefixes.extend(rule.source_address_prefixes)

    return any(_normalize(p) in OPEN_SOURCE_VALUES for p in prefixes)


def _expand_port_range(port_range):
    """Turns '20-25' into {'20','21','22','23','24','25'}; a single port
    like '22' into {'22'}; leaves '*' as a special wildcard marker."""
    port_range = (port_range or "").strip()
    if port_range in ("*", "0-65535"):
        return None  # None = wildcard, meaning "every port" — checked separately
    if "-" in port_range:
        try:
            start, end = port_range.split("-")
            start, end = int(start), int(end)
            # Guard against pathological ranges blowing up memory
            if end - start > 65535:
                return {"*"}
            return {str(p) for p in range(start, end + 1)}
        except ValueError:
            return set()
    return {port_range}


def _exposed_sensitive_ports(rule):
    """
    Returns the set of sensitive ports this rule exposes, checking both the
    singular destination_port_range and the plural destination_port_ranges list.
    Returns the special marker {'*'} if the rule opens every port.
    """
    raw_ranges = []
    if rule.destination_port_range:
        raw_ranges.append(rule.destination_port_range)
    if rule.destination_port_ranges:
        raw_ranges.extend(rule.destination_port_ranges)

    exposed = set()
    for pr in raw_ranges:
        expanded = _expand_port_range(pr)
        if expanded is None:
            return {"*"}  # any single wildcard range means "all ports" — short-circuit
        exposed |= expanded

    return exposed & SENSITIVE_PORTS


def scan(credential=None, subscription_id=None):
    credential = credential or get_azure_credential()
    subscription_id = subscription_id or get_subscription_id()
    client = NetworkManagementClient(credential, subscription_id)
    findings = []

    try:
        nsgs = list(client.network_security_groups.list_all())

        for nsg in nsgs:
            issues = []

            for rule in (nsg.security_rules or []):
                if rule.access != "Allow" or rule.direction != "Inbound":
                    continue

                if not _is_open_source(rule):
                    continue

                exposed_ports = _exposed_sensitive_ports(rule)
                if not exposed_ports:
                    continue

                if exposed_ports == {"*"}:
                    issues.append(
                        f"Rule '{rule.name}' allows ALL inbound traffic from any source on ALL ports"
                    )
                else:
                    port_list = ", ".join(sorted(exposed_ports, key=int))
                    issues.append(
                        f"Rule '{rule.name}' allows inbound access from any source "
                        f"on sensitive port(s): {port_list}"
                    )

            findings.append({
                "provider": "azure",
                "control": "CE1 – Boundary Firewalls",
                "resource": nsg.name,
                "status": "FAIL" if issues else "PASS",
                "detail": "; ".join(issues) if issues else "No overly permissive inbound rules found"
            })

        if not nsgs:
            findings.append({
                "provider": "azure",
                "control": "CE1 – Boundary Firewalls",
                "resource": "subscription",
                "status": "INFO",
                "detail": (
                    "No network security groups found in this subscription. "
                    "This control cannot be fully assessed until network resources exist — "
                    "create an NSG or deploy a VM to enable boundary firewall checks."
                )
            })

    except Exception as e:
        findings.append({
            "provider": "azure",
            "control": "CE1 – Boundary Firewalls",
            "resource": "scanner",
            "status": "ERROR",
            "detail": str(e)
        })

    return findings