import boto3


CRITICAL_PORTS = {
    22: "SG_SSH_OPEN",
    3389: "SG_RDP_OPEN",
    3306: "SG_MYSQL_OPEN",
    5432: "SG_POSTGRES_OPEN"
}


def get_network_signals(profile_name="cloudguardian-demo", region_name="eu-west-2"):
    """
    Returns AWS network-related compliance signals.

    Signals:
    - SG_SSH_OPEN
    - SG_RDP_OPEN
    - SG_MYSQL_OPEN
    - SG_POSTGRES_OPEN
    - IGW_ATTACHED
    - PUBLIC_ROUTE_EXISTS
    - EC2_PUBLIC_IP_PRESENT
    - PUBLIC_EXPOSURE
    """
    session = boto3.Session(profile_name=profile_name, region_name=region_name)
    ec2 = session.client("ec2")

    signals = {
        "SG_SSH_OPEN": False,
        "SG_RDP_OPEN": False,
        "SG_MYSQL_OPEN": False,
        "SG_POSTGRES_OPEN": False,
        "IGW_ATTACHED": False,
        "PUBLIC_ROUTE_EXISTS": False,
        "EC2_PUBLIC_IP_PRESENT": False,
        "PUBLIC_EXPOSURE": False
    }

    try:
        # 1. Security group checks
        sg_response = ec2.describe_security_groups()

        for sg in sg_response.get("SecurityGroups", []):
            for permission in sg.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                if from_port is None or to_port is None:
                    continue

                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")
                    if cidr == "0.0.0.0/0":
                        for port, signal_name in CRITICAL_PORTS.items():
                            if from_port <= port <= to_port:
                                signals[signal_name] = True

        # 2. Internet gateway check
        igw_response = ec2.describe_internet_gateways()
        if igw_response.get("InternetGateways"):
            signals["IGW_ATTACHED"] = True

        # 3. Public route check
        route_tables = ec2.describe_route_tables()
        for rt in route_tables.get("RouteTables", []):
            for route in rt.get("Routes", []):
                destination = route.get("DestinationCidrBlock")
                gateway_id = route.get("GatewayId", "")
                if destination == "0.0.0.0/0" and gateway_id.startswith("igw-"):
                    signals["PUBLIC_ROUTE_EXISTS"] = True

        # 4. EC2 public IP check
        reservations = ec2.describe_instances().get("Reservations", [])
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                if instance.get("State", {}).get("Name") in ["running", "pending", "stopped", "stopping"]:
                    if instance.get("PublicIpAddress"):
                        signals["EC2_PUBLIC_IP_PRESENT"] = True

        # 5. Aggregate public exposure signal
        if (
            signals["PUBLIC_ROUTE_EXISTS"]
            and signals["EC2_PUBLIC_IP_PRESENT"]
        ):
            signals["PUBLIC_EXPOSURE"] = True

    except Exception as e:
        print(f"[NETWORK SCANNER ERROR] {e}")

    return signals
