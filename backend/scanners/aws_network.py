import boto3


CRITICAL_PORTS = {
    22: "SG_SSH_OPEN",
    3389: "SG_RDP_OPEN",
    3306: "SG_MYSQL_OPEN",
    5432: "SG_POSTGRES_OPEN"
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


def get_network_signals(profile_name=None, access_key=None, secret_key=None, region_name="eu-west-2"):
    session = build_session(
        profile_name=profile_name,
        access_key=access_key,
        secret_key=secret_key,
        region_name=region_name,
    )
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

    resources = {
        "SG_SSH_OPEN": [],
        "SG_RDP_OPEN": [],
        "SG_MYSQL_OPEN": [],
        "SG_POSTGRES_OPEN": [],
        "IGW_ATTACHED": [],
        "PUBLIC_ROUTE_EXISTS": [],
        "EC2_PUBLIC_IP_PRESENT": [],
        "PUBLIC_EXPOSURE": []
    }

    try:
        sg_response = ec2.describe_security_groups()

        for sg in sg_response.get("SecurityGroups", []):
            sg_name = sg.get("GroupName", sg.get("GroupId", "unknown-sg"))

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
                                resources[signal_name].append(sg_name)

        igw_response = ec2.describe_internet_gateways()
        for igw in igw_response.get("InternetGateways", []):
            igw_id = igw.get("InternetGatewayId")
            if igw_id:
                signals["IGW_ATTACHED"] = True
                resources["IGW_ATTACHED"].append(igw_id)

        route_tables = ec2.describe_route_tables()
        for rt in route_tables.get("RouteTables", []):
            rt_id = rt.get("RouteTableId", "unknown-rt")
            for route in rt.get("Routes", []):
                destination = route.get("DestinationCidrBlock")
                gateway_id = route.get("GatewayId", "")
                if destination == "0.0.0.0/0" and gateway_id.startswith("igw-"):
                    signals["PUBLIC_ROUTE_EXISTS"] = True
                    resources["PUBLIC_ROUTE_EXISTS"].append(rt_id)

        reservations = ec2.describe_instances().get("Reservations", [])
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId", "unknown-instance")
                state = instance.get("State", {}).get("Name")
                if state in ["running", "pending", "stopped", "stopping"]:
                    if instance.get("PublicIpAddress"):
                        signals["EC2_PUBLIC_IP_PRESENT"] = True
                        resources["EC2_PUBLIC_IP_PRESENT"].append(instance_id)

        if signals["PUBLIC_ROUTE_EXISTS"] and signals["EC2_PUBLIC_IP_PRESENT"]:
            signals["PUBLIC_EXPOSURE"] = True
            resources["PUBLIC_EXPOSURE"] = list(
                set(resources["PUBLIC_ROUTE_EXISTS"] + resources["EC2_PUBLIC_IP_PRESENT"])
            )

    except Exception as e:
        print(f"[NETWORK SCANNER ERROR] {e}")

    return {
        "signals": signals,
        "resources": resources
    }