import boto3
from backend.scanners.aws_auth import build_session

CRITICAL_PORTS = {
    22:   "SG_SSH_OPEN",
    3389: "SG_RDP_OPEN",
    3306: "SG_MYSQL_OPEN",
    5432: "SG_POSTGRES_OPEN",
}

def get_network_signals(role_arn: str, external_id: str, region_name: str = "eu-west-2") -> dict:
    """
    Checks network posture against CE_3_1 (Boundary Firewalls and Internet Gateways).

    Signals raised:
      SG_SSH_OPEN          — security group allows unrestricted inbound SSH (port 22)
      SG_RDP_OPEN          — security group allows unrestricted inbound RDP (port 3389)
      SG_MYSQL_OPEN        — security group allows unrestricted inbound MySQL (port 3306)
      SG_POSTGRES_OPEN     — security group allows unrestricted inbound Postgres (port 5432)
      IGW_ATTACHED         — an internet gateway is attached to a VPC
      PUBLIC_ROUTE_EXISTS  — a route table has a 0.0.0.0/0 route via an IGW
      EC2_PUBLIC_IP_PRESENT — one or more EC2 instances have a public IP address
      PUBLIC_EXPOSURE      — combination of public route + public IP (confirmed exposure)

    Parameters
    ----------
    role_arn    : ARN of the CloudGuardian-ReadOnly-AuditRole in the customer account.
    external_id : Per-customer External ID generated at onboarding.
    region_name : AWS region to scan.
    """

    session = build_session(role_arn, external_id, region_name)
    ec2 = session.client("ec2")

    signals = {
        "SG_SSH_OPEN":           False,
        "SG_RDP_OPEN":           False,
        "SG_MYSQL_OPEN":         False,
        "SG_POSTGRES_OPEN":      False,
        "IGW_ATTACHED":          False,
        "PUBLIC_ROUTE_EXISTS":   False,
        "EC2_PUBLIC_IP_PRESENT": False,
        "PUBLIC_EXPOSURE":       False,
    }

    resources = {
        "SG_SSH_OPEN":           [],
        "SG_RDP_OPEN":           [],
        "SG_MYSQL_OPEN":         [],
        "SG_POSTGRES_OPEN":      [],
        "IGW_ATTACHED":          [],
        "PUBLIC_ROUTE_EXISTS":   [],
        "EC2_PUBLIC_IP_PRESENT": [],
        "PUBLIC_EXPOSURE":       [],
    }

    try:
        # ── 1. Security group open port checks ───────────────────────────────
        sg_response = ec2.describe_security_groups()
        for sg in sg_response.get("SecurityGroups", []):
            sg_name = sg.get("GroupName", sg.get("GroupId", "unknown-sg"))
            for permission in sg.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port   = permission.get("ToPort")
                if from_port is None or to_port is None:
                    continue
                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")
                    if cidr == "0.0.0.0/0":
                        for port, signal_name in CRITICAL_PORTS.items():
                            if from_port <= port <= to_port:
                                signals[signal_name] = True
                                resources[signal_name].append(sg_name)

        # ── 2. Internet gateway check ─────────────────────────────────────────
        igw_response = ec2.describe_internet_gateways()
        for igw in igw_response.get("InternetGateways", []):
            igw_id = igw.get("InternetGatewayId")
            if igw_id:
                signals["IGW_ATTACHED"] = True
                resources["IGW_ATTACHED"].append(igw_id)

        # ── 3. Public route table check ───────────────────────────────────────
        route_tables = ec2.describe_route_tables()
        for rt in route_tables.get("RouteTables", []):
            rt_id = rt.get("RouteTableId", "unknown-rt")
            for route in rt.get("Routes", []):
                destination = route.get("DestinationCidrBlock")
                gateway_id  = route.get("GatewayId", "")
                if destination == "0.0.0.0/0" and gateway_id.startswith("igw-"):
                    signals["PUBLIC_ROUTE_EXISTS"] = True
                    resources["PUBLIC_ROUTE_EXISTS"].append(rt_id)

        # ── 4. EC2 public IP check ────────────────────────────────────────────
        reservations = ec2.describe_instances().get("Reservations", [])
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId", "unknown-instance")
                state = instance.get("State", {}).get("Name")
                if state in ["running", "pending", "stopped", "stopping"]:
                    if instance.get("PublicIpAddress"):
                        signals["EC2_PUBLIC_IP_PRESENT"] = True
                        resources["EC2_PUBLIC_IP_PRESENT"].append(instance_id)

        # ── 5. Confirmed public exposure (route + public IP) ──────────────────
        if signals["PUBLIC_ROUTE_EXISTS"] and signals["EC2_PUBLIC_IP_PRESENT"]:
            signals["PUBLIC_EXPOSURE"] = True
            resources["PUBLIC_EXPOSURE"] = list(
                set(resources["PUBLIC_ROUTE_EXISTS"] + resources["EC2_PUBLIC_IP_PRESENT"])
            )

    except Exception as e:
        print(f"[NETWORK SCANNER ERROR] {e}")

    return {
        "signals":   signals,
        "resources": resources,
    }