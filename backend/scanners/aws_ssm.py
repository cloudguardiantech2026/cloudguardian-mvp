from datetime import datetime, timezone, timedelta
from backend.scanners.aws_auth import build_session

PATCH_SEVERITY_THRESHOLD = 7.0
PATCH_WINDOW_DAYS        = 14

EOL_OS_PATTERNS = [
    "windows server 2008",
    "windows server 2012",
    "windows server 2003",
    "amazon linux 1",
    "ubuntu 14.04",
    "ubuntu 16.04",
    "centos 6",
    "centos 7",
    "rhel 6",
    "debian 8",
    "debian 9",
]


def get_ssm_signals(role_arn: str, external_id: str, region_name: str = "eu-west-2") -> dict:
    """
    Checks patch management posture against CE_4_1 (Security Update Management).

    Signals raised:
      UNPATCHED_CRITICAL_INSTANCE — SSM-managed instance has a CRITICAL/HIGH patch
                                    missing for more than PATCH_WINDOW_DAYS (14) days
      UNMANAGED_SSM_INSTANCE      — EC2 instance exists but is not registered with SSM
      EOL_OS_DETECTED             — instance is running a known end-of-life OS

    Parameters
    ----------
    role_arn    : ARN of the CloudGuardian-ReadOnly-AuditRole in the customer account.
    external_id : Per-customer External ID generated at onboarding.
    region_name : AWS region to scan.
    """

    signals = {
        "UNPATCHED_CRITICAL_INSTANCE": False,
        "UNMANAGED_SSM_INSTANCE":      False,
        "EOL_OS_DETECTED":             False,
    }

    resources = {
        "UNPATCHED_CRITICAL_INSTANCE": [],
        "UNMANAGED_SSM_INSTANCE":      [],
        "EOL_OS_DETECTED":             [],
    }

    try:
        session = build_session(role_arn, external_id, region_name)

        # ── 1. Discover all running/stopped EC2 instances ─────────────────────
        ec2           = session.client("ec2", region_name=region_name)
        all_instances = []

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{
                    "Name":   "instance-state-name",
                    "Values": ["running", "stopped"],
                }]
            ):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        all_instances.append(inst["InstanceId"])
        except Exception:
            pass

        if not all_instances:
            return {"signals": signals, "resources": resources}

        # ── 2. Identify SSM-managed instances ─────────────────────────────────
        ssm         = session.client("ssm", region_name=region_name)
        managed_ids = set()

        try:
            paginator = ssm.get_paginator("describe_instance_information")
            for page in paginator.paginate():
                for info in page["InstanceInformationList"]:
                    managed_ids.add(info["InstanceId"])
        except Exception:
            pass

        # Any instance not in SSM is unmanaged — cannot be patched centrally
        unmanaged = [i for i in all_instances if i not in managed_ids]
        if unmanaged:
            signals["UNMANAGED_SSM_INSTANCE"] = True
            resources["UNMANAGED_SSM_INSTANCE"].extend(unmanaged)

        # ── 3. Patch compliance check on managed instances ────────────────────
        cutoff = datetime.now(timezone.utc) - timedelta(days=PATCH_WINDOW_DAYS)

        for instance_id in managed_ids:
            try:
                paginator = ssm.get_paginator("describe_instance_patches")
                for page in paginator.paginate(
                    InstanceId=instance_id,
                    Filters=[{"Key": "State", "Values": ["Missing", "Failed"]}],
                ):
                    for patch in page["Patches"]:
                        severity = patch.get("Severity", "").upper()
                        released = patch.get("ReleaseDate")

                        if severity in ("CRITICAL", "HIGH"):
                            if released:
                                if hasattr(released, "tzinfo"):
                                    if released.tzinfo is None:
                                        released = released.replace(tzinfo=timezone.utc)
                                    days_old = (datetime.now(timezone.utc) - released).days
                                else:
                                    days_old = PATCH_WINDOW_DAYS + 1

                                if days_old > PATCH_WINDOW_DAYS:
                                    signals["UNPATCHED_CRITICAL_INSTANCE"] = True
                                    label = (
                                        f"{instance_id} — "
                                        f"{patch.get('Title', 'unknown patch')} "
                                        f"({days_old}d overdue)"
                                    )
                                    resources["UNPATCHED_CRITICAL_INSTANCE"].append(label)
                                    break
            except Exception:
                pass

        # ── 4. End-of-life OS detection via SSM inventory ─────────────────────
        try:
            paginator = ssm.get_paginator("get_inventory")
            for page in paginator.paginate(
                Filters=[{
                    "Key":    "AWS:InstanceInformation.InstanceStatus",
                    "Values": ["Active"],
                }]
            ):
                for entity in page.get("Entities", []):
                    instance_id = entity.get("Id", "unknown")
                    content = (
                        entity.get("Data", {})
                        .get("AWS:InstanceInformation", {})
                        .get("Content", [])
                    )
                    for item in content:
                        os_name    = item.get("PlatformName",    "").lower()
                        os_version = item.get("PlatformVersion", "").lower()
                        os_full    = f"{os_name} {os_version}".strip()

                        for pattern in EOL_OS_PATTERNS:
                            if pattern in os_full:
                                signals["EOL_OS_DETECTED"] = True
                                resources["EOL_OS_DETECTED"].append(
                                    f"{instance_id} — {os_full} (end of life)"
                                )
                                break
        except Exception:
            pass

    except Exception:
        pass

    return {
        "signals":   signals,
        "resources": resources,
    }