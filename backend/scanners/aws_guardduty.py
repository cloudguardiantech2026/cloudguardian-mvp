import boto3

def build_session(profile_name=None, access_key=None,
                  secret_key=None, region_name=None):
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

def get_guardduty_signals(profile_name=None, access_key=None,
                          secret_key=None, region_name="eu-west-2"):
    signals = {
        "GUARDDUTY_DISABLED":                  False,
        "GUARDDUTY_ACTIVE_MALWARE_FINDING":    False,
        "GUARDDUTY_S3_PROTECTION_DISABLED":    False,
    }
    resources = {
        "GUARDDUTY_DISABLED":               [],
        "GUARDDUTY_ACTIVE_MALWARE_FINDING": [],
        "GUARDDUTY_S3_PROTECTION_DISABLED": [],
    }

    try:
        session = build_session(profile_name, access_key,
                                secret_key, region_name)
        gd = session.client("guardduty", region_name=region_name)

        # ── 1. Check if GuardDuty is enabled ─────────────────
        try:
            detectors = gd.list_detectors().get("DetectorIds", [])
        except Exception:
            detectors = []

        if not detectors:
            signals["GUARDDUTY_DISABLED"] = True
            resources["GUARDDUTY_DISABLED"].append(
                f"GuardDuty not enabled in {region_name}"
            )
            return {"signals": signals, "resources": resources}

        detector_id = detectors[0]

        # ── 2. Check detector status ──────────────────────────
        try:
            detector = gd.get_detector(DetectorId=detector_id)
            if detector.get("Status") != "ENABLED":
                signals["GUARDDUTY_DISABLED"] = True
                resources["GUARDDUTY_DISABLED"].append(
                    f"GuardDuty detector {detector_id} is not active"
                )
        except Exception:
            pass

        # ── 3. Check for active malware findings ──────────────
        try:
            finding_ids = []
            paginator = gd.get_paginator("list_findings")
            for page in paginator.paginate(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "service.archived": {"Eq": ["false"]},
                        "severity": {"Gte": 4},
                    }
                }
            ):
                finding_ids.extend(page.get("FindingIds", []))

            if finding_ids:
                findings = gd.get_findings(
                    DetectorId=detector_id,
                    FindingIds=finding_ids[:50]
                ).get("Findings", [])

                malware_types = [
                    "execution:ec2/maliciousfile",
                    "malware:ec2/",
                    "malware:s3/",
                    "trojan:",
                    "backdoor:",
                    "behavior:ec2/networkportscandetected",
                ]

                for f in findings:
                    finding_type = f.get("Type", "").lower()
                    for mt in malware_types:
                        if mt in finding_type:
                            signals["GUARDDUTY_ACTIVE_MALWARE_FINDING"] = True
                            resource_id = (
                                f.get("Resource", {})
                                .get("InstanceDetails", {})
                                .get("InstanceId", "unknown")
                            )
                            severity = f.get("Severity", 0)
                            resources["GUARDDUTY_ACTIVE_MALWARE_FINDING"].append(
                                f"{resource_id} — {f.get('Type', 'unknown')} "
                                f"(severity {severity})"
                            )
                            break

        except Exception:
            pass

        # ── 4. Check S3 malware protection ────────────────────
        try:
            s3_protection = gd.get_malware_protection_plan(
                DetectorId=detector_id
            )
            status = (s3_protection.get("MalwareProtectionPlanId", {})
                      or s3_protection.get("Status", ""))
            if not status:
                signals["GUARDDUTY_S3_PROTECTION_DISABLED"] = True
                resources["GUARDDUTY_S3_PROTECTION_DISABLED"].append(
                    "GuardDuty S3 Malware Protection not configured"
                )
        except gd.exceptions.ResourceNotFoundException:
            signals["GUARDDUTY_S3_PROTECTION_DISABLED"] = True
            resources["GUARDDUTY_S3_PROTECTION_DISABLED"].append(
                "GuardDuty S3 Malware Protection not enabled"
            )
        except Exception:
            pass

    except Exception:
        pass

    return {"signals": signals, "resources": resources}
