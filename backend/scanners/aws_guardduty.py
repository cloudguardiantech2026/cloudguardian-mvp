from backend.scanners.aws_auth import build_session


def get_guardduty_signals(role_arn: str, external_id: str, region_name: str = "eu-west-2") -> dict:
    """
    Checks malware protection posture against CE_5_1 (Malware Protection).

    Signals raised:
      GUARDDUTY_DISABLED               — GuardDuty is not enabled or detector is inactive
      GUARDDUTY_ACTIVE_MALWARE_FINDING — one or more active malware-related findings
                                         with severity >= 4 exist in the account
      GUARDDUTY_S3_PROTECTION_DISABLED — GuardDuty S3 Malware Protection is not configured

    Parameters
    ----------
    role_arn    : ARN of the CloudGuardian-ReadOnly-AuditRole in the customer account.
    external_id : Per-customer External ID generated at onboarding.
    region_name : AWS region to scan.
    """

    signals = {
        "GUARDDUTY_DISABLED":               False,
        "GUARDDUTY_ACTIVE_MALWARE_FINDING": False,
        "GUARDDUTY_S3_PROTECTION_DISABLED": False,
    }

    resources = {
        "GUARDDUTY_DISABLED":               [],
        "GUARDDUTY_ACTIVE_MALWARE_FINDING": [],
        "GUARDDUTY_S3_PROTECTION_DISABLED": [],
    }

    try:
        session = build_session(role_arn, external_id, region_name)
        gd      = session.client("guardduty", region_name=region_name)

        # ── 1. Check if GuardDuty is enabled ──────────────────────────────────
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

        # ── 2. Check detector status ───────────────────────────────────────────
        try:
            detector = gd.get_detector(DetectorId=detector_id)
            if detector.get("Status") != "ENABLED":
                signals["GUARDDUTY_DISABLED"] = True
                resources["GUARDDUTY_DISABLED"].append(
                    f"GuardDuty detector {detector_id} is not active"
                )
        except Exception:
            pass

        # ── 3. Check for active malware-related findings ───────────────────────
        try:
            finding_ids = []
            paginator   = gd.get_paginator("list_findings")

            for page in paginator.paginate(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "service.archived": {"Eq": ["false"]},
                        "severity":         {"Gte": 4},
                    }
                },
            ):
                finding_ids.extend(page.get("FindingIds", []))

            if finding_ids:
                findings = gd.get_findings(
                    DetectorId=detector_id,
                    FindingIds=finding_ids[:50],
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

        # ── 4. Check S3 malware protection ────────────────────────────────────
        try:
            s3_protection = gd.get_malware_protection_plan(DetectorId=detector_id)
            status = (
                s3_protection.get("MalwareProtectionPlanId", {})
                or s3_protection.get("Status", "")
            )
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

    return {
        "signals":   signals,
        "resources": resources,
    }