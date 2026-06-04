import boto3
from backend.scanners.aws_auth import build_session

PUBLIC_ALL_USERS_URI  = "http://acs.amazonaws.com/groups/global/AllUsers"
PUBLIC_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def _is_bucket_public(s3, bucket_name: str) -> bool:
    """
    Returns True if the bucket is publicly readable via ACL or bucket policy.
    Checks both ACL grants and the bucket policy public status flag.
    """

    # ── ACL check ─────────────────────────────────────────────────────────────
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri     = grantee.get("URI")
            perm    = grant.get("Permission")
            if uri in (PUBLIC_ALL_USERS_URI, PUBLIC_AUTH_USERS_URI) and perm in ("READ", "FULL_CONTROL"):
                return True
    except Exception:
        pass

    # ── Bucket policy public status check ────────────────────────────────────
    try:
        status = s3.get_bucket_policy_status(Bucket=bucket_name)
        if status.get("PolicyStatus", {}).get("IsPublic") is True:
            return True
    except Exception:
        pass

    return False


def list_s3_buckets(role_arn: str, external_id: str, region_name: str = "eu-west-2") -> list:
    """
    Returns a list of S3 buckets in the customer account with public read status.

    Parameters
    ----------
    role_arn    : ARN of the CloudGuardian-ReadOnly-AuditRole in the customer account.
    external_id : Per-customer External ID generated at onboarding.
    region_name : AWS region for the session.
    """

    session = build_session(role_arn, external_id, region_name)
    s3 = session.client("s3")

    resp    = s3.list_buckets()
    buckets = []

    for b in resp.get("Buckets", []):
        name        = b["Name"]
        public_read = _is_bucket_public(s3, name)
        buckets.append({
            "name":        name,
            "public_read": bool(public_read),
            "cloud":       "AWS",
        })

    return buckets


def get_s3_signals(role_arn: str, external_id: str, region_name: str = "eu-west-2") -> dict:
    """
    Checks S3 posture against CE_2_1 (Secure Configuration).

    Signals raised:
      S3_PUBLIC — one or more S3 buckets are publicly readable

    Parameters
    ----------
    role_arn    : ARN of the CloudGuardian-ReadOnly-AuditRole in the customer account.
    external_id : Per-customer External ID generated at onboarding.
    region_name : AWS region for the session.
    """

    signals   = {"S3_PUBLIC": False}
    resources = {"S3_PUBLIC": []}

    buckets = list_s3_buckets(role_arn, external_id, region_name)

    for bucket in buckets:
        if bucket.get("public_read") is True:
            signals["S3_PUBLIC"] = True
            resources["S3_PUBLIC"].append(bucket["name"])

    return {
        "signals":   signals,
        "resources": resources,
    }