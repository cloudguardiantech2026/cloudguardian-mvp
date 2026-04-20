import boto3


PUBLIC_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
PUBLIC_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


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


def _is_bucket_public(s3, bucket_name: str) -> bool:
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI")
            perm = grant.get("Permission")
            if uri in (PUBLIC_ALL_USERS_URI, PUBLIC_AUTH_USERS_URI) and perm in ("READ", "FULL_CONTROL"):
                return True
    except Exception:
        pass

    try:
        status = s3.get_bucket_policy_status(Bucket=bucket_name)
        if status.get("PolicyStatus", {}).get("IsPublic") is True:
            return True
    except Exception:
        pass

    return False


def list_s3_buckets(profile_name=None, access_key=None, secret_key=None, region_name=None):
    session = build_session(
        profile_name=profile_name,
        access_key=access_key,
        secret_key=secret_key,
        region_name=region_name,
    )
    s3 = session.client("s3")

    resp = s3.list_buckets()
    buckets = []

    for b in resp.get("Buckets", []):
        name = b["Name"]
        public_read = _is_bucket_public(s3, name)

        buckets.append({
            "name": name,
            "public_read": bool(public_read),
            "cloud": "AWS"
        })

    return buckets


def get_s3_signals(profile_name=None, access_key=None, secret_key=None, region_name=None):
    signals = {
        "S3_PUBLIC": False
    }

    resources = {
        "S3_PUBLIC": []
    }

    buckets = list_s3_buckets(
        profile_name=profile_name,
        access_key=access_key,
        secret_key=secret_key,
        region_name=region_name,
    )

    for bucket in buckets:
        if bucket.get("public_read") is True:
            signals["S3_PUBLIC"] = True
            resources["S3_PUBLIC"].append(bucket["name"])

    return {
        "signals": signals,
        "resources": resources
    }