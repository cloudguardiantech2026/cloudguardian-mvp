import boto3

def list_s3_buckets():
    session = boto3.Session(profile_name="cloudguardian-demo")
    s3 = session.client("s3")

    response = s3.list_buckets()

    print("S3 Buckets:")
    for bucket in response["Buckets"]:
        print(f"- {bucket['Name']}")

if __name__ == "__main__":
    list_s3_buckets()