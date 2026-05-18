import os
from azure.identity import ClientSecretCredential

def get_azure_credential():
    return ClientSecretCredential(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"]
    )

def get_subscription_id():
    return os.environ["AZURE_SUBSCRIPTION_ID"]
