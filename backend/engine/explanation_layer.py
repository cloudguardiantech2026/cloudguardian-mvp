SIGNAL_EXPLANATIONS = {
    "ROOT_MFA_DISABLED": {
        "title": "Root account is not protected with MFA",
        "business_impact": "If someone gains access to your main AWS account, they could take full control of your cloud environment.",
        "action": "Enable multi-factor authentication on the AWS root account immediately."
    },
    "IAM_USER_MFA_MISSING": {
        "title": "One or more user accounts do not use MFA",
        "business_impact": "If a password is stolen, an attacker could log in without any additional security check.",
        "action": "Enable MFA for all AWS users."
    },
    "IAM_USER_ADMIN_POLICY": {
        "title": "A user account has more access than it needs",
        "business_impact": "If this account is compromised, someone could make major changes to your AWS environment.",
        "action": "Remove full administrator access and replace it with only the permissions the user needs."
    },
    "S3_PUBLIC": {
        "title": "A storage bucket is publicly accessible",
        "business_impact": "Files or company information stored in this bucket could be exposed on the internet.",
        "action": "Remove public access from the bucket and enable AWS Block Public Access."
    },
    "SG_SSH_OPEN": {
        "title": "A system can be accessed from the internet using SSH",
        "business_impact": "This increases the chance of unwanted access attempts or password guessing attacks.",
        "action": "Restrict SSH access so only trusted IP addresses can connect."
    },
    "SG_RDP_OPEN": {
        "title": "A system can be accessed from the internet using Remote Desktop",
        "business_impact": "This may allow attackers to try to connect to your system remotely.",
        "action": "Restrict Remote Desktop access to trusted IP addresses only."
    },
    "PUBLIC_EXPOSURE": {
        "title": "One or more systems appear publicly reachable",
        "business_impact": "Systems that are reachable from the internet are more likely to be targeted.",
        "action": "Review internet gateways, route tables, public IP addresses and security groups."
    }
}


def get_signal_explanation(signal_name):
    return SIGNAL_EXPLANATIONS.get(signal_name)


def build_control_summary(control_data):
    triggered = control_data.get("triggered_signals", [])

    if not triggered:
        return []

    explanations = []

    for signal in triggered:
        explanation = get_signal_explanation(signal)
        if explanation:
            explanations.append(explanation)

    return explanations

