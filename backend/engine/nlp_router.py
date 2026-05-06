import re


CONTROL_ALIASES = {
    "CE_1_2": [
        "ce_1_2",
        "ce 1 2",
        "mfa",
        "multi factor authentication",
        "multi-factor authentication",
        "access control",
        "iam",
        "identity"
    ],
    "CE_2_1": [
        "ce_2_1",
        "ce 2 1",
        "secure configuration",
        "s3",
        "bucket",
        "storage",
        "public bucket",
        "public storage"
    ],
    "CE_3_1": [
        "ce_3_1",
        "ce 3 1",
        "boundary firewall",
        "internet gateway",
        "network",
        "ssh",
        "security group",
        "public exposure"
    ],
}


def normalize_text(text):
    text = text.lower().strip()
    text = re.sub(r"[_\-]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text


def detect_control(query):
    q = normalize_text(query)

    for control_id, aliases in CONTROL_ALIASES.items():
        for alias in aliases:
            if alias in q:
                return control_id

    return None


def detect_intent(query):
    q = normalize_text(query)

    if any(phrase in q for phrase in [
        "what changed",
        "what has changed",
        "what changed since last scan",
        "show changes",
        "show drift",
        "drift",
        "difference from last scan"
    ]):
        return "show_drift"

    if any(phrase in q for phrase in [
        "score",
        "compliance score",
        "risk level",
        "overall score",
        "overall compliance"
    ]):
        return "show_score"

    if any(phrase in q for phrase in [
        "failed controls",
        "what failed",
        "show failed",
        "risky controls",
        "problems",
        "issues found"
    ]):
        return "show_failed"

    if any(phrase in q for phrase in [
        "passed controls",
        "what passed",
        "show passed",
        "healthy controls"
    ]):
        return "show_passed"

    if any(phrase in q for phrase in [
        "how do i fix",
        "how can i fix",
        "fix this",
        "how to fix",
        "remediate",
        "resolve"
    ]):
        return "fix_control"

    if any(phrase in q for phrase in [
        "why did",
        "why is",
        "why does",
        "why has",
        "reason for",
        "why failing",
        "why failed"
    ]):
        return "why_control_failed"

    if any(phrase in q for phrase in [
        "sra relevance",
        "legal relevance",
        "regulatory relevance",
        "legal view"
    ]):
        return "show_sra"
    
    if any(phrase in q for phrase in [
        "what should i fix",
        "what do i fix",
        "fix first",
        "where do i start",
        "most important",
        "highest priority",
        "what to fix",
        "priority",
        "start with",
        "first step",
        "what next"
    ]):
        return "fix_priority"

    if any(phrase in q for phrase in [
        "how am i doing",
        "how are we doing",
        "where do i stand",
        "how do i look",
        "overall status",
        "am i compliant",
        "are we compliant",
        "summary",
        "overview",
        "give me a summary",
        "show summary",
        "how is my compliance"
    ]):
        return "show_score"

    return "unknown"


def route_natural_language(query):
    intent = detect_intent(query)
    control_id = detect_control(query)

    if intent == "show_drift":
        return "what changed"

    if intent == "show_score":
        return "show compliance score"

    if intent == "show_failed":
        return "show failed controls"

    if intent == "show_passed":
        return "show passed controls"

    if intent == "show_sra" and control_id:
        return f"show sra relevance for {control_id}"

    if intent == "why_control_failed" and control_id:
        return f"why did {control_id} fail"

    if intent == "fix_control" and control_id:
        return f"how do i fix {control_id}"
    if intent == "fix_priority":
        return "show fix priority"
    return None
