def apply_persona_view(persona, control_name, reason, risk, recommendation, resources):
    persona = persona.lower()

    resources_text = ", ".join(resources) if resources else "No specific resources identified"

    if persona == "executive":
        return (
            f"{control_name} has failed.\n"
            f"Business Impact: {risk}\n"
            f"Affected Areas: {resources_text}\n"
            f"Recommended action: {recommendation}"
        )

    if persona == "legal":
        return (
            f"{control_name} has failed.\n"
            f"Compliance View: {reason}\n"
            f"Confidentiality / regulatory concern: {risk}\n"
            f"Affected Areas: {resources_text}\n"
            f"Recommended action: {recommendation}"
        )

    # technical default
    return (
        f"{control_name} has failed.\n"
        f"Technical Cause: {reason}\n"
        f"Affected Resources: {resources_text}\n"
        f"Recommended remediation: {recommendation}"
    )
