from ..rag.retrieval.retriever import retrieve_guidance
from .persona_engine import apply_persona_view


def get_priority(severity):
    if severity == "HIGH":
        return "High - address before production exposure or continued operational use."
    if severity == "MEDIUM":
        return "Medium - address in the next remediation cycle."
    return "Low - review and address as part of routine hardening."


def build_guidance_answer(control_id, control_data, docs, persona="technical", sector="general"):
    name = control_data.get("name", control_id)
    reason = control_data.get("plain_english_fail", "")
    risk = control_data.get("risk", "")
    recommendation = control_data.get("recommendation", "")
    triggered = control_data.get("triggered_signals", [])
    affected_resources = control_data.get("affected_resources", [])
    severity = control_data.get("severity", "MEDIUM")

    lines = []
    lines.append(f"Control: {control_id} - {name}")
    lines.append("")

    lines.append(apply_persona_view(
        persona=persona,
        control_name=name,
        reason=reason,
        risk=risk,
        recommendation=recommendation,
        resources=affected_resources
    ))
    lines.append("")

    lines.append("Priority:")
    lines.append(get_priority(severity))
    lines.append("")

    lines.append(f"Triggered signals: {', '.join(triggered) if triggered else 'None'}")
    lines.append("")

    if affected_resources:
        lines.append("Affected resources:")
        for r in affected_resources:
            lines.append(f"- {r}")
        lines.append("")

    if docs:
        for doc in docs:
            lines.append(f"Guidance: {doc.get('title', 'Guidance')}")
            lines.append(doc.get("content", "").strip())
            lines.append("")

    if sector == "legal":
        lines.append("Sector note:")
        lines.append("This issue should be reviewed with confidentiality, client-data handling, and evidence expectations in mind.")
        lines.append("")

    lines.append("Next step:")
    lines.append("Apply the remediation sequence, then re-run CloudGuardian to confirm the control passes.")

    return "\n".join(lines)


def get_guidance_for_control(control_id, control_data, persona="technical", sector="general", query=""):
    docs = retrieve_guidance(
        control_id=control_id,
        triggered_signals=control_data.get("triggered_signals", []),
        persona=persona,
        sector=sector,
        query=query,
    )

    return build_guidance_answer(
        control_id=control_id,
        control_data=control_data,
        docs=docs,
        persona=persona,
        sector=sector,
    )
