from .rag_engine import get_guidance_for_control


CURRENT_PERSONA = "technical"
CURRENT_SECTOR = "general"


def handle_query(query, results, drift, score_data, persona=None, sector=None):
    global CURRENT_PERSONA, CURRENT_SECTOR

    if persona is None:
        persona = CURRENT_PERSONA
    if sector is None:
        sector = CURRENT_SECTOR

    q = query.strip().lower()

    if q in ["help", "?"]:
        return (
            "Available commands:\n"
            "- show failed controls\n"
            "- show passed controls\n"
            "- show compliance score\n"
            "- why did ce_2_1 fail\n"
            "- how do i fix ce_2_1\n"
            "- show sra relevance for ce_2_1\n"
            "- set persona executive\n"
            "- set persona technical\n"
            "- set persona legal\n"
            "- set sector general\n"
            "- set sector legal\n"
            "- what changed\n"
            "- exit"
        )

    if q.startswith("set persona "):
        new_persona = q.replace("set persona ", "").strip().lower()
        if new_persona in ["executive", "technical", "legal"]:
            CURRENT_PERSONA = new_persona
            return f"Persona set to {CURRENT_PERSONA}."
        return "Unsupported persona. Use executive, technical, or legal."

    if q.startswith("set sector "):
        new_sector = q.replace("set sector ", "").strip().lower()
        if new_sector in ["general", "legal"]:
            CURRENT_SECTOR = new_sector
            return f"Sector set to {CURRENT_SECTOR}."
        return "Unsupported sector. Use general or legal."

    if q == "show failed controls":
        failed = [f"{cid} - {data['name']}" for cid, data in results.items() if data["status"] == "FAIL"]
        if not failed:
            return "No failed controls."
        return "Failed controls:\n" + "\n".join(failed)

    if q == "show passed controls":
        passed = [f"{cid} - {data['name']}" for cid, data in results.items() if data["status"] == "PASS"]
        if not passed:
            return "No passed controls."
        return "Passed controls:\n" + "\n".join(passed)

    if q == "show compliance score":
        return (
            f"Overall Compliance Score: {score_data['score']}%\n"
            f"Risk Level: {score_data['risk_level']}"
        )

    if q.startswith("why did "):
        control_id = q.replace("why did ", "").replace(" fail", "").strip().upper()

        if control_id in results:
            data = results[control_id]
            if data["status"] == "PASS":
                return f"{control_id} passed. No failing signals were detected."

            response = (
                f"{control_id} failed.\n"
                f"Control: {data['name']}\n"
                f"Reason: {data['plain_english_fail']}\n"
                f"Risk: {data['risk']}\n"
                f"Recommendation: {data['recommendation']}\n"
                f"Triggered Signals: {', '.join(data['triggered_signals'])}\n"
                f"Affected Resources: {', '.join(data['affected_resources']) if data['affected_resources'] else 'None'}"
            )

            if sector == "legal":
                sra = data.get("framework_mappings", {}).get("sra", {})
                if sra:
                    response += (
                        f"\nSRA Area: {sra.get('area', 'N/A')}"
                        f"\nSRA Relevance: {sra.get('relevance', 'N/A')}"
                    )

            return response

        return f"No control found with ID {control_id}."

    if q.startswith("show sra relevance for "):
        control_id = q.replace("show sra relevance for ", "").strip().upper()

        if control_id in results:
            sra = results[control_id].get("framework_mappings", {}).get("sra", {})
            if not sra:
                return f"No SRA mapping found for {control_id}."
            return (
                f"SRA Area: {sra.get('area', 'N/A')}\n"
                f"SRA Relevance: {sra.get('relevance', 'N/A')}"
            )

        return f"No control found with ID {control_id}."

    if q.startswith("how do i fix "):
        control_id = q.replace("how do i fix ", "").strip().upper()

        if control_id in results:
            data = results[control_id]
            if data["status"] == "PASS":
                return f"{control_id} is currently passing. No remediation guidance is needed."
            return get_guidance_for_control(
                control_id=control_id,
                control_data=data,
                persona=CURRENT_PERSONA,
                sector=CURRENT_SECTOR,
                query=query,
            )

        return f"No control found with ID {control_id}."

    if q == "what changed":
        if not drift:
            return "No changes detected since last scan."
        lines = []
        for change in drift:
            lines.append(
                f"{change['type']}: {change['signal']} changed from {change['from']} to {change['to']}"
            )
        return "Compliance drift detected:\n" + "\n".join(lines)

    return "I did not understand that query. Type 'help' for available commands."
