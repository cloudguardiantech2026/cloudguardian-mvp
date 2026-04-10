from engine.rag_engine import get_guidance_for_control


def handle_query(query, results, drift, score_data, persona="technical", sector="general"):
    q = query.strip().lower()

    if q in ["help", "?"]:
        return (
            "Available commands:\n"
            "- show failed controls\n"
            "- show passed controls\n"
            "- show compliance score\n"
            "- why did ce_2_1 fail\n"
            "- how do i fix ce_2_1\n"
            "- what changed\n"
            "- exit"
        )

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
            return (
                f"{control_id} failed.\n"
                f"Control: {data['name']}\n"
                f"Reason: {data['plain_english_fail']}\n"
                f"Risk: {data['risk']}\n"
                f"Recommendation: {data['recommendation']}\n"
                f"Triggered Signals: {', '.join(data['triggered_signals'])}"
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
                persona=persona,
                sector=sector,
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
