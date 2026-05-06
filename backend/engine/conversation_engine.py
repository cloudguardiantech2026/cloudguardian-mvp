"""
CloudGuardian Grounded Conversational Engine
============================================
Uses the Anthropic API with live scan results injected as context.
The LLM can only answer based on the actual compliance state —
it cannot hallucinate findings or give generic security advice.
"""

import json
import os
import requests


ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-5"


def _build_compliance_context(results: dict, score_data: dict, drift: list) -> str:
    """Convert live scan results into a structured context string for the LLM."""

    lines = []

    # Overall score
    score = score_data.get("score", 0) if score_data else 0
    risk  = score_data.get("risk_level", "UNKNOWN") if score_data else "UNKNOWN"
    lines.append(f"COMPLIANCE SCORE: {score}%")
    lines.append(f"RISK LEVEL: {risk}")
    lines.append(f"OVERALL STATUS: {'COMPLIANT' if score == 100 else 'NON-COMPLIANT'}")
    lines.append("")

    # Control results
    lines.append("CONTROL RESULTS:")
    for cid, data in results.items():
        status   = data.get("status", "UNKNOWN")
        name     = data.get("name", cid)
        severity = data.get("severity", "UNKNOWN")
        lines.append(f"\n  {cid} — {name}: {status} [{severity}]")

        if status == "FAIL":
            lines.append(f"  Finding: {data.get('plain_english_fail', '')}")
            lines.append(f"  Business risk: {data.get('risk', '')}")
            lines.append(f"  Recommendation: {data.get('recommendation', '')}")
            affected = data.get("affected_resources", [])
            if affected:
                lines.append(f"  Affected resources: {', '.join(affected)}")
            signals = data.get("triggered_signals", [])
            if signals:
                lines.append(f"  Triggered by: {', '.join(signals)}")

    # Drift
    lines.append("\nCHANGES SINCE LAST SCAN:")
    if drift:
        for item in drift:
            lines.append(
                f"  {item.get('type', 'CHANGED')}: "
                f"{item.get('signal')} changed from "
                f"{item.get('from')} to {item.get('to')}"
            )
    else:
        lines.append("  No changes detected since last scan.")

    return "\n".join(lines)


def _build_system_prompt(compliance_context: str) -> str:
    return f"""You are CloudGuardian, an intelligent cloud compliance advisor for Cyber Essentials.

Your job is to help non-technical business owners understand their AWS cloud security compliance posture and take action to improve it.

STRICT RULES:
1. You ONLY answer questions about the compliance data provided below. Do not invent findings, resources, or issues that are not in the data.
2. Always use plain English. Never use jargon without explaining it immediately.
3. Be specific — always refer to the actual control IDs, resource names, and findings from the data.
4. Be concise but complete. Business owners are busy — get to the point.
5. If asked something outside the scope of the compliance data (e.g. general IT advice, pricing, unrelated topics), politely redirect: "I can only answer questions about your current compliance scan results."
6. Never make up remediation steps that aren't grounded in the findings below.
7. Always be encouraging — compliance is fixable. Frame findings as solvable problems, not disasters.
8. If the user seems confused or distressed about a finding, reassure them that CloudGuardian will guide them through fixing it.

TONE: Friendly, clear, professional. Like a trusted advisor — not a robot, not a lecturer.

CURRENT COMPLIANCE STATE FOR THIS ACCOUNT:
{compliance_context}

Answer the user's question based strictly on the above data."""


def handle_query(query: str, results: dict, drift: list, score_data: dict,
                 persona: str = "technical", sector: str = "general") -> str:
    """
    Handle a natural language compliance query using a grounded LLM.
    Falls back to a helpful message if the API is unavailable.
    """

    if not query or not query.strip():
        return "Please type a question about your compliance results."

    if not results:
        return (
            "I don't have any scan results to work with yet. "
            "Please run a compliance scan first, then ask me anything about your results."
        )

    if not ANTHROPIC_API_KEY:
        return (
            "The AI conversational engine requires an Anthropic API key. "
            "Please set the ANTHROPIC_API_KEY environment variable and restart the application."
        )

    # Build grounded context from live scan results
    compliance_context = _build_compliance_context(results, score_data, drift)
    system_prompt = _build_system_prompt(compliance_context)

    try:
        response = requests.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": MODEL,
                "max_tokens": 1024,
                "system": system_prompt,
                "messages": [
                    {"role": "user", "content": query.strip()}
                ],
            },
            timeout=30,
        )

        if response.status_code == 200:
            data = response.json()
            content = data.get("content", [])
            text_blocks = [block["text"] for block in content if block.get("type") == "text"]
            return "\n".join(text_blocks).strip() if text_blocks else "I received an empty response. Please try again."

        elif response.status_code == 401:
            return "API authentication failed. Please check your Anthropic API key."

        elif response.status_code == 429:
            return "The AI engine is temporarily busy. Please wait a moment and try again."

        else:
            error_detail = response.text[:500] if response.text else "no detail"
            return f"API error {response.status_code}: {error_detail}"

    except requests.exceptions.Timeout:
        return "The request timed out. Please check your internet connection and try again."

    except requests.exceptions.ConnectionError:
        return "Could not connect to the AI engine. Please check your internet connection."

    except Exception as e:
        return f"An unexpected error occurred: {str(e)}. Please try again."