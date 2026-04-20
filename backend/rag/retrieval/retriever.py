from pathlib import Path
import re


DOCS_PATH = Path("backend/rag/data/docs/playbooks")


def parse_doc(file_path):
    text = Path(file_path).read_text(encoding="utf-8")

    if not text.startswith("---"):
        return None

    parts = text.split("---", 2)
    if len(parts) < 3:
        return None

    metadata_block = parts[1].strip()
    content_block = parts[2].strip()

    metadata = {}
    for line in metadata_block.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            metadata[key.strip()] = value.strip()

    # normalize comma-separated fields
    for key in ["signals", "sector", "persona"]:
        if key in metadata:
            metadata[key] = [item.strip() for item in metadata[key].split(",") if item.strip()]
        else:
            metadata[key] = []

    metadata["content"] = content_block
    return metadata


def load_docs():
    docs = []
    for file_path in DOCS_PATH.glob("*.md"):
        parsed = parse_doc(file_path)
        if parsed:
            docs.append(parsed)
    return docs


def simple_keyword_score(query, content):
    query_terms = re.findall(r"\w+", query.lower())
    content_lower = content.lower()
    score = 0

    for term in query_terms:
        if term in content_lower:
            score += 1

    return score


def retrieve_guidance(control_id, triggered_signals, persona="technical", sector="general", query=""):
    docs = load_docs()
    ranked = []

    for doc in docs:
        score = 0

        # Hard filter-ish scoring
        if doc.get("control_id", "").upper() == control_id.upper():
            score += 50

        if persona in doc.get("persona", []):
            score += 10
        elif "technical" in doc.get("persona", []) and persona == "technical":
            score += 5

        if sector in doc.get("sector", []):
            score += 10
        elif "general" in doc.get("sector", []):
            score += 5

        signal_matches = set(triggered_signals).intersection(set(doc.get("signals", [])))
        score += len(signal_matches) * 5

        score += simple_keyword_score(query, doc.get("content", ""))

        ranked.append((score, doc))

    ranked.sort(key=lambda x: x[0], reverse=True)

    if not ranked:
        return []

    # return top 2 matching docs with non-zero score
    top = [doc for score, doc in ranked if score > 0][:2]
    return top
