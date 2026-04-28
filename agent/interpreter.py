import json
import logging
import re
import requests
from typing import Any, Dict, List
from urllib.parse import urlparse

logger = logging.getLogger("autonomous_recon")

def classify_intent(message: str, memory_summary: str, recent_messages: List[Dict[str, Any]], config: Any) -> Dict[str, str]:
    """
    Classify the user's intent into: new_scan, follow_up, meta, or clarification.
    Returns a dict with 'intent' and 'extracted_target' (if any).
    """
    context = f"Session Summary: {memory_summary}\n\nRecent Messages:\n"
    for msg in recent_messages[-5:]:
        context += f"{msg['role'].upper()}: {msg['content']}\n"
        
    prompt = f"""
You are an intent interpreter for an autonomous red team agent.
Given the conversation context and the user's new message, classify the intent of the message into exactly one of these categories:
- "new_scan": The user wants to start a new scan or action on a target.
- "follow_up": The user is asking a question about previous findings or scans in the memory.
- "meta": The user is issuing a system command like save, load, list, or clear.
- "clarification": The user's request is ambiguous, or they are answering a clarification question from the agent.

Also, extract the 'target' if the user mentions one (e.g., example.com). If none, leave it empty.

Context:
{context}

User Message: {message}

Return a STRICT JSON object:
{{
  "intent": "<new_scan|follow_up|meta|clarification>",
  "extracted_target": "<target or empty>"
}}
"""
    heuristic = _heuristic_intent(message)

    try:
        response = requests.post(
            str(getattr(config, "ollama_url", "http://localhost:11434/api/generate")),
            json={
                "model": str(getattr(config, "ollama_model", "mistral")),
                "prompt": prompt,
                "stream": False,
            },
            timeout=min(12, int(getattr(config, "llm_timeout", 180))),
        )
        response.raise_for_status()

        output = str(response.json().get("response", ""))
        
        start = output.find("{")
        end = output.rfind("}") + 1
        cleaned = output[start:end] if start != -1 and end > start else "{}"
        
        parsed = json.loads(cleaned)
        intent = str(parsed.get("intent", heuristic["intent"])).strip().lower()
        if intent not in {"new_scan", "follow_up", "meta", "clarification"}:
            intent = heuristic["intent"]

        return {
            "intent": intent,
            "extracted_target": parsed.get("extracted_target", "") or heuristic["extracted_target"]
        }
    except Exception as exc:
        logger.error(f"[ERROR] Intent interpreter failed: {exc}")
        return heuristic


def _heuristic_intent(message: str) -> Dict[str, str]:
    """Fallback intent parser so scan requests work even without the LLM."""
    text = str(message or "").strip()
    lowered = text.lower()
    target = _extract_target(text)

    meta_keywords = {"save", "load", "list", "clear"}
    if lowered.startswith("/"):
        return {"intent": "meta", "extracted_target": target}
    if any(re.search(rf"\b{keyword}\b", lowered) for keyword in meta_keywords):
        return {"intent": "meta", "extracted_target": target}

    scan_keywords = ("scan", "recon", "enumerate", "probe", "assess", "test")
    wants_scan = any(keyword in lowered for keyword in scan_keywords)

    if target and wants_scan:
        return {"intent": "new_scan", "extracted_target": target}

    if target and ("report" in lowered or "findings" in lowered) and wants_scan:
        return {"intent": "new_scan", "extracted_target": target}

    if any(keyword in lowered for keyword in ("report", "findings", "summary", "commands", "what did you run")):
        return {"intent": "follow_up", "extracted_target": target}

    if target and any(keyword in lowered for keyword in ("start", "run", "check")):
        return {"intent": "new_scan", "extracted_target": target}

    return {"intent": "clarification", "extracted_target": target}


def _extract_target(message: str) -> str:
    """Extract a likely host/domain target from free-form user text."""
    text = str(message or "").strip()
    if not text:
        return ""

    url_match = re.search(r"(https?://[^\s]+)", text, re.IGNORECASE)
    if url_match:
        value = url_match.group(1).rstrip(".,)")
        parsed = urlparse(value)
        return (parsed.hostname or value).strip().lower()

    domain_match = re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
    if domain_match:
        return domain_match.group(0).strip().lower()

    return ""
