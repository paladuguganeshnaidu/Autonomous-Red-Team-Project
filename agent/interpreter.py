import json
import logging
import requests
from typing import Any, Dict, List

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
    try:
        response = requests.post(
            str(getattr(config, "ollama_url", "http://localhost:11434/api/generate")),
            json={
                "model": str(getattr(config, "ollama_model", "mistral")),
                "prompt": prompt,
                "stream": False,
            },
            timeout=int(getattr(config, "llm_timeout", 180)),
        )
        response.raise_for_status()

        output = str(response.json().get("response", ""))
        
        start = output.find("{")
        end = output.rfind("}") + 1
        cleaned = output[start:end] if start != -1 and end > start else "{}"
        
        parsed = json.loads(cleaned)
        return {
            "intent": parsed.get("intent", "clarification"),
            "extracted_target": parsed.get("extracted_target", "")
        }
    except Exception as exc:
        logger.error(f"[ERROR] Intent interpreter failed: {exc}")
        return {"intent": "clarification", "extracted_target": ""}
