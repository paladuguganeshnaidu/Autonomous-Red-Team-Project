"""Intent classification wrapper for legacy code paths."""

from __future__ import annotations

from typing import Any, Dict, List

from agent.intent_parser import parse_intent


def classify_intent(message: str, memory_summary: str, recent_messages: List[Dict[str, Any]], config: Any) -> Dict[str, str]:
    """Classify a user message into legacy intent buckets."""
    intent = parse_intent(message, config, recent_messages)
    if intent.get("primary_tool") and intent.get("target"):
        return {"intent": "new_scan", "extracted_target": str(intent.get("target", ""))}

    lowered = str(message or "").strip().lower()
    if lowered.startswith("/") or any(token in lowered for token in ("save", "load", "list", "clear")):
        return {"intent": "meta", "extracted_target": ""}

    if intent.get("clarification_needed"):
        return {"intent": "clarification", "extracted_target": str(intent.get("target", ""))}

    return {"intent": "follow_up", "extracted_target": str(intent.get("target", ""))}
