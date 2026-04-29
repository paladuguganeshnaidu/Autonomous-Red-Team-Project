"""Structured intent parsing for conversational scan requests."""

from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from core.llm import generate_json


SUPPORTED_TOOLS = {"nmap", "subfinder", "httpx", "ffuf", "dirsearch", "shell"}


def parse_intent(message: str, config: Any, history: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    """Parse a user request into a structured tool intent."""
    history = history or []
    heuristic = _heuristic_intent(message)
    prompt = _build_prompt(message, history)
    parsed = generate_json(
        prompt,
        config,
        default=heuristic,
        options={"num_predict": 260},
        max_retries=2,
    )

    intent = {
        "primary_tool": _normalize_tool(parsed.get("primary_tool") or heuristic.get("primary_tool", "")),
        "target": _extract_target(str(parsed.get("target", "")).strip()) or heuristic.get("target", ""),
        "scan_level": _normalize_scan_level(parsed.get("scan_level", heuristic.get("scan_level", 1))),
        "extra_args": _normalize_string_list(parsed.get("extra_args", heuristic.get("extra_args", []))),
        "followup_questions": _normalize_string_list(
            parsed.get("followup_questions", heuristic.get("followup_questions", []))
        ),
    }

    if not intent["primary_tool"]:
        intent["primary_tool"] = heuristic.get("primary_tool", "")
    if not intent["target"]:
        intent["target"] = heuristic.get("target", "")

    intent["resolved_args"] = resolve_tool_args(intent)
    intent["clarification_needed"] = bool(parsed.get("clarification_needed", False))
    intent["requires_confirmation"] = _requires_confirmation(intent)
    intent["summary"] = build_intent_summary(intent)

    if not intent["primary_tool"]:
        intent["clarification_needed"] = True
        intent["followup_questions"] = ["Which tool do you want me to use? For example: nmap, subfinder, httpx, or ffuf."]

    if not intent["target"]:
        intent["clarification_needed"] = True
        intent["followup_questions"] = ["Which target should I scan?"]

    if intent["primary_tool"] == "shell":
        intent["requires_confirmation"] = True

    return intent


def resolve_tool_args(intent: Dict[str, Any]) -> List[str]:
    """Resolve scan levels into concrete tool arguments."""
    tool = str(intent.get("primary_tool", "")).lower()
    scan_level = _normalize_scan_level(intent.get("scan_level", 1))
    extra_args = _normalize_string_list(intent.get("extra_args", []))

    if tool == "nmap":
        presets = {
            1: ["-sV", "-Pn"],
            2: ["-sV", "-Pn", "-T3", "--top-ports", "1000"],
            3: ["-sV", "-Pn", "-A", "-T3"],
            4: ["-A", "-T4", "-Pn", "-p-", "--script", "vuln"],
            5: ["-A", "-T4", "-Pn", "-p-", "-sS", "--script", "vuln,default"],
        }
        return presets.get(scan_level, presets[1]) + extra_args

    return extra_args


def build_intent_summary(intent: Dict[str, Any]) -> str:
    """Build a user-facing summary of the parsed request."""
    tool = str(intent.get("primary_tool", "unknown")).lower()
    target = str(intent.get("target", "unknown")).strip() or "unknown"
    level = _normalize_scan_level(intent.get("scan_level", 1))
    args = " ".join(str(arg) for arg in intent.get("resolved_args", []) if str(arg).strip())
    if tool == "nmap":
        return f"I will run Nmap level {level} on {target} with `{args} {target}`."
    if tool in {"ffuf", "dirsearch"}:
        return f"I will run ffuf-style content discovery against {target}."
    return f"I will run {tool} against {target}."


def _build_prompt(message: str, history: List[Dict[str, Any]]) -> str:
    conversation = []
    for item in history[-5:]:
        conversation.append(f"{item.get('role', 'user').upper()}: {item.get('content', '')}")

    return f"""
Extract the cybersecurity tool the user wants to run and the target. If any details are missing, ask for them.
Return STRICT JSON in this schema:
{{
  "primary_tool": "<nmap|subfinder|httpx|ffuf|dirsearch|shell|empty>",
  "target": "<target or empty>",
  "scan_level": <1-5>,
  "extra_args": ["<arg>"],
  "followup_questions": ["<question if needed>"],
  "clarification_needed": <true|false>
}}

Recent Conversation:
{chr(10).join(conversation)}

User Message: {message}
"""


def _heuristic_intent(message: str) -> Dict[str, Any]:
    text = str(message or "").strip()
    lowered = text.lower()
    tool = ""
    for candidate in ("nmap", "subfinder", "httpx", "ffuf", "dirsearch"):
        if candidate in lowered:
            tool = candidate
            break

    if not tool and any(token in lowered for token in ("scan", "vuln", "recon", "ports")):
        tool = "nmap"

    scan_level = 1
    match = re.search(r"\blevel\s*([1-5])\b", lowered)
    if match:
        scan_level = int(match.group(1))
    elif "intense" in lowered or "deep" in lowered:
        scan_level = 4

    return {
        "primary_tool": tool,
        "target": _extract_target(text),
        "scan_level": scan_level,
        "extra_args": [],
        "followup_questions": [],
        "clarification_needed": False,
    }


def _normalize_tool(tool: Any) -> str:
    clean = str(tool or "").strip().lower()
    return clean if clean in SUPPORTED_TOOLS else ""


def _normalize_scan_level(value: Any) -> int:
    try:
        level = int(value)
    except (TypeError, ValueError):
        level = 1
    return max(1, min(5, level))


def _normalize_string_list(values: Any) -> List[str]:
    if not isinstance(values, list):
        return []
    normalized: List[str] = []
    for value in values:
        clean = str(value).strip()
        if clean:
            normalized.append(clean)
    return normalized


def _requires_confirmation(intent: Dict[str, Any]) -> bool:
    tool = str(intent.get("primary_tool", "")).lower()
    level = _normalize_scan_level(intent.get("scan_level", 1))
    return tool == "nmap" and level >= 3


def _extract_target(message: str) -> str:
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
