"""Shared LLM prompt helpers backed by the robust client."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from core.llm_client import LLMUnavailableError, get_llm_client


logger = logging.getLogger("autonomous_recon")


def generate_text(
    prompt: str,
    config: Any,
    *,
    system: str = "",
    options: Dict[str, Any] | None = None,
    max_retries: int | None = None,
) -> str:
    """Generate text from the configured LLM backend."""
    logger.info("[LLM_PROMPT] %s", prompt)
    client = get_llm_client(config)
    try:
        output = client.generate(
            prompt,
            system=system,
            options=options,
            max_retries=max_retries,
            timeout=(
                int(getattr(config, "llm_connect_timeout", 5)),
                int(getattr(config, "llm_read_timeout", 30)),
            ),
            stream=True,
        )
        logger.info("[LLM_RESPONSE] %s", output)
        return output
    except LLMUnavailableError as exc:
        logger.error("[ERROR] LLM request failed: %s", exc)
        raise


def generate_json(
    prompt: str,
    config: Any,
    *,
    system: str = "",
    options: Dict[str, Any] | None = None,
    default: Dict[str, Any] | None = None,
    max_retries: int | None = None,
) -> Dict[str, Any]:
    """Generate JSON from the configured LLM backend with safe fallback parsing."""
    default_payload = default or {}
    try:
        text = generate_text(
            prompt,
            config,
            system=system,
            options=options,
            max_retries=max_retries,
        )
    except LLMUnavailableError as exc:
        payload = dict(default_payload)
        payload.setdefault("error", str(exc))
        return payload

    start = text.find("{")
    end = text.rfind("}") + 1
    cleaned = text[start:end] if start != -1 and end > start else "{}"

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        payload = dict(default_payload)
        payload.setdefault("error", f"Failed to parse JSON response: {exc}")
        payload.setdefault("raw_response", text)
        return payload

    if not isinstance(parsed, dict):
        payload = dict(default_payload)
        payload.setdefault("error", "LLM returned non-dictionary JSON.")
        payload.setdefault("raw_response", text)
        return payload

    return parsed


def analyze_with_llm(state: dict, config: Any) -> dict:
    """Analyze structured scan state with LLM and return strict parsed JSON."""
    prompt = f"""
Analyze the following scan results:

{json.dumps(state, indent=2)}

Identify realistic vulnerabilities and practical next actions.
Return STRICT JSON in the form:
{{
  "vulnerabilities": [
    {{
      "name": "<finding title>",
      "target": "<host or URL>",
      "evidence": "<supporting evidence>",
      "severity": "<critical|high|medium|low|info>",
      "confidence": <0.0-1.0>,
      "reasoning": "<why this matters>",
      "fix": "<remediation advice>"
    }}
  ],
  "next_actions": ["<next step>"]
}}
"""
    parsed = generate_json(
        prompt,
        config,
        default={"vulnerabilities": [], "next_actions": []},
        options={"num_predict": 400},
    )

    vulnerabilities = _normalize_vulnerabilities(parsed.get("vulnerabilities", []), state)
    next_actions = _normalize_next_actions(parsed.get("next_actions", []))
    result = {
        "vulnerabilities": vulnerabilities,
        "next_actions": next_actions,
    }
    if parsed.get("error"):
        result["error"] = str(parsed.get("error"))
    return result


def plan_with_llm(
    state: dict,
    config: Any,
    memory_summary: str = "",
    recent_messages: List[Dict[str, Any]] | None = None,
) -> dict:
    """Use LLM to plan the exact OS command to execute next."""
    recent_messages = recent_messages or []

    context_str = f"Session Summary:\n{memory_summary}\n\nRecent Memory:\n" if memory_summary else "Recent Memory:\n"
    for msg in recent_messages[-5:]:
        context_str += f"{msg['role'].upper()}: {msg['content']}\n"

    prompt = f"""
You are an autonomous red team agent. Your goal is to map the attack surface and find vulnerabilities.
Current State:
{json.dumps(state, indent=2)}

{context_str}

Decide the single next best terminal command to run to increase the level of scanning.
You can use tools like nmap, subfinder, httpx, ffuf, curl, dig, etc.
Return a STRICT JSON object with the following schema:
{{
  "action": "run_command",
  "command": "<exact shell command to execute>",
  "target": "<the target of the command>",
  "reason": "<why this command is useful>"
}}
"""
    parsed = generate_json(
        prompt,
        config,
        default={"action": "stop", "reason": "Planner failed to return valid JSON.", "score": 1.0},
        options={"num_predict": 250},
    )

    if parsed.get("command"):
        return {
            "action": "run_command",
            "command": str(parsed.get("command", "")).strip(),
            "target": str(parsed.get("target", state.get("target", ""))).strip(),
            "reason": str(parsed.get("reason", "Decided by LLM")).strip(),
            "score": 1.0,
        }

    error = str(parsed.get("error", "")).strip()
    if error:
        return {"action": "stop", "reason": error, "score": 1.0}
    return {"action": "stop", "reason": "Failed to parse valid JSON from LLM for planning.", "score": 1.0}


def chat_with_agent(message: str, state: dict, history: list, config: Any) -> Dict[str, Any]:
    """Send a user message to the LLM with the current recon state as context."""
    context_str = json.dumps(
        {
            "target": state.get("target"),
            "subdomains_count": len(state.get("subdomains", [])),
            "subdomains_sample": state.get("subdomains", [])[:5],
            "ports": state.get("ports", []),
            "vulnerabilities": state.get("vulnerabilities", [])[:5],
            "summary": state.get("summary", "No summary available."),
        },
        indent=2,
    )

    prompt = f"""You are an elite autonomous red team agent. You are discussing the current security assessment with your human operator.
Keep your answers concise, direct, and under 3 sentences unless asked for details.
If the operator asks you to execute a command, scan, or perform an action, provide the appropriate shell command.
ALWAYS respond with a STRICT JSON object matching this exact schema:
{{
  "response": "<your conversational reply to the user>",
  "action": "<'run_command' if there is a command to execute, else ''>",
  "command": "<the exact shell command to run, if applicable, else ''>"
}}

Current Assessment State:
{context_str}

Recent Conversation:
"""
    for msg in history[-5:]:
        prompt += f"{msg['role'].upper()}: {msg['content']}\n"
    prompt += f"USER: {message}\nAGENT:"

    logger.info("[CHAT_USER] %s", message)
    parsed = generate_json(
        prompt,
        config,
        default={"response": "", "action": "", "command": ""},
        options={"num_predict": 180},
    )
    return {
        "response": str(parsed.get("response", "")).strip(),
        "action": str(parsed.get("action", "")).strip(),
        "command": str(parsed.get("command", "")).strip(),
        **({"error": str(parsed.get("error"))} if parsed.get("error") else {}),
    }


def _normalize_vulnerabilities(values: Any, state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize LLM vulnerability items into stable internal schema."""
    if not isinstance(values, list):
        return []

    normalized: List[Dict[str, Any]] = []
    seen = set()
    default_target = str(state.get("target", "")).strip()

    for item in values:
        if not isinstance(item, dict):
            continue

        name = str(item.get("name", "")).strip()
        target = str(item.get("target", default_target)).strip() or default_target
        evidence = str(item.get("evidence", "")).strip()
        severity = str(item.get("severity", "medium")).strip().lower() or "medium"
        reasoning = str(item.get("reasoning", "")).strip()
        fix = str(item.get("fix", "")).strip()

        try:
            confidence = float(item.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0

        confidence = max(0.0, min(1.0, confidence))

        if not name:
            continue

        key = (name, target, evidence)
        if key in seen:
            continue
        seen.add(key)

        normalized.append(
            {
                "title": name,
                "name": name,
                "target": target,
                "asset": target,
                "evidence": evidence,
                "severity": severity,
                "confidence": confidence,
                "reasoning": reasoning,
                "fix": fix,
                "recommendation": fix,
                "source": "llm",
            }
        )

    return normalized


def _normalize_next_actions(values: Any) -> List[str]:
    """Normalize LLM next action suggestions to unique string list."""
    if not isinstance(values, list):
        return []

    normalized: List[str] = []
    for value in values:
        clean = str(value).strip()
        if clean and clean not in normalized:
            normalized.append(clean)
    return normalized
