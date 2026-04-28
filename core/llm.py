"""LLM-assisted vulnerability intelligence backed by Ollama/Mistral."""

from __future__ import annotations

import json
from typing import Any, Dict, List

import requests


def analyze_with_llm(state: dict, config: Any) -> dict:
    """Analyze structured scan state with LLM and return strict parsed JSON."""
    prompt = f"""
Analyze the following scan results:

{json.dumps(state, indent=2)}

Identify realistic vulnerabilities.
Return STRICT JSON.
"""
    import logging
    logger = logging.getLogger("autonomous_recon")
    logger.info("[LLM_PROMPT] %s", prompt)

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
        logger.info("[LLM_RESPONSE] %s", output)

        start = output.find("{")
        end = output.rfind("}") + 1
        cleaned = output[start:end] if start != -1 and end > start else "{}"

        parsed = json.loads(cleaned)
        if not isinstance(parsed, dict):
            return {"vulnerabilities": [], "next_actions": []}

        vulnerabilities = _normalize_vulnerabilities(parsed.get("vulnerabilities", []), state)
        next_actions = _normalize_next_actions(parsed.get("next_actions", []))

        return {
            "vulnerabilities": vulnerabilities,
            "next_actions": next_actions,
        }
    except Exception as exc:
        return {
            "vulnerabilities": [],
            "next_actions": [],
            "error": str(exc),
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

def plan_with_llm(state: dict, config: Any, memory_summary: str = "", recent_messages: List[Dict[str, Any]] = None) -> dict:
    """Use LLM to plan the exact OS command to execute next."""
    recent_messages = recent_messages or []
    
    context_str = f"Session Summary:\n{memory_summary}\n\nRecent Memory:\n" if memory_summary else "Recent Memory:\n"
    for m in recent_messages[-5:]:
        context_str += f"{m['role'].upper()}: {m['content']}\n"
        
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
    import logging
    logger = logging.getLogger("autonomous_recon")
    logger.info("[LLM_PROMPT] %s", prompt)

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
        logger.info("[LLM_RESPONSE] %s", output)

        start = output.find("{")
        end = output.rfind("}") + 1
        cleaned = output[start:end] if start != -1 and end > start else "{}"

        parsed = json.loads(cleaned)
        if not isinstance(parsed, dict) or "command" not in parsed:
            return {"action": "stop", "reason": "Failed to parse valid JSON from LLM for planning.", "score": 1.0}

        return {
            "action": "run_command",
            "command": parsed.get("command", ""),
            "target": parsed.get("target", state.get("target", "")),
            "reason": parsed.get("reason", "Decided by LLM"),
            "score": 1.0
        }
    except Exception as exc:
        logger.error(f"[ERROR] LLM planning failed: {exc}")
        return {"action": "stop", "reason": f"LLM error: {exc}", "score": 1.0}

def chat_with_agent(message: str, state: dict, history: list, config: Any) -> Any:
    """Send a user message to the LLM with the current recon state as context.
    Returns a dict with 'response', 'action', and 'command' keys."""
    
    # Build context from state, truncating large lists to save context size
    context_str = json.dumps({
        "target": state.get("target"),
        "subdomains_count": len(state.get("subdomains", [])),
        "subdomains_sample": state.get("subdomains", [])[:5],
        "ports": state.get("ports", []),
        "vulnerabilities": state.get("vulnerabilities", [])[:5]
    }, indent=2)

    prompt = f"""You are an elite autonomous red team agent. You are discussing the current security assessment with your human operator. Keep your answers concise, direct, and under 3 sentences unless asked for details.
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
    for msg in history[-5:]: # Keep last 5 messages for context
        prompt += f"{msg['role'].upper()}: {msg['content']}\n"
    
    prompt += f"USER: {message}\nAGENT:"

    import logging
    logger = logging.getLogger("autonomous_recon")
    logger.info(f"[CHAT_USER] {message}")

    try:
        response = requests.post(
            str(getattr(config, "ollama_url", "http://localhost:11434/api/generate")),
            json={
                "model": str(getattr(config, "ollama_model", "mistral")),
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": 150
                }
            },
            timeout=int(getattr(config, "llm_timeout", 180)),
        )
        response.raise_for_status()

        output = str(response.json().get("response", "")).strip()
        logger.info(f"[CHAT_AGENT_RAW] {output}")
        
        start = output.find("{")
        end = output.rfind("}") + 1
        if start != -1 and end > start:
            cleaned = output[start:end]
            parsed = json.loads(cleaned)
            return parsed
        else:
            return {"response": output, "action": "", "command": ""}

    except Exception as exc:
        logger.error(f"[ERROR] LLM chat failed: {exc}")
        return {"response": f"Error communicating with LLM: {exc}", "action": "", "command": ""}
