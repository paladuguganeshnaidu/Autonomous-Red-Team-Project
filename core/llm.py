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

    try:
        response = requests.post(
            str(getattr(config, "ollama_url", "http://localhost:11434/api/generate")),
            json={
                "model": str(getattr(config, "ollama_model", "mistral")),
                "prompt": prompt,
                "stream": False,
            },
            timeout=int(getattr(config, "llm_timeout", 45)),
        )
        response.raise_for_status()

        output = str(response.json().get("response", ""))

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
