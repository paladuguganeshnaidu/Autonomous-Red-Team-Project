"""LLM-powered analysis helpers for conversational tool results."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List

from core.llm import generate_json


def analyse_tool_output(tool_name: str, target: str, raw_output: str, config: Any) -> Dict[str, Any]:
    """Analyse a single tool output into a user-facing summary."""
    prompt = f"""
You are a senior penetration tester.
Analyse the following {tool_name} output for target {target}.
Return STRICT JSON:
{{
  "summary": "<short operator-facing summary>",
  "findings": ["<important finding>"],
  "risks": ["<risk or vulnerability>"],
  "next_steps": ["<recommended next step>"]
}}

Raw Output:
{raw_output[:12000]}
"""
    parsed = generate_json(
        prompt,
        config,
        default={"summary": "", "findings": [], "risks": [], "next_steps": []},
        options={"num_predict": 350},
    )
    return {
        "summary": str(parsed.get("summary", "")).strip(),
        "findings": _string_list(parsed.get("findings", [])),
        "risks": _string_list(parsed.get("risks", [])),
        "next_steps": _string_list(parsed.get("next_steps", [])),
        **({"error": str(parsed.get("error"))} if parsed.get("error") else {}),
    }


def consolidate_analyses(items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge multiple tool analyses into a single summary payload."""
    summaries: List[str] = []
    findings: List[str] = []
    risks: List[str] = []
    next_steps: List[str] = []

    for item in items or []:
        if not isinstance(item, dict):
            continue
        summary = str(item.get("summary", "")).strip()
        if summary:
            summaries.append(summary)
        findings.extend(_string_list(item.get("findings", [])))
        risks.extend(_string_list(item.get("risks", [])))
        next_steps.extend(_string_list(item.get("next_steps", [])))

    return {
        "summary": " ".join(summaries).strip(),
        "findings": _dedupe(findings),
        "risks": _dedupe(risks),
        "next_steps": _dedupe(next_steps),
    }


def _string_list(values: Any) -> List[str]:
    if not isinstance(values, list):
        return []
    output: List[str] = []
    for value in values:
        clean = str(value).strip()
        if clean:
            output.append(clean)
    return output


def _dedupe(values: List[str]) -> List[str]:
    unique: List[str] = []
    for value in values:
        if value not in unique:
            unique.append(value)
    return unique
