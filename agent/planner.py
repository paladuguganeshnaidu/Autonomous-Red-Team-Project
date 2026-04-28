"""Scoring-based planner for adaptive autonomous recon decisions."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse


from core.llm import plan_with_llm

def decide_next_action(state: dict, config: Any, memory_summary: str = "", recent_messages: List[Dict[str, Any]] = None) -> dict:
    """Choose the next action using deterministic recon steps or the LLM planner."""
    if bool(getattr(config, "use_llm_planner", False)):
        return plan_with_llm(state, config, memory_summary=memory_summary, recent_messages=recent_messages)
    return _deterministic_plan(state)


def _deterministic_plan(state: Dict[str, Any]) -> Dict[str, Any]:
    """Run a stable, basic recon sequence without requiring the LLM planner."""
    target = str(state.get("target", "")).strip()
    if not target:
        return {"action": "stop", "reason": "No target was provided for the scan.", "score": 1.0}

    actions_taken = state.get("actions_taken", []) if isinstance(state.get("actions_taken"), list) else []
    primary_web_target = _preferred_web_target(state, target)

    candidates = [
        {
            "action": "run_subfinder",
            "command": f"subfinder -d {target} -silent",
            "target": target,
            "reason": "Enumerate subdomains to expand the reachable attack surface.",
            "score": 0.95,
        },
        {
            "action": "run_httpx",
            "command": f"httpx -u {primary_web_target}",
            "target": primary_web_target,
            "reason": "Probe the primary web target to confirm live endpoints and technologies.",
            "score": 0.9,
        },
        {
            "action": "run_nmap",
            "command": f"nmap -sV -Pn {target}",
            "target": target,
            "reason": "Identify open ports and exposed services on the target host.",
            "score": 0.88,
        },
        {
            "action": "run_dirsearch",
            "command": f"ffuf -u {primary_web_target.rstrip('/')}/FUZZ",
            "target": primary_web_target,
            "reason": "Check the live web surface for exposed files, panels, and interesting paths.",
            "score": 0.84,
        },
    ]

    for candidate in candidates:
        if _action_signature(candidate) not in actions_taken:
            return candidate

    return {
        "action": "stop",
        "reason": "Completed the basic recon sequence and there are no remaining deterministic steps.",
        "score": 1.0,
    }


def _preferred_web_target(state: Dict[str, Any], default_target: str) -> str:
    """Choose the best URL-like target for web probing."""
    endpoints = state.get("endpoints", []) if isinstance(state.get("endpoints"), list) else []
    for endpoint in endpoints:
        clean = str(endpoint).strip()
        if clean.startswith("http://") or clean.startswith("https://"):
            return clean.rstrip("/")

    target = str(default_target or "").strip()
    if target.startswith("http://") or target.startswith("https://"):
        return target.rstrip("/")

    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
        return f"https://{host}".rstrip("/")

    return f"https://{target.split('/')[0]}".rstrip("/")


def _action_signature(action: Dict[str, Any]) -> str:
    """Build the same stable action signature used by the main loop."""
    action_name = str(action.get("action", "")).strip().lower()
    target = _normalize_signature_target(str(action.get("target", "")).strip())
    return f"{action_name}::{target}"


def _normalize_signature_target(target: str) -> str:
    """Normalize action targets for duplicate detection."""
    clean = str(target or "").strip().lower()
    if not clean:
        return ""

    if clean.startswith("http://") or clean.startswith("https://") or "://" in clean:
        parsed = urlparse(clean)
        return (parsed.hostname or clean).strip().lower()

    return clean.split("/")[0].strip().lower()

