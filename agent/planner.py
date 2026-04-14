"""Scoring-based planner for adaptive autonomous recon decisions."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse


def decide_next_action(state: dict) -> dict:
    """Score candidate actions dynamically and return the best next action."""
    normalized = _normalize_state(state)
    target = _normalize_target(normalized.get("target", ""))

    if not target:
        return {
            "action": "stop",
            "target": "",
            "reason": "Missing target in state.",
            "score": 1.0,
        }

    if _has_high_conf_vulnerability(normalized):
        return {
            "action": "stop",
            "target": target,
            "reason": "High-confidence vulnerability already detected.",
            "score": 1.0,
        }

    if normalized["vulnerabilities"]:
        return {
            "action": "prioritize_exploit",
            "target": target,
            "reason": "Vulnerabilities detected. Prioritize exploit path.",
            "score": 0.95,
        }

    scores = {
        "run_subfinder": 0.9 if not normalized["subdomains"] else 0.1,
        "run_nmap": 0.8 if not normalized["ports"] else 0.2,
        "run_httpx": 0.75 if not normalized["technologies"] else 0.15,
        "run_dirsearch": 0.7 if _has_http_services(normalized["services"]) else 0.1,
    }

    action_history = normalized.get("action_history", [])
    for action_name in action_history:
        canonical_action = _canonical_action_name(action_name)
        if canonical_action in scores:
            scores[canonical_action] *= 0.5

    actions_taken_signatures = set(normalized.get("actions_taken", []))
    targets = {
        "run_subfinder": target,
        "run_nmap": _choose_nmap_target(normalized, target),
        "run_httpx": _choose_web_target(normalized, target),
        "run_dirsearch": _choose_web_target(normalized, target),
    }

    for action_name, action_target in targets.items():
        normalized_target = _normalize_target(action_target)
        canonical_signature = f"{action_name}::{normalized_target}"
        legacy_signature = f"{_legacy_action_name(action_name)}::{normalized_target}"
        if canonical_signature in actions_taken_signatures or legacy_signature in actions_taken_signatures:
            scores[action_name] *= 0.4

    best_action = max(scores, key=scores.get)
    best_score = float(scores[best_action])

    if best_score <= 0.05:
        return {
            "action": "stop",
            "target": target,
            "reason": "All action scores are too low after feedback penalties.",
            "score": round(best_score, 2),
        }

    reasons = {
        "run_subfinder": "Subdomains are missing or insufficient.",
        "run_nmap": "Port/service mapping is incomplete.",
        "run_httpx": "Technology intelligence is incomplete.",
        "run_dirsearch": "HTTP surface exists; endpoint fuzzing is prioritized.",
    }

    return {
        "action": best_action,
        "target": targets.get(best_action, target),
        "reason": reasons.get(best_action, "Highest dynamic score selected."),
        "score": round(best_score, 2),
    }


def _normalize_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize planner input state to expected schema."""
    normalized = {
        "target": str(state.get("target", "")).strip(),
        "subdomains": _as_str_list(state.get("subdomains", [])),
        "ports": _as_str_list(state.get("ports", [])),
        "services": state.get("services", []) if isinstance(state.get("services", []), list) else [],
        "technologies": _as_str_list(state.get("technologies", [])),
        "endpoints": _as_str_list(state.get("endpoints", [])),
        "vulnerabilities": state.get("vulnerabilities", []) if isinstance(state.get("vulnerabilities", []), list) else [],
        "actions_taken": _as_str_list(state.get("actions_taken", [])),
        "action_history": _normalize_action_history(state.get("action_history", [])),
    }
    return normalized


def _normalize_action_history(values: Any) -> List[str]:
    """Normalize action history entries to plain action-name strings."""
    if not isinstance(values, list):
        return []

    normalized: List[str] = []
    for item in values:
        if isinstance(item, dict):
            action_name = str(item.get("action", "")).strip().lower()
        else:
            action_name = str(item).strip().lower()
        action_name = _canonical_action_name(action_name)
        if action_name:
            normalized.append(action_name)
    return normalized


def _canonical_action_name(action_name: str) -> str:
    """Map legacy action aliases to current executor contract names."""
    aliases = {
        "subfinder": "run_subfinder",
        "nmap": "run_nmap",
        "httpx": "run_httpx",
        "dirsearch": "run_dirsearch",
    }
    clean = str(action_name or "").strip().lower()
    return aliases.get(clean, clean)


def _legacy_action_name(action_name: str) -> str:
    """Map current executor action names to legacy aliases for compatibility."""
    aliases = {
        "run_subfinder": "subfinder",
        "run_nmap": "nmap",
        "run_httpx": "httpx",
        "run_dirsearch": "dirsearch",
    }
    clean = str(action_name or "").strip().lower()
    return aliases.get(clean, clean)


def _as_str_list(values: Any) -> List[str]:
    """Convert list-like values to unique strings preserving order."""
    if not isinstance(values, list):
        return []

    normalized: List[str] = []
    for value in values:
        clean = str(value).strip()
        if clean and clean not in normalized:
            normalized.append(clean)
    return normalized


def _normalize_target(target: str) -> str:
    """Normalize host/url target to hostname format where possible."""
    raw = str(target or "").strip()
    if not raw:
        return ""

    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        return (parsed.hostname or raw).strip().lower()

    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or raw).strip().lower()

    return raw.split("/")[0].strip().lower()


def _has_http_services(services: List[Any]) -> bool:
    """Return True when state indicates HTTP service presence."""
    for service in services:
        if isinstance(service, str) and "http" in service.lower():
            return True
        if isinstance(service, dict):
            service_name = str(service.get("service", "")).lower()
            port = str(service.get("port", "")).strip()
            if "http" in service_name or port in {"80", "443", "8080", "8443", "8000", "3000"}:
                return True
    return False


def _choose_nmap_target(state: Dict[str, Any], fallback_target: str) -> str:
    """Choose nmap target preferring first discovered subdomain."""
    subdomains = state.get("subdomains", [])
    if subdomains:
        return subdomains[0]
    return fallback_target


def _choose_web_target(state: Dict[str, Any], fallback_target: str) -> str:
    """Choose web target from endpoints/services/subdomains in priority order."""
    endpoints = state.get("endpoints", [])
    if endpoints:
        endpoint = str(endpoints[0]).strip()
        if endpoint:
            return endpoint

    services = state.get("services", [])
    for service in services:
        if not isinstance(service, dict):
            continue
        host = str(service.get("host", "")).strip()
        if host:
            return host

    subdomains = state.get("subdomains", [])
    if subdomains:
        return str(subdomains[0]).strip()

    return fallback_target


def _has_high_conf_vulnerability(state: Dict[str, Any]) -> bool:
    """Detect stop-worthy vulnerability confidence in current state."""
    for vuln in state.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        try:
            confidence = float(vuln.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        if confidence >= 0.85:
            return True
    return False
