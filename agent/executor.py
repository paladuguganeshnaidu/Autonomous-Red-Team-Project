"""Action executor that maps planner decisions to concrete tool calls."""

from __future__ import annotations

from typing import Any, Callable, Dict
from urllib.parse import urlparse

from tools.dirsearch_tool import run_dirsearch
from tools.httpx_tool import run_httpx_probe
from tools.nmap_tool import run_nmap
from tools.subdomain_tool import run_subdomain_enum


def execute_action(action: dict, config: Any) -> dict:
    """Execute one planner action and return a structured JSON result."""
    action_name = str(action.get("action", "")).strip().lower()
    target = str(action.get("target", "")).strip()

    if action_name in {"", "stop"}:
        return {
            "status": "skipped",
            "action": action_name or "stop",
            "target": target,
            "data": {"message": "No executable action requested."},
            "error": None,
            "attempts": 0,
        }

    if action_name == "prioritize_exploit":
        return {
            "status": "success",
            "action": action_name,
            "target": target,
            "data": {"message": "Exploit path prioritized for manual validation."},
            "error": None,
            "attempts": 1,
        }

    handlers: Dict[str, Callable[[str, Any], Dict[str, Any]]] = {
        "run_subfinder": _execute_subfinder,
        "run_nmap": _execute_nmap,
        "run_httpx": _execute_httpx,
        "run_dirsearch": _execute_dirsearch,
    }

    handler = handlers.get(action_name)
    if handler is None:
        return {
            "status": "failed",
            "action": action_name,
            "target": target,
            "data": {},
            "error": f"Unsupported action: {action_name}",
            "attempts": 0,
        }

    retries = min(2, max(0, int(getattr(config, "command_retries", 2))))
    max_attempts = retries + 1

    last_error = "Unknown execution failure"
    last_data: Dict[str, Any] = {}

    for attempt in range(1, max_attempts + 1):
        try:
            data = handler(target, config)
        except Exception as exc:
            data = {
                "tool": action_name,
                "exit_code": -1,
                "error": str(exc),
            }

        if _tool_succeeded(data):
            return {
                "status": "success",
                "action": action_name,
                "target": target,
                "data": data,
                "error": None,
                "attempts": attempt,
            }

        last_data = data
        last_error = str(data.get("error", "Tool returned no success signals."))

    return {
        "status": "failed",
        "action": action_name,
        "target": target,
        "data": last_data,
        "error": last_error,
        "attempts": max_attempts,
    }


def _execute_subfinder(target: str, config: Any) -> Dict[str, Any]:
    """Execute subdomain enumeration for the requested target."""
    return run_subdomain_enum(
        domain=target,
        subfinder_path=getattr(config, "subfinder_path", "subfinder"),
        timeout=int(getattr(config, "command_timeout", 120)),
    )


def _execute_nmap(target: str, config: Any) -> Dict[str, Any]:
    """Execute nmap service discovery for the requested target."""
    return run_nmap(
        target=target,
        nmap_path=getattr(config, "nmap_path", "nmap"),
        timeout=int(getattr(config, "command_timeout", 120)),
    )


def _execute_httpx(target: str, config: Any) -> Dict[str, Any]:
    """Execute HTTP probing and technology checks for a web target."""
    normalized_url = _normalize_web_target(target)
    user_agents = getattr(config, "user_agents", []) or ["AutonomousReconAgent/1.0"]

    return run_httpx_probe(
        urls=[normalized_url],
        httpx_path=getattr(config, "httpx_path", "httpx"),
        timeout=int(getattr(config, "request_timeout", 10)),
        user_agent=user_agents[0],
    )


def _execute_dirsearch(target: str, config: Any) -> Dict[str, Any]:
    """Execute directory/content discovery for a web target."""
    normalized_url = _normalize_web_target(target)

    return run_dirsearch(
        base_url=normalized_url,
        ffuf_path=getattr(config, "ffuf_path", "ffuf"),
        wordlist=getattr(config, "dirsearch_wordlist", ""),
        match_codes=getattr(config, "dirsearch_match_codes", "200,204,301,302,307,401,403"),
        timeout=int(getattr(config, "command_timeout", 120)),
        max_time=int(getattr(config, "dirsearch_max_time", 90)),
        rate=int(getattr(config, "dirsearch_rate", 25)),
    )


def _normalize_web_target(target: str) -> str:
    """Normalize any host/URL target into a valid URL string for web tools."""
    clean = str(target or "").strip()
    if not clean:
        return ""

    if clean.startswith("http://") or clean.startswith("https://"):
        return clean.rstrip("/")

    if "://" in clean:
        parsed = urlparse(clean)
        host = parsed.hostname or clean
        return f"https://{host}".rstrip("/")

    host = clean.split("/")[0]
    return f"https://{host}".rstrip("/")


def _tool_succeeded(data: Dict[str, Any]) -> bool:
    """Check if tool output contains successful execution signals."""
    raw_exit_code = data.get("exit_code", -1)
    exit_code = -1 if raw_exit_code is None else int(raw_exit_code)
    if exit_code == 0:
        return True

    if data.get("subdomains"):
        return True

    if data.get("ports"):
        return True

    responses = data.get("responses", [])
    if isinstance(responses, list):
        for response in responses:
            if int(response.get("status_code", 0) or 0) > 0:
                return True

    if data.get("findings"):
        return True

    return False
