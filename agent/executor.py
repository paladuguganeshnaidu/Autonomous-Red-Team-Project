"""Tool executor supporting both legacy actions and conversational intents."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict
from urllib.parse import urlparse

from tools.registry import TOOL_MAP, ToolResult


def execute_action(action: Dict[str, Any], config: Any) -> Dict[str, Any]:
    """Execute one legacy planner action and return a structured JSON result."""
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

    legacy_map = {
        "run_subfinder": "subfinder",
        "run_nmap": "nmap",
        "run_httpx": "httpx",
        "run_dirsearch": "ffuf",
        "run_command": "shell",
    }
    tool_name = legacy_map.get(action_name)
    if not tool_name:
        return {
            "status": "failed",
            "action": action_name,
            "target": target,
            "data": {},
            "error": f"Unsupported action: {action_name}",
            "attempts": 0,
        }

    intent = {
        "primary_tool": tool_name,
        "target": _normalize_target_for_tool(tool_name, target),
        "command": str(action.get("command", "")).strip(),
        "resolved_args": action.get("resolved_args", []),
    }
    result = execute_intent(intent, config)
    return _tool_result_to_action_result(action_name, target, result)


def execute_intent(intent: Dict[str, Any], config: Any) -> ToolResult:
    """Execute a parsed conversational intent through the tool registry."""
    tool_name = str(intent.get("primary_tool", "")).strip().lower()
    tool = TOOL_MAP.get(tool_name)
    target = str(intent.get("target", "")).strip()

    if tool is None:
        return ToolResult(
            tool=tool_name or "unknown",
            target=target,
            command="",
            exit_code=-1,
            raw_output="",
            duration_sec=0.0,
            data={},
            error=f"Unsupported tool requested: {tool_name}",
        )

    try:
        return tool.run(intent, config)
    except OSError as exc:
        return ToolResult(
            tool=tool_name,
            target=target,
            command=str(intent.get("command", "")),
            exit_code=-1,
            raw_output="",
            duration_sec=0.0,
            data={},
            error=f"Tool process failed: {exc}",
        )
    except Exception as exc:
        return ToolResult(
            tool=tool_name,
            target=target,
            command=str(intent.get("command", "")),
            exit_code=-1,
            raw_output="",
            duration_sec=0.0,
            data={},
            error=str(exc),
        )


def _tool_result_to_action_result(action_name: str, target: str, result: ToolResult) -> Dict[str, Any]:
    """Convert a registry tool result into the legacy action result envelope."""
    data = dict(result.data)
    data.setdefault("command", result.command)
    data.setdefault("raw_output", result.raw_output)
    data.setdefault("duration_sec", result.duration_sec)
    data.setdefault("exit_code", result.exit_code)

    success = _tool_succeeded(data)
    return {
        "status": "success" if success else "failed",
        "action": action_name,
        "target": target,
        "data": data,
        "error": None if success else (result.error or "Tool returned no success signals."),
        "attempts": 1,
    }


def _normalize_target_for_tool(tool_name: str, target: str) -> str:
    """Normalize target based on tool expectations."""
    clean = str(target or "").strip()
    if tool_name in {"httpx", "ffuf", "dirsearch"}:
        return _normalize_web_target(clean)
    return clean


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

    findings = data.get("findings")
    if isinstance(findings, list) and findings:
        return True
    if isinstance(findings, str) and findings.strip():
        return True

    return False
