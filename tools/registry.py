"""Registry of dynamic recon tools used by the conversational copilot."""

from __future__ import annotations

from dataclasses import dataclass
import shlex
import subprocess
import time
from typing import Any, Dict, List, Protocol

from tools.dirsearch_tool import run_dirsearch
from tools.httpx_tool import run_httpx_probe
from tools.nmap_tool import run_nmap
from tools.subdomain_tool import run_subdomain_enum


@dataclass
class ToolResult:
    """Structured result returned by every registered tool."""

    tool: str
    target: str
    command: str
    exit_code: int
    raw_output: str
    duration_sec: float
    data: Dict[str, Any]
    error: str = ""


class Tool(Protocol):
    """Protocol for dynamically invokable tools."""

    name: str

    def run(self, intent: Dict[str, Any], config: Any) -> ToolResult:
        """Run the tool with a parsed intent."""


class NmapTool:
    name = "nmap"

    def run(self, intent: Dict[str, Any], config: Any) -> ToolResult:
        target = str(intent.get("target", "")).strip()
        extra_args = intent.get("resolved_args", []) if isinstance(intent.get("resolved_args"), list) else []
        payload = run_nmap(
            target=target,
            nmap_path=getattr(config, "nmap_path", "nmap"),
            timeout=int(getattr(config, "command_timeout", 120)),
            extra_args=extra_args or ["-sV", "-Pn"],
        )
        return ToolResult(
            tool=self.name,
            target=target,
            command=str(payload.get("command", "")),
            exit_code=int(payload.get("exit_code", -1) or -1),
            raw_output=str(payload.get("raw_output", "")),
            duration_sec=float(payload.get("duration_sec", 0.0) or 0.0),
            data=payload,
            error=str(payload.get("error", "")),
        )


class SubfinderTool:
    name = "subfinder"

    def run(self, intent: Dict[str, Any], config: Any) -> ToolResult:
        target = str(intent.get("target", "")).strip()
        payload = run_subdomain_enum(
            domain=target,
            subfinder_path=getattr(config, "subfinder_path", "subfinder"),
            timeout=int(getattr(config, "command_timeout", 120)),
        )
        return ToolResult(
            tool=self.name,
            target=target,
            command=str(payload.get("command", "")),
            exit_code=int(payload.get("exit_code", -1) or -1),
            raw_output=str(payload.get("raw_output", "")),
            duration_sec=float(payload.get("duration_sec", 0.0) or 0.0),
            data=payload,
            error=str(payload.get("error", "")),
        )


class HttpxTool:
    name = "httpx"

    def run(self, intent: Dict[str, Any], config: Any) -> ToolResult:
        target = str(intent.get("target", "")).strip()
        payload = run_httpx_probe(
            urls=[target],
            httpx_path=getattr(config, "httpx_path", "httpx"),
            timeout=int(getattr(config, "request_timeout", 10)),
            user_agent=(getattr(config, "user_agents", []) or ["AutonomousReconAgent/1.0"])[0],
        )
        command = f"{getattr(config, 'httpx_path', 'httpx')} -u {target}"
        return ToolResult(
            tool=self.name,
            target=target,
            command=command,
            exit_code=int(payload.get("exit_code", -1) or -1),
            raw_output=str(payload),
            duration_sec=float(payload.get("duration_sec", 0.0) or 0.0),
            data=payload,
            error=str(payload.get("error", "")),
        )


class FfufTool:
    name = "ffuf"

    def run(self, intent: Dict[str, Any], config: Any) -> ToolResult:
        target = str(intent.get("target", "")).strip()
        payload = run_dirsearch(
            base_url=target,
            ffuf_path=getattr(config, "ffuf_path", "ffuf"),
            wordlist=getattr(config, "dirsearch_wordlist", ""),
            match_codes=getattr(config, "dirsearch_match_codes", "200,204,301,302,307,401,403"),
            timeout=int(getattr(config, "command_timeout", 120)),
            max_time=int(getattr(config, "dirsearch_max_time", 90)),
            rate=int(getattr(config, "dirsearch_rate", 25)),
        )
        return ToolResult(
            tool=self.name,
            target=target,
            command=str(payload.get("command", "")),
            exit_code=int(payload.get("exit_code", -1) or -1),
            raw_output=str(payload.get("raw_output", "")),
            duration_sec=float(payload.get("duration_sec", 0.0) or 0.0),
            data=payload,
            error=str(payload.get("error", "")),
        )


class ShellTool:
    name = "shell"

    def run(self, intent: Dict[str, Any], config: Any) -> ToolResult:
        command = str(intent.get("command", "")).strip()
        target = str(intent.get("target", "")).strip()
        if not command:
            return ToolResult(
                tool=self.name,
                target=target,
                command="",
                exit_code=-1,
                raw_output="",
                duration_sec=0.0,
                data={},
                error="No shell command provided.",
            )

        started = time.time()
        try:
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=int(getattr(config, "command_timeout", 120)),
            )
            raw_output = (completed.stdout or "") + (completed.stderr or "")
            return ToolResult(
                tool=self.name,
                target=target,
                command=command,
                exit_code=int(completed.returncode),
                raw_output=raw_output[:8000],
                duration_sec=round(time.time() - started, 2),
                data={"findings": raw_output[:8000], "command": command, "exit_code": completed.returncode},
                error="",
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return ToolResult(
                tool=self.name,
                target=target,
                command=command,
                exit_code=-1,
                raw_output="",
                duration_sec=round(time.time() - started, 2),
                data={"command": command},
                error=str(exc),
            )


TOOL_MAP: Dict[str, Tool] = {
    "nmap": NmapTool(),
    "subfinder": SubfinderTool(),
    "httpx": HttpxTool(),
    "ffuf": FfufTool(),
    "dirsearch": FfufTool(),
    "shell": ShellTool(),
}


def build_shell_command(parts: List[str]) -> str:
    """Build a shell-safe string representation of a command."""
    return " ".join(shlex.quote(str(part)) for part in parts if str(part).strip())
