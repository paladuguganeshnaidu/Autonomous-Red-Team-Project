"""nmap wrapper for structured port and service discovery output."""

from __future__ import annotations

import re
import subprocess
import time
from typing import Any, Dict, List


def run_nmap(target: str, nmap_path: str = "nmap", timeout: int = 120) -> Dict[str, Any]:
    """Run nmap service detection and return structured JSON-compatible output."""
    clean_target = str(target or "").strip()
    if not clean_target:
        return {
            "tool": "nmap",
            "exit_code": -1,
            "error": "No target provided to nmap tool.",
            "ports": [],
            "raw_output": "",
            "command": "",
            "duration_sec": 0,
        }

    command = [nmap_path, "-sV", "-Pn", clean_target]
    started = time.time()

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        raw_output = (completed.stdout or "") + (completed.stderr or "")
        return {
            "tool": "nmap",
            "exit_code": completed.returncode,
            "error": "",
            "ports": _parse_ports(raw_output),
            "raw_output": raw_output,
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except FileNotFoundError:
        return {
            "tool": "nmap",
            "exit_code": -1,
            "error": f"nmap executable not found: {nmap_path}",
            "ports": [],
            "raw_output": "",
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or "") + (exc.stderr or "")
        return {
            "tool": "nmap",
            "exit_code": -1,
            "error": f"nmap timed out after {timeout}s",
            "ports": _parse_ports(partial),
            "raw_output": partial,
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {
            "tool": "nmap",
            "exit_code": -1,
            "error": str(exc),
            "ports": [],
            "raw_output": "",
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }


def _parse_ports(raw_output: str) -> List[Dict[str, str]]:
    """Parse open port lines from nmap text output."""
    parsed: List[Dict[str, str]] = []
    for match in re.finditer(r"(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)", raw_output or ""):
        parsed.append(
            {
                "port": match.group(1),
                "protocol": match.group(2),
                "state": "open",
                "service": match.group(3),
            }
        )
    return parsed
