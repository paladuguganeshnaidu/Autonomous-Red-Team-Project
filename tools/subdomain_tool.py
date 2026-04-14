"""subfinder wrapper for structured subdomain enumeration output."""

from __future__ import annotations

import subprocess
import time
from typing import Any, Dict, List
from urllib.parse import urlparse


def run_subdomain_enum(domain: str, subfinder_path: str = "subfinder", timeout: int = 120) -> Dict[str, Any]:
    """Run subfinder against domain input and return normalized JSON output."""
    normalized_domain = _normalize_domain(domain)
    if not normalized_domain:
        return {
            "tool": "subdomain",
            "exit_code": -1,
            "error": "No domain provided to subdomain tool.",
            "subdomains": [],
            "raw_output": "",
            "command": "",
            "duration_sec": 0,
        }

    command = [subfinder_path, "-d", normalized_domain, "-silent"]
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
            "tool": "subdomain",
            "exit_code": completed.returncode,
            "error": "",
            "subdomains": _parse_subdomains(completed.stdout or ""),
            "raw_output": raw_output,
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except FileNotFoundError:
        return {
            "tool": "subdomain",
            "exit_code": -1,
            "error": f"subfinder executable not found: {subfinder_path}",
            "subdomains": [],
            "raw_output": "",
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or "") + (exc.stderr or "")
        return {
            "tool": "subdomain",
            "exit_code": -1,
            "error": f"subfinder timed out after {timeout}s",
            "subdomains": _parse_subdomains(exc.stdout or ""),
            "raw_output": partial,
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {
            "tool": "subdomain",
            "exit_code": -1,
            "error": str(exc),
            "subdomains": [],
            "raw_output": "",
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }


def _normalize_domain(domain: str) -> str:
    """Normalize raw domain/URL input to host-only domain string."""
    value = str(domain or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return (parsed.hostname or "").strip().lower()
    return value.split("/")[0].strip().lower()


def _parse_subdomains(stdout: str) -> List[str]:
    """Parse and deduplicate subfinder stdout lines."""
    parsed: List[str] = []
    for line in stdout.splitlines():
        clean = str(line).strip().lower()
        if clean and clean not in parsed:
            parsed.append(clean)
    return parsed
