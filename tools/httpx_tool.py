"""HTTP probing wrapper that returns structured JSON data."""

from __future__ import annotations

import json
import subprocess
import time
from typing import Any, Dict, Iterable, List

import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
]


def run_httpx_probe(
    urls: Iterable[str],
    httpx_path: str = "httpx",
    timeout: int = 10,
    user_agent: str = "AutonomousReconAgent/1.0",
) -> Dict[str, Any]:
    """Probe HTTP endpoints and return normalized responses and technologies."""
    deduped_urls = _dedupe_urls(urls)
    started = time.time()
    responses: List[Dict[str, Any]] = []

    for url in deduped_urls:
        response = _probe_single_url(url=url, httpx_path=httpx_path, timeout=timeout, user_agent=user_agent)
        responses.append(response)

    has_success = any(int(item.get("status_code", 0) or 0) > 0 and not item.get("error") for item in responses)
    has_any_signal = any(int(item.get("status_code", 0) or 0) > 0 for item in responses)

    return {
        "tool": "httpx",
        "exit_code": 0 if has_success or has_any_signal else -1,
        "error": "" if has_success or has_any_signal else "All HTTP probes failed.",
        "responses": responses,
        "duration_sec": round(time.time() - started, 2),
    }


def _probe_single_url(url: str, httpx_path: str, timeout: int, user_agent: str) -> Dict[str, Any]:
    """Probe one URL with httpx and fallback requests headers check."""
    parsed_httpx = _run_httpx(url=url, httpx_path=httpx_path, timeout=timeout)
    fallback = _requests_fallback(url=url, timeout=timeout, user_agent=user_agent)

    status_code = int(parsed_httpx.get("status_code") or fallback.get("status_code", 0) or 0)
    url_value = str(parsed_httpx.get("url") or fallback.get("url") or url)

    missing_headers = fallback.get("missing_headers", SECURITY_HEADERS[:])
    tech_values = parsed_httpx.get("tech", []) if isinstance(parsed_httpx.get("tech", []), list) else []

    error_parts = []
    if parsed_httpx.get("error"):
        error_parts.append(str(parsed_httpx.get("error")))
    if fallback.get("error"):
        error_parts.append(str(fallback.get("error")))

    return {
        "url": url_value,
        "status_code": status_code,
        "title": str(parsed_httpx.get("title", "")),
        "webserver": str(parsed_httpx.get("webserver") or fallback.get("server", "")),
        "tech": tech_values,
        "missing_headers": missing_headers,
        "error": " | ".join(error_parts),
    }


def _run_httpx(url: str, httpx_path: str, timeout: int) -> Dict[str, Any]:
    """Run httpx for one URL and parse single-line JSON output."""
    command = [
        httpx_path,
        "-u",
        url,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-web-server",
        "-tech-detect",
        "-timeout",
        str(timeout),
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout + 5,
        )

        output_line = ""
        for line in (completed.stdout or "").splitlines():
            line = line.strip()
            if line:
                output_line = line
                break

        if not output_line:
            return {
                "error": (completed.stderr or "httpx returned no output").strip(),
            }

        payload = json.loads(output_line)
        return {
            "url": payload.get("url", url),
            "status_code": int(payload.get("status_code", 0) or 0),
            "title": payload.get("title", ""),
            "webserver": payload.get("webserver", ""),
            "tech": payload.get("tech", []) if isinstance(payload.get("tech", []), list) else [],
            "error": "",
        }
    except FileNotFoundError:
        return {"error": f"httpx executable not found: {httpx_path}"}
    except subprocess.TimeoutExpired:
        return {"error": f"httpx timed out after {timeout + 5}s"}
    except json.JSONDecodeError:
        return {"error": "httpx returned non-JSON output"}
    except Exception as exc:
        return {"error": str(exc)}


def _requests_fallback(url: str, timeout: int, user_agent: str) -> Dict[str, Any]:
    """Fallback HTTP request that extracts header posture even without httpx."""
    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
        )
        missing_headers = [header for header in SECURITY_HEADERS if header not in response.headers]
        return {
            "url": response.url,
            "status_code": response.status_code,
            "server": response.headers.get("Server", ""),
            "missing_headers": missing_headers,
            "error": "",
        }
    except Exception as exc:
        return {
            "url": url,
            "status_code": 0,
            "server": "",
            "missing_headers": SECURITY_HEADERS[:],
            "error": str(exc),
        }


def _dedupe_urls(urls: Iterable[str]) -> List[str]:
    """Deduplicate URL inputs while preserving order."""
    deduped: List[str] = []
    if isinstance(urls, str):
        urls = [urls]

    for url in urls or []:
        clean = str(url).strip()
        if clean and clean not in deduped:
            deduped.append(clean)
    return deduped
