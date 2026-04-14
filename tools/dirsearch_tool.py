"""Directory/content discovery wrapper implemented with ffuf."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from typing import Any, Dict


def run_dirsearch(
    base_url: str,
    ffuf_path: str = "ffuf",
    wordlist: str = "",
    match_codes: str = "200,204,301,302,307,401,403",
    timeout: int = 120,
    max_time: int = 90,
    rate: int = 25,
) -> Dict[str, Any]:
    """Run directory discovery and return structured JSON output."""
    started = time.time()
    target = str(base_url or "").strip().rstrip("/")

    if not target:
        return {
            "tool": "dirsearch",
            "exit_code": -1,
            "error": "No base URL provided for directory scan.",
            "findings": [],
            "duration_sec": 0,
            "command": "",
        }

    if not wordlist or not os.path.exists(wordlist):
        return {
            "tool": "dirsearch",
            "exit_code": -1,
            "error": f"Wordlist not found: {wordlist}",
            "findings": [],
            "duration_sec": round(time.time() - started, 2),
            "command": "",
        }

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    tmp.close()
    output_path = tmp.name

    command = [
        ffuf_path,
        "-u",
        f"{target}/FUZZ",
        "-w",
        wordlist,
        "-mc",
        match_codes,
        "-rate",
        str(rate),
        "-maxtime-job",
        str(max_time),
        "-of",
        "json",
        "-o",
        output_path,
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

        findings = []
        if os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            for item in payload.get("results", []):
                findings.append(
                    {
                        "url": item.get("url", ""),
                        "path": item.get("input", {}).get("FUZZ", ""),
                        "status": int(item.get("status", 0) or 0),
                        "length": int(item.get("length", 0) or 0),
                        "words": int(item.get("words", 0) or 0),
                        "lines": int(item.get("lines", 0) or 0),
                    }
                )

        error = ""
        if completed.returncode != 0 and not findings:
            error = (completed.stderr or "Directory scan failed.").strip()

        return {
            "tool": "dirsearch",
            "exit_code": 0 if findings or completed.returncode == 0 else -1,
            "error": error,
            "findings": findings,
            "duration_sec": round(time.time() - started, 2),
            "command": " ".join(command),
            "raw_output": ((completed.stdout or "") + (completed.stderr or ""))[:6000],
        }
    except FileNotFoundError:
        return {
            "tool": "dirsearch",
            "exit_code": -1,
            "error": f"ffuf executable not found: {ffuf_path}",
            "findings": [],
            "duration_sec": round(time.time() - started, 2),
            "command": " ".join(command),
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "dirsearch",
            "exit_code": -1,
            "error": f"Directory scan timed out after {timeout}s",
            "findings": [],
            "duration_sec": round(time.time() - started, 2),
            "command": " ".join(command),
        }
    except Exception as exc:
        return {
            "tool": "dirsearch",
            "exit_code": -1,
            "error": str(exc),
            "findings": [],
            "duration_sec": round(time.time() - started, 2),
            "command": " ".join(command),
        }
    finally:
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except OSError:
                pass
