import subprocess
import time
from urllib.parse import urlparse


def _normalize_domain(domain):
    value = (domain or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or ""
    return value.split("/")[0]


def run_subdomain_enum(domain, subfinder_path="subfinder", timeout=120):
    domain = _normalize_domain(domain)
    if not domain:
        return {
            "tool": "subdomain",
            "exit_code": -1,
            "error": "No domain provided to subdomain tool.",
            "raw_output": "",
            "subdomains": [],
            "command": "",
            "duration_sec": 0,
        }

    command = [subfinder_path, "-d", domain, "-silent"]
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
        subdomains = []
        for line in (completed.stdout or "").splitlines():
            value = line.strip()
            if value and value not in subdomains:
                subdomains.append(value)

        return {
            "tool": "subdomain",
            "exit_code": completed.returncode,
            "error": "",
            "raw_output": raw_output,
            "subdomains": subdomains,
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except FileNotFoundError:
        return {
            "tool": "subdomain",
            "exit_code": -1,
            "error": f"subfinder executable not found: {subfinder_path}",
            "raw_output": "",
            "subdomains": [],
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or "") + (exc.stderr or "")
        return {
            "tool": "subdomain",
            "exit_code": -1,
            "error": f"subfinder timed out after {timeout}s",
            "raw_output": partial,
            "subdomains": [],
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {
            "tool": "subdomain",
            "exit_code": -1,
            "error": str(exc),
            "raw_output": "",
            "subdomains": [],
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
