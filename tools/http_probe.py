import json
import os
import subprocess
import tempfile
import time

import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
]


def run_http_probe(urls, httpx_path="httpx", timeout=10, user_agent="AutonomousRedTeam/1.0"):
    return _run_http_probe_with_httpx(
        urls=urls,
        httpx_path=httpx_path,
        timeout=timeout,
        user_agent=user_agent,
    )


def _dedupe_urls(urls):
    if isinstance(urls, str):
        urls = [urls]

    deduped = []
    for url in urls or []:
        clean = str(url or "").strip()
        if clean and clean not in deduped:
            deduped.append(clean)
    return deduped


def _requests_header_probe(url, timeout, user_agent):
    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": user_agent},
            allow_redirects=True,
        )
        missing_headers = [h for h in SECURITY_HEADERS if h not in response.headers]
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


def _run_http_probe_with_httpx(urls, httpx_path="httpx", timeout=10, user_agent="AutonomousRedTeam/1.0"):
    deduped_urls = _dedupe_urls(urls)
    started = time.time()
    responses = []
    httpx_missing = False

    for url in deduped_urls:
        parsed_line = {}
        httpx_error = ""

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
            if output_line:
                try:
                    parsed_line = json.loads(output_line)
                except json.JSONDecodeError:
                    httpx_error = "httpx returned non-JSON output."

            if completed.returncode != 0 and not output_line:
                httpx_error = (completed.stderr or "httpx failed.").strip()
        except FileNotFoundError:
            httpx_missing = True
            httpx_error = f"httpx executable not found: {httpx_path}"
        except subprocess.TimeoutExpired:
            httpx_error = f"httpx timed out after {timeout + 5}s"
        except Exception as exc:
            httpx_error = str(exc)

        header_probe = _requests_header_probe(url, timeout, user_agent)
        combined_error = header_probe.get("error", "")
        if httpx_error:
            combined_error = httpx_error if not combined_error else f"{httpx_error} | {combined_error}"

        responses.append(
            {
                "url": parsed_line.get("url") or header_probe.get("url", url),
                "status_code": int(parsed_line.get("status_code") or header_probe.get("status_code", 0) or 0),
                "title": parsed_line.get("title", ""),
                "webserver": parsed_line.get("webserver") or header_probe.get("server", ""),
                "tech": parsed_line.get("tech", []) if isinstance(parsed_line.get("tech", []), list) else [],
                "missing_headers": header_probe.get("missing_headers", SECURITY_HEADERS[:]),
                "error": combined_error,
            }
        )

    has_success = any(not item.get("error") for item in responses)
    general_error = ""
    if not has_success:
        general_error = "All HTTP probes failed."
    elif httpx_missing:
        general_error = "httpx unavailable, used fallback HTTP checks."

    return {
        "tool": "http_probe",
        "exit_code": 0 if has_success else -1,
        "error": general_error,
        "responses": responses,
        "raw_output": "",
        "duration_sec": round(time.time() - started, 2),
    }


def run_ffuf_scan(
    base_url,
    ffuf_path="ffuf",
    wordlist="",
    match_codes="200,204,301,302,307,401,403",
    timeout=120,
    max_time=90,
    rate=25,
):
    started = time.time()
    target = str(base_url or "").strip().rstrip("/")

    if not target:
        return {
            "tool": "ffuf",
            "exit_code": -1,
            "error": "No base_url provided for ffuf.",
            "findings": [],
            "raw_output": "",
            "duration_sec": 0,
        }

    if not wordlist or not os.path.exists(wordlist):
        return {
            "tool": "ffuf",
            "exit_code": -1,
            "error": f"Wordlist not found: {wordlist}",
            "findings": [],
            "raw_output": "",
            "duration_sec": round(time.time() - started, 2),
        }

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    temp_file.close()
    output_path = temp_file.name

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
            error = (completed.stderr or "ffuf failed without JSON findings.").strip()

        return {
            "tool": "ffuf",
            "exit_code": 0 if findings or completed.returncode == 0 else -1,
            "error": error,
            "findings": findings,
            "raw_output": ((completed.stdout or "") + (completed.stderr or ""))[:8000],
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except FileNotFoundError:
        return {
            "tool": "ffuf",
            "exit_code": -1,
            "error": f"ffuf executable not found: {ffuf_path}",
            "findings": [],
            "raw_output": "",
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "ffuf",
            "exit_code": -1,
            "error": f"ffuf timed out after {timeout}s",
            "findings": [],
            "raw_output": "",
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {
            "tool": "ffuf",
            "exit_code": -1,
            "error": str(exc),
            "findings": [],
            "raw_output": "",
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    finally:
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except OSError:
                pass


def run_whatweb_detect(urls, whatweb_path="whatweb", timeout=120):
    started = time.time()
    deduped_urls = _dedupe_urls(urls)

    fingerprints = []
    errors = []

    for url in deduped_urls:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        temp_file.close()
        output_path = temp_file.name

        command = [
            whatweb_path,
            "--color=never",
            f"--log-json={output_path}",
            url,
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

            parsed_any = False
            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as handle:
                    raw = handle.read().strip()
                if raw:
                    for line in raw.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        plugins = entry.get("plugins", {}) if isinstance(entry, dict) else {}
                        tech = sorted(list(plugins.keys())) if isinstance(plugins, dict) else []
                        fingerprints.append(
                            {
                                "url": entry.get("target", url),
                                "tech": tech,
                            }
                        )
                        parsed_any = True

            if completed.returncode != 0 and not parsed_any:
                errors.append((completed.stderr or "whatweb failed.").strip())

        except FileNotFoundError:
            errors.append(f"whatweb executable not found: {whatweb_path}")
            break
        except subprocess.TimeoutExpired:
            errors.append(f"whatweb timed out after {timeout}s for {url}")
        except Exception as exc:
            errors.append(str(exc))
        finally:
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    pass

    return {
        "tool": "whatweb",
        "exit_code": 0 if fingerprints else -1,
        "error": " | ".join(errors[:3]),
        "fingerprints": fingerprints,
        "raw_output": "",
        "duration_sec": round(time.time() - started, 2),
    }
