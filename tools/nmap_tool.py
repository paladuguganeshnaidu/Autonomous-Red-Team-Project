import subprocess
import time
import re


def _parse_nmap_ports(raw_output):
    ports = []
    for match in re.finditer(r"(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)", raw_output or ""):
        ports.append(
            {
                "port": match.group(1),
                "protocol": match.group(2),
                "state": "open",
                "service": match.group(3),
            }
        )
    return ports


def run_nmap(target, nmap_path="nmap", timeout=120):
    if not target:
        return {
            "tool": "nmap",
            "exit_code": -1,
            "error": "No target provided to nmap tool.",
            "raw_output": "",
            "ports": [],
            "command": "",
            "duration_sec": 0,
        }

    command = [nmap_path, "-sV", "-Pn", target]
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
        parsed_ports = _parse_nmap_ports(raw_output)
        return {
            "tool": "nmap",
            "exit_code": completed.returncode,
            "error": "",
            "raw_output": raw_output,
            "ports": parsed_ports,
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except FileNotFoundError:
        return {
            "tool": "nmap",
            "exit_code": -1,
            "error": f"nmap executable not found: {nmap_path}",
            "raw_output": "",
            "ports": [],
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except subprocess.TimeoutExpired as exc:
        partial = (exc.stdout or "") + (exc.stderr or "")
        parsed_ports = _parse_nmap_ports(partial)
        return {
            "tool": "nmap",
            "exit_code": -1,
            "error": f"nmap timed out after {timeout}s",
            "raw_output": partial,
            "ports": parsed_ports,
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {
            "tool": "nmap",
            "exit_code": -1,
            "error": str(exc),
            "raw_output": "",
            "ports": [],
            "command": " ".join(command),
            "duration_sec": round(time.time() - started, 2),
        }
