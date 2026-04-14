import re


def validate_result(tool, output):
    """Return a dict describing whether a tool output is useful."""
    text = output or ""
    useful = False
    signals = []

    if tool == "ffuf":
        for line in text.splitlines():
            if any(code in line for code in [" 200 ", " 204 ", " 301 ", " 302 ", " 307 ", " 401 ", " 403 "]):
                useful = True
                signals.append(line.strip()[:200])
        return {"useful": useful, "signals": signals[:10]}

    if tool == "nmap":
        matches = re.findall(r"(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)", text)
        if matches:
            useful = True
            signals = [f"{port}/{proto} {svc}" for port, proto, svc in matches[:10]]
        return {"useful": useful, "signals": signals}

    if tool == "nuclei":
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        matches = [line for line in lines if "[" in line and "]" in line]
        useful = bool(matches)
        return {"useful": useful, "signals": matches[:10]}

    if tool == "subfinder":
        lines = [line.strip().lower() for line in text.splitlines()]
        matches = [line for line in lines if " " not in line and "." in line]
        useful = bool(matches)
        return {"useful": useful, "signals": matches[:10]}

    # Passive tools or unknown: any output is considered useful.
    if text.strip():
        return {"useful": True, "signals": [text.strip()[:200]]}

    return {"useful": False, "signals": []}
