import re


def _format_services(scan_state):
    services = scan_state.get("services", {}) or {}
    parts = []
    for port in scan_state.get("open_ports", [])[:20]:
        service = services.get(port, "unknown")
        parts.append(f"{port}/{service}")
    return parts


def _extract_nmap_versions(command_results):
    versions = []
    pattern = re.compile(r"(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)(?:\s+(.*))?")

    for item in command_results or []:
        if item.get("tool") != "nmap":
            continue
        text = item.get("analysis_input") or item.get("output") or ""
        for match in pattern.finditer(text):
            port = match.group(1)
            service = match.group(3)
            version_text = (match.group(4) or "").strip()
            summary = f"{port}/{service} {version_text}".strip()
            if summary not in versions:
                versions.append(summary)
    return versions[:20]


def build_retrieval_query(scan_state, stage, plan=None, analysis=None, command_results=None):
    target = scan_state.get("target", "")
    network_target = scan_state.get("network_target", "")
    urls = scan_state.get("urls", [])[:8]
    findings = scan_state.get("findings", [])[-12:]
    risks = scan_state.get("risk_signals", [])[-12:]
    services = _format_services(scan_state)
    nmap_versions = _extract_nmap_versions(command_results)

    parts = [
        f"stage: {stage}",
        f"target: {target}",
        f"network_target: {network_target}",
    ]

    if services:
        parts.append(f"services: {services}")
    if nmap_versions:
        parts.append(f"service_versions: {nmap_versions}")
    if urls:
        parts.append(f"web_endpoints: {urls}")
    if findings:
        parts.append(f"recent_findings: {findings}")
    if risks:
        parts.append(f"recent_risk_signals: {risks}")

    if plan:
        parts.append(f"iteration_goal: {plan.get('iteration_goal', '')}")
        parts.append(f"planner_reasoning: {plan.get('reasoning', '')}")

    if analysis:
        parts.append(f"analysis_summary: {analysis.get('summary', '')}")
        vuln_titles = []
        for vuln in analysis.get("vulnerability_candidates", [])[:10]:
            if not isinstance(vuln, dict):
                continue
            title = str(vuln.get("title", "")).strip()
            severity = str(vuln.get("severity", "info")).strip().lower()
            asset = str(vuln.get("asset", "")).strip()
            if title:
                vuln_titles.append(f"[{severity}] {title} @ {asset}")
        if vuln_titles:
            parts.append(f"vulnerability_candidates: {vuln_titles}")

    command_tools = [item.get("tool") for item in (command_results or []) if item.get("tool")]
    if command_tools:
        parts.append(f"tools_executed: {command_tools}")

    joined = "\n".join([item for item in parts if str(item).strip()])
    return joined.strip()
