"""Generate actionable human-readable pentest reports from autonomous scan state."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlparse


def generate_report(state: dict) -> str:
    """Build a practical, human-readable security report from scan state."""
    normalized = _normalize_state(state)
    vulnerabilities = _normalize_vulnerabilities(
        normalized.get("vulnerabilities", []),
        normalized.get("target", ""),
    )
    weaknesses = _derive_weaknesses(normalized, vulnerabilities)
    next_steps = _recommended_next_steps(normalized, vulnerabilities)

    lines: List[str] = []
    lines.append("==============================")
    lines.append("AUTONOMOUS RED TEAM REPORT")
    lines.append("==========================")
    lines.append("")
    lines.append(f"Target: {normalized.get('target', '')}")
    lines.append("")
    lines.append("--- Recon Summary ---")
    lines.append(f"Subdomains: {len(normalized.get('subdomains', []))}")
    lines.append(f"Open Ports: {len(normalized.get('ports', []))}")
    lines.append(f"Services: {len(normalized.get('services', []))}")
    lines.append(f"Endpoints: {len(normalized.get('endpoints', []))}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("--- Vulnerabilities Found ---")
    lines.append("")

    if vulnerabilities:
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda item: (_severity_rank(item.get("severity", "low")), -float(item.get("confidence", 0.0))),
        )

        for vulnerability in sorted_vulns:
            severity = str(vulnerability.get("severity", "low")).upper()
            title = str(vulnerability.get("title", "Unlabeled vulnerability")).strip()
            target = str(vulnerability.get("target", normalized.get("target", ""))).strip()
            evidence = str(vulnerability.get("evidence", "No direct evidence captured.")).strip()

            lines.append(f"[{severity}] {title}")
            lines.append("")
            lines.append(f"Target: {target}")
            lines.append(f"Evidence: {evidence}")
            lines.append(f"Why It Matters: {_why_it_matters(vulnerability)}")
            lines.append(
                "How to Exploit (high-level, safe explanation): "
                f"{_safe_exploit_path(vulnerability)}"
            )
            lines.append(f"Fix / Mitigation: {_fix_guidance(vulnerability)}")
            lines.append("")
    else:
        lines.append("No confirmed vulnerabilities were detected in this run.")
        lines.append("Automated output still shows weaknesses requiring manual validation.")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("--- Security Weaknesses (Even if not confirmed vuln) ---")
    lines.append("")

    if weaknesses:
        for weakness in weaknesses:
            lines.append(f"* {weakness}")
    else:
        lines.append("* No explicit weaknesses were derived; increase scan depth and manual verification.")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("--- Recommended Next Steps ---")
    lines.append("")

    for step in next_steps:
        lines.append(f"* {step}")

    return "\n".join(lines).rstrip() + "\n"


def _normalize_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize shared state values into predictable list-friendly structures."""
    target = str(state.get("target", "")).strip() or "unknown-target"

    return {
        "target": target,
        "subdomains": _dedupe_strings(state.get("subdomains", [])),
        "ports": _dedupe_strings(state.get("ports", [])),
        "services": state.get("services", []) if isinstance(state.get("services", []), list) else [],
        "endpoints": _dedupe_strings(state.get("endpoints", [])),
        "technologies": _dedupe_strings(state.get("technologies", [])),
        "vulnerabilities": state.get("vulnerabilities", []) if isinstance(state.get("vulnerabilities", []), list) else [],
    }


def _normalize_vulnerabilities(values: Iterable[Any], default_target: str) -> List[Dict[str, Any]]:
    """Normalize vulnerability entries to a stable structure for reporting."""
    normalized: List[Dict[str, Any]] = []
    seen = set()

    for item in values or []:
        if not isinstance(item, dict):
            continue

        title = str(item.get("title") or item.get("name") or "Unlabeled vulnerability").strip()
        severity = str(item.get("severity", "medium")).strip().lower() or "medium"
        target = str(item.get("target") or item.get("asset") or default_target).strip() or default_target
        evidence = str(item.get("evidence", "No direct evidence captured.")).strip()

        try:
            confidence = float(item.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0

        confidence = max(0.0, min(1.0, confidence))

        payload = {
            "title": title,
            "severity": severity,
            "target": target,
            "evidence": evidence,
            "confidence": confidence,
            "recommendation": str(item.get("recommendation") or item.get("fix") or "").strip(),
            "reasoning": str(item.get("reasoning", "")).strip(),
            "raw": item,
        }

        key = (payload["title"], payload["target"], payload["evidence"])
        if key in seen:
            continue
        seen.add(key)

        normalized.append(payload)

    return normalized


def _derive_weaknesses(state: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> List[str]:
    """Build practical weakness statements from recon + vulnerability evidence."""
    weaknesses: List[str] = []

    ports = set(state.get("ports", []))
    endpoints = state.get("endpoints", [])

    if _has_missing_header_signal(vulnerabilities):
        weaknesses.append(
            "Missing headers: Security header gaps detected (CSP/HSTS/X-Frame-Options). "
            "This is a security misconfiguration that can allow clickjacking, content injection, "
            "or weaker transport posture. Enforce headers at reverse proxy and application layers."
        )
    else:
        weaknesses.append(
            "Missing headers: Not explicitly confirmed in persisted state. Validate all in-scope endpoints "
            "for CSP, HSTS, and X-Frame-Options and standardize headers globally."
        )

    if ports:
        sorted_ports = sorted(ports, key=lambda item: _port_sort_key(item))
        sample = ", ".join(sorted_ports[:10])
        weaknesses.append(
            f"Open ports: {sample}. Internet-exposed services increase attack surface; "
            "limit exposure with network ACLs and bind non-public services to private interfaces."
        )
    else:
        weaknesses.append(
            "Open ports: No open ports were persisted in this run, but this can be a false negative if "
            "scans timed out or tooling was unavailable."
        )

    if "3306" in ports:
        weaknesses.append(
            "Port 3306 exposure risk: Database service appears externally reachable. "
            "Restrict MySQL/MariaDB access to trusted application hosts, enforce strong credentials, "
            "and require encrypted DB transport."
        )

    if "3389" in ports:
        weaknesses.append(
            "Port 3389 exposure risk: RDP brute-force and credential-stuffing risk if internet-exposed. "
            "Require VPN/MFA gateway, apply account lockout, and enforce source-IP allow-listing."
        )

    admin_endpoints = _admin_endpoints(endpoints)
    if admin_endpoints:
        sample = ", ".join(admin_endpoints[:5])
        weaknesses.append(
            f"Exposed admin panels: {sample}. Protect admin routes with MFA, strict authorization checks, "
            "and network-level access restrictions."
        )
    else:
        weaknesses.append(
            "Exposed admin panels: No explicit /admin route observed in current endpoint list. "
            "Manually test alternate paths such as /manage, /dashboard, and framework-specific admin URLs."
        )

    return _dedupe_strings(weaknesses)


def _recommended_next_steps(state: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> List[str]:
    """Generate prioritized and practical follow-up actions."""
    steps: List[str] = []

    high_risk = [v for v in vulnerabilities if _severity_rank(v.get("severity", "low")) <= _severity_rank("high")]

    if high_risk:
        top_titles = ", ".join(v.get("title", "finding") for v in high_risk[:3])
        steps.append(
            f"Priority action: Triage and remediate high-risk findings first ({top_titles}) with ownership, deadlines, and retest criteria."
        )
    else:
        steps.append(
            "Priority action: No high-confidence vulnerabilities confirmed; schedule manual validation before declaring target low risk."
        )

    steps.append(
        "Manual testing: Use Burp Suite Repeater/Intruder to validate authentication, authorization, and input-handling issues on discovered endpoints."
    )

    steps.append(
        "Tooling next: Run focused Nmap NSE scripts for exposed services and run Nuclei with vetted templates against discovered web endpoints."
    )

    if _admin_endpoints(state.get("endpoints", [])):
        steps.append(
            "Access-control priority: Test admin endpoints with anonymous, low-privilege, and admin sessions to confirm isolation and privilege boundaries."
        )

    if "3306" in set(state.get("ports", [])):
        steps.append(
            "Network hardening: Immediately restrict 3306 at perimeter firewall and verify DB is not internet-routable."
        )

    if "3389" in set(state.get("ports", [])):
        steps.append(
            "Identity hardening: Enforce MFA and lockout policy on RDP access points and move RDP behind VPN/jump-host controls."
        )

    steps.append(
        "Validation cycle: Re-run this autonomous scan after fixes and compare deltas in vulnerabilities, weak endpoints, and exposed services."
    )

    return _dedupe_strings(steps)


def _why_it_matters(vulnerability: Dict[str, Any]) -> str:
    """Return concise impact explanation for a vulnerability."""
    blob = _vuln_blob(vulnerability)
    severity = str(vulnerability.get("severity", "medium")).lower()

    if "header" in blob or "csp" in blob or "hsts" in blob:
        return (
            "Missing defensive headers weaken browser-side protections, increasing risk of clickjacking, "
            "content injection, and transport security downgrade scenarios."
        )

    if "admin" in blob:
        return (
            "Administrative surface exposure can lead to privilege escalation, unauthorized configuration changes, "
            "or sensitive data access if access controls are weak."
        )

    if ".git" in blob or ".env" in blob or "backup" in blob or "config" in blob:
        return (
            "Sensitive file exposure can disclose credentials, internal architecture, and secrets that accelerate follow-on compromise."
        )

    if "sql" in blob or "sqli" in blob or "injection" in blob:
        return "Injection flaws can allow unauthorized data access or backend manipulation with significant business impact."

    if "auth" in blob or "idor" in blob or "access" in blob:
        return "Access-control weaknesses can permit unauthorized actions or data exposure across users or tenants."

    if severity in {"critical", "high"}:
        return "High-severity findings can be chained into material compromise if not remediated quickly."

    return "This finding indicates a security control gap that could become exploitable when combined with other weaknesses."


def _safe_exploit_path(vulnerability: Dict[str, Any]) -> str:
    """Return high-level and safe exploitation validation guidance."""
    blob = _vuln_blob(vulnerability)

    if "header" in blob or "csp" in blob or "hsts" in blob:
        return (
            "Verify missing headers across sensitive routes with a proxy/browser developer tools, then demonstrate impact "
            "using non-destructive clickjacking and policy-bypass checks in an authorized test window."
        )

    if "admin" in blob:
        return (
            "Attempt access to admin routes with different privilege levels and confirm whether unauthorized users can view "
            "or invoke administrative functions."
        )

    if ".git" in blob or ".env" in blob or "backup" in blob or "config" in blob:
        return (
            "Request the exposed path as an unauthenticated user, confirm sensitive content exposure, and scope impact without "
            "modifying server-side data."
        )

    if "sql" in blob or "sqli" in blob or "injection" in blob:
        return (
            "Use controlled payload families to test query behavior changes and confirm exploitability with read-only validation paths."
        )

    return (
        "Reproduce the finding with deterministic requests, validate impact under least-privilege and privileged contexts, "
        "and capture minimal evidence needed for remediation."
    )


def _fix_guidance(vulnerability: Dict[str, Any]) -> str:
    """Return practical mitigation guidance for a vulnerability."""
    recommendation = str(vulnerability.get("recommendation", "")).strip()
    if recommendation:
        return recommendation

    blob = _vuln_blob(vulnerability)

    if "header" in blob or "csp" in blob or "hsts" in blob:
        return (
            "Set CSP, HSTS, and X-Frame-Options at edge and app tiers, then validate headers are present on all dynamic and static responses."
        )

    if "admin" in blob:
        return (
            "Require MFA for admin users, enforce role-based authorization server-side, and restrict admin routes to trusted networks."
        )

    if ".git" in blob or ".env" in blob or "backup" in blob or "config" in blob:
        return (
            "Remove sensitive artifacts from web root, block direct access at web server level, rotate exposed credentials, "
            "and add CI checks to prevent recurrence."
        )

    if "sql" in blob or "sqli" in blob or "injection" in blob:
        return "Use parameterized queries, strict input validation, and least-privilege DB accounts for affected components."

    return "Apply least-privilege, harden exposed services/endpoints, and retest after remediation with the same evidence path."


def _vuln_blob(vulnerability: Dict[str, Any]) -> str:
    """Flatten relevant vulnerability text to a searchable lowercased blob."""
    pieces = [
        vulnerability.get("title", ""),
        vulnerability.get("evidence", ""),
        vulnerability.get("reasoning", ""),
        vulnerability.get("recommendation", ""),
    ]
    return " ".join(str(piece) for piece in pieces).lower()


def _has_missing_header_signal(vulnerabilities: List[Dict[str, Any]]) -> bool:
    """Check if vulnerability evidence indicates missing security headers."""
    for item in vulnerabilities:
        blob = _vuln_blob(item)
        if "missing header" in blob or "x-frame-options" in blob or "strict-transport-security" in blob or "content-security-policy" in blob:
            return True
    return False


def _admin_endpoints(endpoints: Iterable[str]) -> List[str]:
    """Return endpoints that look like admin surfaces."""
    matched: List[str] = []

    for endpoint in endpoints or []:
        text = str(endpoint).strip()
        if not text:
            continue

        path = text.lower()
        if "://" in text:
            parsed = urlparse(text)
            path = str(parsed.path or "").lower()

        if "/admin" in path or path.rstrip("/") == "admin":
            if text not in matched:
                matched.append(text)

    return matched


def _dedupe_strings(values: Iterable[Any]) -> List[str]:
    """Deduplicate string values while preserving insertion order."""
    unique: List[str] = []
    for value in values or []:
        clean = str(value).strip()
        if clean and clean not in unique:
            unique.append(clean)
    return unique


def _severity_rank(severity: Any) -> int:
    """Return sort rank for severity labels."""
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }
    return order.get(str(severity).strip().lower(), 5)


def _port_sort_key(value: str) -> Tuple[int, str]:
    """Sort ports numerically when possible, otherwise lexicographically."""
    text = str(value).strip()
    if text.isdigit():
        return (0, f"{int(text):06d}")
    return (1, text)
