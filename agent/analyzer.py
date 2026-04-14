"""Result analyzer that merges tool outputs and enriches findings with LLM intelligence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

from core.llm import analyze_with_llm


SENSITIVE_PATH_MARKERS = (
    ".git",
    ".env",
    "admin",
    "backup",
    "config",
    "db",
)


def analyze_result(result: dict, state: dict, config: Optional[Any] = None) -> dict:
    """Analyze one execution result, update state, and optionally enrich with LLM intelligence."""
    normalized = _normalize_state(state)

    action_name = str(result.get("action", "")).strip().lower()
    status = str(result.get("status", "failed")).strip().lower()
    data = result.get("data", {}) if isinstance(result.get("data", {}), dict) else {}

    before_snapshot = _state_counts(normalized)
    before_services = len(normalized["services"])
    before_endpoints = len(normalized["endpoints"])

    if action_name == "run_subfinder" and status == "success":
        _merge_subdomains(normalized, data)

    if action_name == "run_nmap" and status == "success":
        _merge_nmap_data(normalized, data)

    if action_name == "run_httpx" and status == "success":
        _merge_httpx_data(normalized, data)

    if action_name == "run_dirsearch" and status == "success":
        _merge_dirsearch_data(normalized, data)

    normalized["subdomains"] = _dedupe_str_list(normalized["subdomains"])
    normalized["ports"] = _dedupe_str_list(normalized["ports"])
    normalized["technologies"] = _dedupe_str_list(normalized["technologies"])
    normalized["endpoints"] = _dedupe_str_list(normalized["endpoints"])
    normalized["services"] = _dedupe_dict_list(normalized["services"], ["host", "port", "service"])
    normalized["vulnerabilities"] = _dedupe_dict_list(normalized["vulnerabilities"], ["title", "asset", "evidence"])

    new_services_found = len(normalized["services"]) > before_services
    new_endpoints_found = len(normalized["endpoints"]) > before_endpoints

    if config is not None and (new_services_found or new_endpoints_found):
        llm_output = analyze_with_llm(normalized, config)
        llm_vulns = llm_output.get("vulnerabilities", []) if isinstance(llm_output, dict) else []

        if isinstance(llm_vulns, list) and llm_vulns:
            normalized["vulnerabilities"].extend(llm_vulns)
            normalized["vulnerabilities"] = _dedupe_dict_list(
                normalized["vulnerabilities"],
                ["title", "asset", "evidence"],
            )

        next_actions = llm_output.get("next_actions", []) if isinstance(llm_output, dict) else []
        if isinstance(next_actions, list) and next_actions:
            normalized["history"].append(
                {
                    "timestamp": _utc_now_iso(),
                    "type": "llm-next-actions",
                    "next_actions": [str(item).strip() for item in next_actions if str(item).strip()],
                }
            )

    after_snapshot = _state_counts(normalized)
    no_new_data = before_snapshot == after_snapshot

    normalized["history"].append(
        {
            "timestamp": _utc_now_iso(),
            "type": "action-result",
            "action": action_name,
            "status": status,
            "error": result.get("error"),
            "attempts": int(result.get("attempts", 0) or 0),
            "no_new_data": no_new_data,
            "new_services_found": new_services_found,
            "new_endpoints_found": new_endpoints_found,
            "counts": after_snapshot,
        }
    )

    if len(normalized["history"]) > 500:
        normalized["history"] = normalized["history"][-500:]

    return normalized


def _normalize_state(state: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize shared state to required schema and safe list types."""
    normalized: Dict[str, Any] = {
        "target": str(state.get("target", "")).strip(),
        "subdomains": _dedupe_str_list(state.get("subdomains", [])),
        "ports": _dedupe_str_list(state.get("ports", [])),
        "services": state.get("services", []) if isinstance(state.get("services", []), list) else [],
        "technologies": _dedupe_str_list(state.get("technologies", [])),
        "endpoints": _dedupe_str_list(state.get("endpoints", [])),
        "vulnerabilities": state.get("vulnerabilities", []) if isinstance(state.get("vulnerabilities", []), list) else [],
        "actions_taken": state.get("actions_taken", []) if isinstance(state.get("actions_taken", []), list) else [],
        "action_history": state.get("action_history", []) if isinstance(state.get("action_history", []), list) else [],
        "history": state.get("history", []) if isinstance(state.get("history", []), list) else [],
    }
    return normalized


def _merge_subdomains(state: Dict[str, Any], data: Dict[str, Any]) -> None:
    """Merge subdomain enumeration output into state."""
    for subdomain in data.get("subdomains", []):
        clean = str(subdomain).strip().lower()
        if clean:
            state["subdomains"].append(clean)


def _merge_nmap_data(state: Dict[str, Any], data: Dict[str, Any]) -> None:
    """Merge nmap ports and services into state."""
    for item in data.get("ports", []):
        if not isinstance(item, dict):
            continue

        port = str(item.get("port", "")).strip()
        service_name = str(item.get("service", "unknown")).strip().lower()
        host = str(item.get("host", state.get("target", ""))).strip().lower()

        if port:
            state["ports"].append(port)
            state["services"].append(
                {
                    "host": host,
                    "port": port,
                    "service": service_name,
                }
            )


def _merge_httpx_data(state: Dict[str, Any], data: Dict[str, Any]) -> None:
    """Merge HTTP probing output (technologies/services/endpoints) into state."""
    for response in data.get("responses", []):
        if not isinstance(response, dict):
            continue

        response_url = str(response.get("url", "")).strip()
        host = _extract_host(response_url) or str(state.get("target", "")).strip().lower()
        status_code = int(response.get("status_code", 0) or 0)

        if response_url:
            state["endpoints"].append(response_url)

        if status_code > 0:
            port = "443" if response_url.startswith("https://") else "80"
            state["ports"].append(port)
            state["services"].append(
                {
                    "host": host,
                    "port": port,
                    "service": "https" if port == "443" else "http",
                }
            )

        webserver = str(response.get("webserver", "")).strip()
        if webserver:
            state["technologies"].append(webserver)

        for tech in response.get("tech", []):
            tech_clean = str(tech).strip()
            if tech_clean:
                state["technologies"].append(tech_clean)


def _merge_dirsearch_data(state: Dict[str, Any], data: Dict[str, Any]) -> None:
    """Merge directory discovery output and generate vulnerability hints."""
    for finding in data.get("findings", []):
        if not isinstance(finding, dict):
            continue

        url = str(finding.get("url", "")).strip()
        path = str(finding.get("path", "")).strip().lower()
        status_code = int(finding.get("status", 0) or 0)

        if url:
            state["endpoints"].append(url)

        if status_code not in {200, 401, 403}:
            continue

        if any(marker in path for marker in SENSITIVE_PATH_MARKERS):
            severity = "medium"
            if ".git" in path or ".env" in path:
                severity = "high"

            state["vulnerabilities"].append(
                {
                    "title": "Sensitive path exposure candidate",
                    "severity": severity,
                    "asset": url,
                    "target": _extract_host(url) or state.get("target", ""),
                    "evidence": f"Discovered path '{path}' with status {status_code}",
                    "recommendation": "Validate exposure and restrict access to sensitive endpoints.",
                    "confidence": 0.6,
                    "source": "rule",
                }
            )


def _state_counts(state: Dict[str, Any]) -> Dict[str, int]:
    """Build compact counts used to detect whether a loop added new data."""
    return {
        "subdomains": len(state.get("subdomains", [])),
        "ports": len(state.get("ports", [])),
        "services": len(state.get("services", [])),
        "technologies": len(state.get("technologies", [])),
        "endpoints": len(state.get("endpoints", [])),
        "vulnerabilities": len(state.get("vulnerabilities", [])),
    }


def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _extract_host(url: str) -> str:
    """Extract host from URL and normalize it."""
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").strip().lower()
    except Exception:
        return ""


def _dedupe_str_list(values: Iterable[Any]) -> List[str]:
    """Return ordered, deduplicated string values."""
    unique: List[str] = []
    for value in values or []:
        clean = str(value).strip()
        if clean and clean not in unique:
            unique.append(clean)
    return unique


def _dedupe_dict_list(items: Iterable[Any], fields: List[str]) -> List[Dict[str, Any]]:
    """Return ordered unique dictionaries keyed by selected fields."""
    unique: List[Dict[str, Any]] = []
    seen = set()

    for item in items or []:
        if not isinstance(item, dict):
            continue
        key = tuple(item.get(field) for field in fields)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    return unique
