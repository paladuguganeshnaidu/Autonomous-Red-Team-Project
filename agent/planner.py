import json
import re
from urllib.parse import urlparse

import requests


class Planner:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def plan_iteration(self, state):
        if self.config.stop_on_vuln and state.get("vulnerabilities"):
            return {
                "agent_role": "analysis_agent",
                "reason": "Vulnerability already detected and stop_on_vuln is enabled.",
                "stop": True,
                "actions": [],
            }

        if self.config.use_llm_planner:
            llm_plan = self._plan_with_llm(state)
            if llm_plan:
                return llm_plan

        return self._plan_rule_based(state)

    def _plan_rule_based(self, state):
        target = (state.get("target") or "").strip()
        host = self._extract_host(target)
        base_url = self._to_base_url(target, host)

        tool_history = self._tool_history_counts(state)
        known_subdomains = state.get("subdomains", [])
        known_ports = [str(p) for p in state.get("ports", [])]
        web_open = any(port in {"80", "443", "8080", "8443", "8000"} for port in known_ports)

        if self._looks_like_domain(host) and not known_subdomains and tool_history.get("subdomain", 0) == 0:
            return {
                "agent_role": "recon_agent",
                "reason": "No subdomains in memory; run subfinder first.",
                "stop": False,
                "actions": [
                    {
                        "tool": "subdomain",
                        "description": "Enumerate subdomains before deeper scans.",
                        "params": {"domain": host},
                    }
                ],
            }

        if not known_ports and tool_history.get("nmap", 0) == 0:
            return {
                "agent_role": "recon_agent",
                "reason": "Ports are not scanned yet.",
                "stop": False,
                "actions": [
                    {
                        "tool": "nmap",
                        "description": "Run service and port discovery.",
                        "params": {"target": host or target},
                    }
                ],
            }

        if web_open and tool_history.get("http_probe", 0) == 0:
            return {
                "agent_role": "recon_agent",
                "reason": "Web service found; probe with httpx + header checks.",
                "stop": False,
                "actions": [
                    {
                        "tool": "http_probe",
                        "description": "Probe HTTP hosts and security headers.",
                        "params": {"urls": self._candidate_urls(base_url, known_subdomains)},
                    }
                ],
            }

        if web_open and tool_history.get("whatweb", 0) == 0:
            return {
                "agent_role": "analysis_agent",
                "reason": "Technology stack has not been fingerprinted yet.",
                "stop": False,
                "actions": [
                    {
                        "tool": "whatweb",
                        "description": "Detect framework and technology fingerprints.",
                        "params": {"urls": self._candidate_urls(base_url, known_subdomains)[:3]},
                    }
                ],
            }

        if web_open and tool_history.get("ffuf", 0) == 0:
            return {
                "agent_role": "exploit_agent",
                "reason": "Run bounded directory brute force after recon and fingerprinting.",
                "stop": False,
                "actions": [
                    {
                        "tool": "ffuf",
                        "description": "Safe path discovery on primary web endpoint.",
                        "params": {"base_url": base_url},
                    }
                ],
            }

        if tool_history.get("http_probe", 0) == 0:
            return {
                "agent_role": "recon_agent",
                "reason": "Nmap did not confirm web ports; probe baseline HTTP endpoint directly.",
                "stop": False,
                "actions": [
                    {
                        "tool": "http_probe",
                        "description": "Baseline HTTP probe even when port evidence is incomplete.",
                        "params": {"urls": [base_url]},
                    }
                ],
            }

        if state.get("vulnerabilities") and self.config.stop_on_vuln:
            return {
                "agent_role": "analysis_agent",
                "reason": "Vulnerability detected; log and stop.",
                "stop": True,
                "actions": [],
            }

        return {
            "agent_role": "recon_agent",
            "reason": "No new high-value actions available.",
            "stop": True,
            "actions": [],
        }

    def _plan_with_llm(self, state):
        prompt = self._build_llm_prompt(state)

        try:
            response = requests.post(
                self.config.ollama_url,
                json={
                    "model": self.config.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=self.config.llm_timeout,
            )
            response.raise_for_status()

            text = response.json().get("response", "")
            payload = self._extract_json(text)
            if not isinstance(payload, dict):
                return None

            tool = str(payload.get("tool", "")).strip().lower()
            if tool in {"", "stop"}:
                return {
                    "agent_role": payload.get("agent_role", "analysis_agent"),
                    "reason": str(payload.get("reason", "LLM requested stop.")).strip(),
                    "stop": True,
                    "actions": [],
                }

            params = payload.get("params", {})
            if not isinstance(params, dict):
                params = {}

            return {
                "agent_role": payload.get("agent_role", "recon_agent"),
                "reason": str(payload.get("reason", "LLM selected next action.")).strip(),
                "stop": False,
                "actions": [
                    {
                        "tool": tool,
                        "description": "LLM-directed action.",
                        "params": params,
                    }
                ],
            }
        except Exception as exc:
            self.logger.warning("LLM planner failed, falling back to rule-based plan: %s", exc)
            return None

    @staticmethod
    def _extract_json(text):
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{[\s\S]*\}", text)
            if not match:
                return None
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                return None

    def _build_llm_prompt(self, state):
        return (
            "You are planning authorized recon only. Return JSON only with keys: "
            "tool, params, reason, agent_role. "
            "Allowed tool values: subdomain, nmap, http_probe, ffuf, whatweb, stop.\n"
            f"Current state: {json.dumps(state, default=str)[:5000]}"
        )

    @staticmethod
    def _tool_history_counts(state):
        counts = {}
        for item in state.get("iterations", []):
            for result in item.get("results", []):
                tool = str(result.get("tool", "")).strip().lower()
                if not tool:
                    continue
                counts[tool] = counts.get(tool, 0) + 1
        return counts

    def _candidate_urls(self, base_url, subdomains):
        urls = [base_url]
        for subdomain in subdomains[:5]:
            urls.append(f"https://{subdomain}")
        return self._dedupe(urls)

    @staticmethod
    def _extract_host(target):
        if not target:
            return ""
        value = target.strip()
        if "://" in value:
            parsed = urlparse(value)
            return parsed.hostname or ""
        return value.split("/")[0]

    @staticmethod
    def _to_base_url(target, host):
        value = (target or "").strip()
        if value.startswith("http://") or value.startswith("https://"):
            return value.rstrip("/")
        if host:
            return f"https://{host}"
        return value

    @staticmethod
    def _looks_like_domain(host):
        return bool(host and "." in host and not host.replace(".", "").isdigit())

    @staticmethod
    def _dedupe(items):
        unique = []
        for item in items:
            if item and item not in unique:
                unique.append(item)
        return unique
