import re


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
]


class Analyzer:
    def analyze(self, results, state):
        findings = []
        vulnerabilities = []
        ports = []
        services = []
        subdomains = []
        successful_tools = 0

        for result in results:
            tool = result.get("tool", "")
            if int(result.get("exit_code", -1)) == 0:
                successful_tools += 1

            if result.get("error"):
                findings.append(f"{tool} error: {result.get('error')}")

            if tool == "nmap":
                parsed_ports = result.get("ports", [])
                if parsed_ports:
                    for item in parsed_ports:
                        port = str(item.get("port", "")).strip()
                        service = str(item.get("service", "unknown")).strip()
                        if port:
                            ports.append(port)
                            services.append({"port": port, "service": service})
                    findings.append(f"Open ports detected: {', '.join(self._dedupe(ports))}")
                else:
                    fallback_ports = self._extract_open_ports(result.get("raw_output", ""))
                    ports.extend(fallback_ports)
                    if fallback_ports:
                        findings.append(f"Open ports detected: {', '.join(fallback_ports)}")

            if tool == "subdomain":
                discovered = result.get("subdomains", [])
                subdomains.extend(discovered)
                if discovered:
                    findings.append(f"Subdomains discovered: {', '.join(discovered[:10])}")

            if tool == "http_probe":
                for response in result.get("responses", []):
                    missing = response.get("missing_headers", [])
                    status_code = int(response.get("status_code", 0) or 0)
                    has_transport_error = bool(response.get("error"))

                    if missing and not has_transport_error and status_code > 0:
                        vulnerabilities.append(
                            {
                                "title": "Missing security headers",
                                "severity": "medium",
                                "asset": response.get("url", ""),
                                "evidence": f"Missing: {', '.join(missing)}",
                                "recommendation": "Configure CSP, HSTS, and X-Frame-Options headers.",
                            }
                        )

                    if status_code in {200, 301, 302}:
                        findings.append(f"Reachable web endpoint: {response.get('url', '')} [{status_code}]")

                    if response.get("error"):
                        findings.append(f"HTTP probe error on {response.get('url', '')}: {response.get('error')}")

            if tool == "ffuf":
                for hit in result.get("findings", []):
                    path = str(hit.get("path", "")).lower()
                    status_code = int(hit.get("status", 0) or 0)

                    if status_code in {200, 401, 403}:
                        findings.append(f"Potential sensitive path: {hit.get('url', '')} [{status_code}]")

                    if ".git/config" in path and status_code == 200:
                        vulnerabilities.append(
                            {
                                "title": "Exposed git metadata",
                                "severity": "critical",
                                "asset": hit.get("url", ""),
                                "evidence": "Accessible .git/config via HTTP.",
                                "recommendation": "Block repository internals and remove exposed .git directory from web root.",
                            }
                        )

            if tool == "whatweb":
                fingerprints = result.get("fingerprints", [])
                for fp in fingerprints:
                    tech = fp.get("tech", [])
                    if tech:
                        findings.append(f"Tech fingerprint {fp.get('url', '')}: {', '.join(tech[:6])}")

        ports = self._dedupe(ports)
        services = self._dedupe_dicts(services, ["port", "service"])
        subdomains = self._dedupe(subdomains)
        vulnerabilities = self._dedupe_dicts(vulnerabilities, ["title", "asset", "evidence"])
        findings = self._dedupe(findings)

        risk_score = self._risk_score(vulnerabilities)
        confidence_score = self._confidence_score(results, successful_tools, findings, vulnerabilities)
        risk_level = self._risk_level_from_score(risk_score)

        stop_recommended = any(v.get("severity") == "critical" for v in vulnerabilities)
        stop_reason = "Critical vulnerability identified." if stop_recommended else ""

        return {
            "summary": f"Processed {len(results)} tool results.",
            "findings": findings,
            "vulnerabilities": vulnerabilities,
            "subdomains": subdomains,
            "ports": ports,
            "services": services,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "confidence_score": confidence_score,
            "stop_recommended": stop_recommended,
            "stop_reason": stop_reason,
            "next_action_hint": "Continue iteration" if state.get("current_iteration", 0) < 4 else "Finalize report",
        }

    def build_final_summary(self, state):
        all_vulns = []
        for item in state.get("iterations", []):
            all_vulns.extend(item.get("analysis", {}).get("vulnerabilities", []))

        risk_score = self._risk_score(all_vulns)
        overall_risk = self._risk_level_from_score(risk_score)
        confidence_score = float(state.get("scores", {}).get("confidence_score", 0.0))

        return {
            "target": state.get("target", ""),
            "run_id": state.get("run_id", ""),
            "total_iterations": len(state.get("iterations", [])),
            "total_findings": sum(len(i.get("analysis", {}).get("findings", [])) for i in state.get("iterations", [])),
            "total_vulnerabilities": len(all_vulns),
            "overall_risk": overall_risk,
            "risk_score": risk_score,
            "confidence_score": confidence_score,
            "stop_reason": state.get("stop_reason", ""),
        }

    @staticmethod
    def _extract_open_ports(raw_output):
        ports = []
        for match in re.finditer(r"(\d{1,5})/(tcp|udp)\s+open", raw_output or ""):
            ports.append(match.group(1))
        return ports

    @staticmethod
    def _risk_score(vulns):
        if not vulns:
            return 0.1
        weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.3,
            "info": 0.1,
        }
        total = 0.0
        for vuln in vulns:
            severity = str(vuln.get("severity", "low")).lower()
            total += weights.get(severity, 0.3)
        score = min(1.0, total / max(1, len(vulns)))
        return round(score, 2)

    @staticmethod
    def _confidence_score(results, successful_tools, findings, vulnerabilities):
        if not results:
            return 0.0

        base = 0.35
        base += min(0.3, successful_tools * 0.1)
        base += min(0.2, len(findings) * 0.02)
        base += min(0.15, len(vulnerabilities) * 0.05)
        return round(min(0.98, base), 2)

    @staticmethod
    def _risk_level_from_score(risk_score):
        score = float(risk_score)
        if score >= 0.9:
            return "critical"
        if score >= 0.75:
            return "high"
        if score >= 0.45:
            return "medium"
        return "low"

    @staticmethod
    def _dedupe(items):
        unique = []
        for item in items:
            if item not in unique:
                unique.append(item)
        return unique

    @staticmethod
    def _dedupe_dicts(items, fields):
        unique = []
        seen = set()
        for item in items:
            key = tuple(item.get(field) for field in fields)
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique
