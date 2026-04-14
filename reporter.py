from datetime import datetime
import os
import re


class Reporter:
    def __init__(self, target, memory, run_id, scan_state, final_assessment, iteration_records=None):
        self.target = target
        self.memory = memory
        self.run_id = run_id
        self.scan_state = scan_state
        self.final_assessment = final_assessment or {}
        self.iteration_records = iteration_records or []

    @staticmethod
    def _safe_filename_component(value):
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
        cleaned = cleaned.strip("._")
        return cleaned or "target"

    @staticmethod
    def _severity_rank(value):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(str(value).lower(), 5)

    def _add_exploitation_path(self, paths, seen_titles, title, priority, objective, evidence, steps):
        key = re.sub(r"\s+", " ", str(title).lower()).strip()
        if not key or key in seen_titles:
            return

        seen_titles.add(key)
        normalized_priority = str(priority).lower().strip()
        if normalized_priority not in {"high", "medium", "low"}:
            normalized_priority = "medium"

        clean_steps = [
            re.sub(r"\s+", " ", str(step)).strip()
            for step in (steps or [])
            if str(step).strip()
        ]
        if not clean_steps:
            clean_steps = ["Reproduce the finding with a deterministic request in a test window."]

        paths.append(
            {
                "title": re.sub(r"\s+", " ", str(title)).strip(),
                "priority": normalized_priority,
                "objective": re.sub(r"\s+", " ", str(objective)).strip(),
                "evidence": re.sub(r"\s+", " ", str(evidence)).strip(),
                "steps": clean_steps,
            }
        )

    def _build_exploitation_paths(self, vulnerabilities):
        paths = []
        seen_titles = set()

        for vuln in vulnerabilities[:8]:
            title = vuln.get("title", "Untitled finding")
            asset = vuln.get("asset", "") or self.target
            evidence = vuln.get("evidence", "") or vuln.get("source", "") or "No evidence provided."
            recommendation = vuln.get("recommendation", "")
            severity = vuln.get("severity", "info")
            keyword_blob = f"{title} {evidence} {recommendation}".lower()

            objective = "Validate exploitability, impact, and blast radius for this candidate."
            steps = [
                "Replay the exact request pattern tied to this evidence and confirm consistency.",
                "Test adjacent inputs and parameters to determine whether impact is isolated or systemic.",
                "Capture minimal proof of impact with redacted evidence and clear reproduction conditions.",
                "Map the affected component to business impact and required remediation priority.",
            ]

            if any(word in keyword_blob for word in ["auth", "login", "admin", "permission", "idor", "access"]):
                objective = "Assess whether authorization boundaries can be bypassed across roles or tenants."
                steps = [
                    "Build a role matrix (anonymous, user, privileged) for the affected endpoint.",
                    "Compare response behavior and data exposure between low-privilege and high-privilege sessions.",
                    "Attempt object-level access changes with controlled identifiers to detect broken access control.",
                    "Document the highest privilege gain possible and impacted data classes.",
                ]
            elif any(word in keyword_blob for word in ["xss", "cross-site"]):
                objective = "Determine whether client-side script injection is possible and session-impacting."
                steps = [
                    "Trace untrusted input from source to rendered context (HTML, attribute, script, URL).",
                    "Validate whether encoding changes across contexts and whether sanitization is bypassable.",
                    "Test impact in low-risk mode first (alert-free markers, reflected output checks).",
                    "Assess account/session impact and required browser interaction assumptions.",
                ]
            elif any(word in keyword_blob for word in ["sql", "sqli", "database"]):
                objective = "Verify whether backend query manipulation is possible through user-controlled input."
                steps = [
                    "Identify parameters reaching database-backed functionality.",
                    "Measure differential responses across controlled boundary-condition inputs.",
                    "Confirm whether validation, type checks, or parameterization prevents abuse.",
                    "Quantify potential data exposure scope if exploitation succeeds.",
                ]
            elif any(word in keyword_blob for word in ["lfi", "rfi", "traversal", "file inclusion", "path"]):
                objective = "Check for filesystem boundary breaks and unauthorized file access paths."
                steps = [
                    "Identify file/path parameters and normalize expected canonical paths.",
                    "Test traversal normalization edge cases in a controlled scope.",
                    "Verify whether application-level or server-level path constraints are enforceable.",
                    "Record accessible file classes and privilege implications.",
                ]
            elif any(word in keyword_blob for word in ["template", "ssti"]):
                objective = "Validate whether server-side template rendering can be influenced by user input."
                steps = [
                    "Map template entry points where user data is rendered server-side.",
                    "Check for expression evaluation behavior versus literal rendering.",
                    "Confirm sandbox restrictions and blocked object access boundaries.",
                    "Assess reachable impact from information disclosure to code execution risk.",
                ]

            self._add_exploitation_path(
                paths,
                seen_titles,
                title=f"{title} ({asset})",
                priority="high" if str(severity).lower() in {"critical", "high"} else "medium",
                objective=objective,
                evidence=evidence,
                steps=steps,
            )

        urls = [str(item).strip() for item in self.scan_state.get("urls", []) if str(item).strip()]
        findings = [str(item).strip() for item in self.scan_state.get("findings", []) if str(item).strip()]
        hosts = [str(item).strip() for item in self.scan_state.get("additional_hosts", []) if str(item).strip()]
        open_ports = [str(item).strip() for item in self.scan_state.get("open_ports", []) if str(item).strip()]

        risk_signals = []
        for item in self.final_assessment.get("risk_signals", []) + self.scan_state.get("risk_signals", []):
            text = str(item).strip()
            if text and text not in risk_signals:
                risk_signals.append(text)

        sensitive_findings = [
            item
            for item in findings
            if any(word in item.lower() for word in ["admin", "login", "backup", "debug", "config", "api", "graphql"])
        ]

        if urls:
            evidence = f"Discovered {len(urls)} in-scope web endpoints. Sample: {', '.join(urls[:4])}."
            if sensitive_findings:
                evidence += f" Sensitive endpoint indicators: {'; '.join(sensitive_findings[:3])}."
            self._add_exploitation_path(
                paths,
                seen_titles,
                title="Endpoint exposure and access-control drift path",
                priority="high" if sensitive_findings else "medium",
                objective="Determine whether discovered routes expose restricted data or admin behavior.",
                evidence=evidence,
                steps=[
                    "Prioritize endpoints with 200/401/403 behavior and map authentication requirements.",
                    "Compare anonymous and authenticated responses on the same route and parameters.",
                    "Check for backup/debug/config paths and verify whether access controls are enforced.",
                    "Record impact as data class exposed, privilege required, and reproducibility conditions.",
                ],
            )

        if hosts:
            self._add_exploitation_path(
                paths,
                seen_titles,
                title="Subdomain trust-boundary pivot path",
                priority="medium",
                objective="Test whether weaker sibling hosts can be used to pivot into higher-value assets.",
                evidence=f"Discovered in-scope hosts: {', '.join(hosts[:6])}.",
                steps=[
                    "Profile authentication and security header posture per host.",
                    "Compare cookie scope, CORS policy, and shared-session behavior across subdomains.",
                    "Check whether less-hardened hosts can access shared APIs or trusted backends.",
                    "Document cross-host trust assumptions that expand attack surface.",
                ],
            )

        if open_ports:
            services = self.scan_state.get("services", {})
            service_summary = ", ".join([f"{port}/{services.get(port, 'unknown')}" for port in open_ports[:8]])
            self._add_exploitation_path(
                paths,
                seen_titles,
                title="Internet-exposed service abuse path",
                priority="medium",
                objective="Validate whether exposed network services enable direct compromise or lateral movement.",
                evidence=f"Open service indicators: {service_summary}.",
                steps=[
                    "Confirm service version and configuration for each externally exposed port.",
                    "Assess authentication posture, default hardening, and known weak operations.",
                    "Test whether service exposure leaks sensitive metadata or administrative interfaces.",
                    "Map service-to-web trust links and potential pivot paths.",
                ],
            )

        has_http = any(item.lower().startswith("http://") for item in urls)
        has_https = any(item.lower().startswith("https://") for item in urls)
        if has_http and has_https:
            self._add_exploitation_path(
                paths,
                seen_titles,
                title="Protocol downgrade and session-handling path",
                priority="medium",
                objective="Assess whether mixed HTTP/HTTPS exposure weakens session security and transport integrity.",
                evidence="Both HTTP and HTTPS endpoints were observed for the target scope.",
                steps=[
                    "Check redirect consistency from HTTP to HTTPS across all sensitive routes.",
                    "Verify cookie security attributes and whether session tokens are transport-protected.",
                    "Look for inconsistent cache/security headers between protocols.",
                    "Document downgrade scenarios and required mitigations.",
                ],
            )

        if risk_signals:
            self._add_exploitation_path(
                paths,
                seen_titles,
                title="Coverage-gap and blind-spot follow-up path",
                priority="medium",
                objective="Close visibility gaps that may hide exploit paths missed during automated runs.",
                evidence=f"Observed risk signals: {'; '.join(risk_signals[:4])}.",
                steps=[
                    "Re-run failed or partial checks with corrected permissions and deterministic settings.",
                    "Use alternative tools or manual validation for coverage where commands errored or timed out.",
                    "Prioritize high-value assets first when coverage is incomplete.",
                    "Track unresolved blind spots as explicit residual risk.",
                ],
            )

        fallback_paths = [
            {
                "title": "Business-logic abuse path",
                "priority": "medium",
                "objective": "Evaluate workflow-level abuse opportunities not visible through signature scanning.",
                "evidence": "Recon established reachable application endpoints suitable for transaction-flow testing.",
                "steps": [
                    "Map core user workflows end to end and identify trust transitions.",
                    "Test sequencing, replay, and state-transition assumptions with safe, reversible actions.",
                    "Check whether server-side validation enforces expected business invariants.",
                    "Capture impact as integrity loss, unauthorized action, or financial/process abuse.",
                ],
            },
            {
                "title": "Error-handling and information-leakage path",
                "priority": "low",
                "objective": "Identify response behaviors that disclose internal details useful for follow-on attacks.",
                "evidence": "Multiple automated probes were executed across web and discovery endpoints.",
                "steps": [
                    "Trigger controlled invalid-input states and compare verbose error differences.",
                    "Check whether stack traces, framework fingerprints, or internal paths are exposed.",
                    "Validate consistency of error responses across subdomains and protocol variants.",
                    "Prioritize leaks that directly enable privilege or data-access escalation.",
                ],
            },
            {
                "title": "Authentication lifecycle abuse path",
                "priority": "medium",
                "objective": "Assess account lifecycle controls for brute-force, reset, and session-fixation weaknesses.",
                "evidence": "Attack surface includes web endpoints suitable for auth workflow testing.",
                "steps": [
                    "Inventory login, signup, reset, and MFA endpoints and their rate-limit behavior.",
                    "Verify token lifetime, one-time-use guarantees, and invalidation on credential changes.",
                    "Check whether session identifiers rotate correctly across privilege changes.",
                    "Document highest-risk abuse case with reproducible timing and prerequisites.",
                ],
            },
        ]

        for item in fallback_paths:
            if len(paths) >= 5:
                break
            self._add_exploitation_path(
                paths,
                seen_titles,
                title=item["title"],
                priority=item["priority"],
                objective=item["objective"],
                evidence=item["evidence"],
                steps=item["steps"],
            )

        return paths[:8]

    def _render_exploitation_guidance(self, vulnerabilities):
        paths = self._build_exploitation_paths(vulnerabilities)
        lines = []
        lines.append("## End-of-Report Exploitation Guidance (Authorized Testing)")
        lines.append("")
        lines.append(
            "This section analyzes the complete run evidence and proposes multiple "
            "authorized testing paths to validate real exploitability and impact."
        )
        lines.append("")

        for index, path in enumerate(paths, start=1):
            lines.append(f"### Path {index}: {path.get('title', 'Untitled path')}")
            lines.append(f"- Priority: **{path.get('priority', 'medium')}**")
            lines.append(f"- Objective: {path.get('objective', '')}")
            lines.append(f"- Evidence: {path.get('evidence', '')}")
            lines.append("Validation flow:")
            for step_index, step in enumerate(path.get("steps", []), start=1):
                lines.append(f"{step_index}. {step}")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def _rows(self):
        if self.iteration_records:
            return self.iteration_records

        # Backward compatibility path for older runs.
        legacy = []
        for item in self.memory.get_iterations(self.run_id):
            legacy.append(
                {
                    "iteration": item.get("iteration"),
                    "iteration_goal": item.get("objective", ""),
                    "planner_reasoning": item.get("reasoning", ""),
                    "analysis_summary": item.get("analysis_summary", ""),
                    "key_findings": item.get("key_findings", []),
                    "risk_signals": item.get("risk_signals", []),
                    "vulnerability_candidates": [],
                    "next_focus": item.get("next_focus", ""),
                    "confidence": item.get("confidence", "medium"),
                    "commands": [
                        {
                            "tool": item.get("tool"),
                            "command": item.get("command"),
                            "output": item.get("output_preview", ""),
                            "analysis_input": item.get("output_preview", ""),
                            "exit_code": item.get("exit_code"),
                            "timed_out": item.get("timed_out", False),
                            "duration_sec": item.get("duration_sec", 0.0),
                            "timestamp": item.get("timestamp", ""),
                            "objective": item.get("objective", ""),
                            "timeout_sec": "",
                        }
                    ],
                }
            )
        return legacy

    def generate_markdown(self):
        rows = self._rows()
        vulnerabilities = sorted(
            self.final_assessment.get("vulnerabilities", []),
            key=lambda item: (self._severity_rank(item.get("severity")), item.get("title", "")),
        )

        md = "# Autonomous Red Team Report\n\n"
        md += f"**Target:** `{self.target}`  \n"
        md += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n"
        md += f"**Run ID:** `{self.run_id}`  \n"
        md += f"**Total iterations:** {len(rows)}\n\n"

        md += "## Final Intelligence Summary\n\n"
        md += f"{self.final_assessment.get('executive_summary', 'No executive summary available.')}\n\n"
        md += f"- Overall risk: **{self.final_assessment.get('overall_risk', 'unknown')}**\n"
        md += f"- Confidence: **{self.final_assessment.get('confidence', 'unknown')}**\n\n"

        md += "### Attack Surface\n\n"
        for item in self.final_assessment.get("attack_surface", []) or ["No attack-surface elements identified."]:
            md += f"- {item}\n"

        md += "\n### High Value Findings\n\n"
        for item in self.final_assessment.get("high_value_findings", []) or ["No high-value findings were confirmed."]:
            md += f"- {item}\n"

        md += "\n### Risk Signals\n\n"
        for item in self.final_assessment.get("risk_signals", []) or ["No strong risk signals were identified."]:
            md += f"- {item}\n"

        md += "\n### Recommended Next Steps\n\n"
        for item in self.final_assessment.get("recommended_next_steps", []) or ["No recommendations provided."]:
            md += f"- {item}\n"

        md += "\n## Vulnerability Candidates\n\n"
        if vulnerabilities:
            for idx, vuln in enumerate(vulnerabilities, start=1):
                md += f"### V{idx}: {vuln.get('title', 'Untitled finding')}\n"
                md += f"- Severity: **{vuln.get('severity', 'info')}**\n"
                md += f"- Asset: {vuln.get('asset', '') or 'unknown'}\n"
                md += f"- Source: {vuln.get('source', '') or 'unknown'}\n"
                md += f"- Evidence: {vuln.get('evidence', '') or 'not provided'}\n"
                md += f"- Recommendation: {vuln.get('recommendation', '') or 'not provided'}\n\n"
        else:
            md += "No vulnerability candidates were extracted in this run.\n\n"

        md += "## Iteration Attack Chain\n\n"
        md += "| Iter | Goal | Tools | Commands | Failures |\n"
        md += "|------|------|-------|----------|----------|\n"
        for row in rows:
            commands = row.get("commands", [])
            tools = sorted({str(item.get("tool", "")) for item in commands if item.get("tool")})
            failures = sum(1 for item in commands if int(item.get("exit_code", 0) or 0) != 0)
            goal = str(row.get("iteration_goal", "")).replace("|", "\\|")[:70]
            md += (
                f"| {row.get('iteration')} | {goal} | {', '.join(tools) if tools else 'none'} "
                f"| {len(commands)} | {failures} |\n"
            )

        md += "\n## Iteration Details\n\n"
        for row in rows:
            md += f"### Iteration {row.get('iteration')}\n"
            md += f"**Goal:** {row.get('iteration_goal', '')}\n\n"
            md += f"**Planner reasoning:** {row.get('planner_reasoning', '')}\n\n"
            md += f"**Analysis summary:** {row.get('analysis_summary', '')}\n\n"
            md += f"**Confidence:** {row.get('confidence', 'medium')}\n\n"
            if row.get("next_focus"):
                md += f"**Next focus:** {row.get('next_focus')}\n\n"

            findings = row.get("key_findings", [])
            if findings:
                md += "**Key findings:**\n"
                for item in findings:
                    md += f"- {item}\n"
                md += "\n"

            risks = row.get("risk_signals", [])
            if risks:
                md += "**Risk signals:**\n"
                for item in risks:
                    md += f"- {item}\n"
                md += "\n"

            vulns = row.get("vulnerability_candidates", [])
            if vulns:
                md += "**Vulnerability candidates from this iteration:**\n"
                for item in vulns:
                    md += (
                        f"- [{item.get('severity', 'info')}] {item.get('title', 'untitled')}"
                        f" @ {item.get('asset', 'unknown')}\n"
                    )
                md += "\n"

            for command_index, cmd in enumerate(row.get("commands", []), start=1):
                md += f"#### Command {command_index}: {str(cmd.get('tool', '')).upper()}\n"
                md += f"- Objective: {cmd.get('objective', '')}\n"
                md += f"- Timeout: {cmd.get('timeout_sec', '')}\n"
                md += f"- Exit code: {cmd.get('exit_code', '')}\n"
                md += f"- Timed out: {cmd.get('timed_out', False)}\n"
                md += f"- Duration sec: {cmd.get('duration_sec', '')}\n"
                md += f"- Command: `{cmd.get('command', '')}`\n\n"
                md += f"```\n{cmd.get('output', '')}\n```\n\n"

        md += self._render_exploitation_guidance(vulnerabilities)

        os.makedirs("output", exist_ok=True)
        safe_target = self._safe_filename_component(self.target)
        filename = f"output/report_{safe_target}.md"
        with open(filename, "w", encoding="utf-8") as file_handle:
            file_handle.write(md)
        return filename

    def generate_vulnerability_text(self):
        vulnerabilities = sorted(
            self.final_assessment.get("vulnerabilities", []),
            key=lambda item: (self._severity_rank(item.get("severity")), item.get("title", "")),
        )

        lines = []
        lines.append("AUTONOMOUS RECON - VULNERABILITY SUMMARY")
        lines.append("=" * 58)
        lines.append(f"Target: {self.target}")
        lines.append(f"Run ID: {self.run_id}")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Overall Risk: {self.final_assessment.get('overall_risk', 'unknown')}")
        lines.append(f"Confidence: {self.final_assessment.get('confidence', 'unknown')}")
        lines.append("")

        if vulnerabilities:
            lines.append(f"Total Vulnerability Candidates: {len(vulnerabilities)}")
            lines.append("-")
            for index, vuln in enumerate(vulnerabilities, start=1):
                lines.append(f"{index}. {vuln.get('title', 'Untitled finding')}")
                lines.append(f"   Severity: {vuln.get('severity', 'info')}")
                lines.append(f"   Asset: {vuln.get('asset', 'unknown') or 'unknown'}")
                lines.append(f"   Source: {vuln.get('source', 'unknown') or 'unknown'}")
                lines.append(f"   Evidence: {vuln.get('evidence', 'not provided') or 'not provided'}")
                lines.append(f"   Recommendation: {vuln.get('recommendation', 'not provided') or 'not provided'}")
                lines.append("")
        else:
            lines.append("No vulnerability candidates were identified in this run.")
            lines.append("")

        lines.append("High Value Findings")
        lines.append("-")
        for item in self.final_assessment.get("high_value_findings", []) or ["No high-value findings available."]:
            lines.append(f"- {item}")

        lines.append("")
        lines.append("Risk Signals")
        lines.append("-")
        for item in self.final_assessment.get("risk_signals", []) or ["No risk signals available."]:
            lines.append(f"- {item}")

        lines.append("")
        lines.append("Recommended Next Steps")
        lines.append("-")
        for item in self.final_assessment.get("recommended_next_steps", []) or ["No recommended next steps provided."]:
            lines.append(f"- {item}")

        os.makedirs("output", exist_ok=True)
        safe_target = self._safe_filename_component(self.target)
        filename = f"output/vulns_{safe_target}.txt"
        with open(filename, "w", encoding="utf-8") as file_handle:
            file_handle.write("\n".join(lines).strip() + "\n")
        return filename
