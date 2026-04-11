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
