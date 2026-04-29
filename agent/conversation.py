"""Conversation manager for a copilot-style security assistant."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agent.analyzer import analyze_result
from agent.executor import execute_intent
from agent.intent_parser import build_intent_summary, parse_intent
from agent.qa_handler import answer_follow_up
from core.memory import ConversationMemory
from core.state_manager import StateManager
from reporting.analyser import analyse_tool_output
from reporting.report_generator import generate_report


CONFIRM_YES = {"y", "yes", "yeah", "confirm", "continue", "proceed", "ok"}
CONFIRM_NO = {"n", "no", "cancel", "stop", "abort"}


@dataclass
class ConversationResponse:
    """Conversation response payload."""

    messages: List[str]
    executed: bool = False
    requires_confirmation: bool = False
    final_report: str = ""


class ConversationManager:
    """Coordinates intent parsing, confirmation, tool execution, and reporting."""

    def __init__(
        self,
        *,
        config: Any,
        logger: Any,
        memory: ConversationMemory,
        state_manager: StateManager,
        initial_state: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.config = config
        self.logger = logger
        self.memory = memory
        self.state_manager = state_manager
        self.state = initial_state or state_manager.load()
        self.pending_intent: Optional[Dict[str, Any]] = None

    def handle_message(self, message: str) -> ConversationResponse:
        """Handle one operator message and return agent responses."""
        clean_message = str(message or "").strip()
        self.memory.add_message("user", clean_message)
        self.logger.info("[CHAT_USER] %s", clean_message)

        if not clean_message:
            return self._respond("Please enter a scan request or a follow-up question.")

        if self.pending_intent:
            lowered = clean_message.lower()
            if lowered in CONFIRM_YES:
                intent = self.pending_intent
                self.pending_intent = None
                return self._execute_intent(intent)
            if lowered in CONFIRM_NO:
                summary = build_intent_summary(self.pending_intent)
                self.pending_intent = None
                return self._respond(f"Cancelled. I did not run the pending action: {summary}")
            return self._respond("I’m waiting for confirmation on the pending action. Reply with `y` or `n`.")

        intent = parse_intent(clean_message, self.config, self.memory.get_recent(8))
        if intent.get("clarification_needed"):
            questions = intent.get("followup_questions", []) or ["I need a bit more detail before I run anything."]
            return self._respond("\n".join(questions))

        if intent.get("primary_tool"):
            summary = build_intent_summary(intent)
            if intent.get("requires_confirmation", False):
                self.pending_intent = intent
                return self._respond(f"{summary} Continue? [Y/n]", requires_confirmation=True)
            return self._execute_intent(intent)

        return self._respond(answer_follow_up(clean_message, self.memory, self.config))

    def _execute_intent(self, intent: Dict[str, Any]) -> ConversationResponse:
        """Execute a confirmed intent and turn results into operator-friendly output."""
        tool_name = str(intent.get("primary_tool", "")).lower()
        target = str(intent.get("target", "")).strip()
        self.state["target"] = target
        self.state_manager.persist(self.state)

        intro = f"Scanning {target} with {tool_name}... this may take a few minutes."
        self._record_agent_message(intro)

        tool_result = execute_intent(intent, self.config)
        if tool_result.error and tool_result.exit_code != 0:
            return self._respond(
                f"Sorry, something went wrong: the {tool_name} scan failed because {tool_result.error}. "
                "Would you like to try a lighter scan or confirm the target first?"
            )

        action_result = self._tool_result_to_action_result(tool_name, target, tool_result)
        self.state = analyze_result(action_result, self.state, self.config)
        self.state.setdefault("action_history", []).append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action_result["action"],
                "target": target,
                "command": tool_result.command,
                "status": action_result["status"],
                "summary": self._tool_summary(tool_result),
                "duration_sec": tool_result.duration_sec,
            }
        )
        self.state_manager.persist(self.state)

        analysis = analyse_tool_output(tool_name, target, tool_result.raw_output or str(tool_result.data), self.config)
        final_report = generate_report(self.state)
        self.memory.add_message(
            "tool",
            f"Command: {tool_result.command}\nOutput: {tool_result.raw_output[:6000]}",
            metadata={
                "type": "tool_output",
                "tool": tool_name,
                "target": target,
                "command": tool_result.command,
                "status": action_result["status"],
                "summary": analysis.get("summary") or self._tool_summary(tool_result),
            },
        )
        self.memory.add_message(
            "agent",
            final_report,
            metadata={"type": "final_report", "target": target},
        )

        lines = [
            f"Scan finished. Command used: `{tool_result.command}`",
            analysis.get("summary") or self._tool_summary(tool_result),
        ]

        findings = analysis.get("findings", [])
        if findings:
            lines.append("Findings:")
            lines.extend(f"- {item}" for item in findings[:5])

        risks = analysis.get("risks", [])
        if risks:
            lines.append("Risks:")
            lines.extend(f"- {item}" for item in risks[:5])

        next_steps = analysis.get("next_steps", [])
        if next_steps:
            lines.append("Next steps:")
            lines.extend(f"- {item}" for item in next_steps[:5])

        lines.append("Final report:")
        lines.append(final_report)

        joined = "\n".join(lines)
        return self._respond(joined, executed=True, final_report=final_report)

    def _tool_result_to_action_result(self, tool_name: str, target: str, tool_result: Any) -> Dict[str, Any]:
        action_map = {
            "nmap": "run_nmap",
            "subfinder": "run_subfinder",
            "httpx": "run_httpx",
            "ffuf": "run_dirsearch",
            "dirsearch": "run_dirsearch",
            "shell": "run_command",
        }
        action_name = action_map.get(tool_name, f"run_{tool_name}")
        data = dict(tool_result.data)
        data.setdefault("command", tool_result.command)
        data.setdefault("raw_output", tool_result.raw_output)
        data.setdefault("duration_sec", tool_result.duration_sec)
        data.setdefault("exit_code", tool_result.exit_code)
        return {
            "status": "success" if tool_result.exit_code == 0 or self._has_signal(tool_result.data) else "failed",
            "action": action_name,
            "target": target,
            "data": data,
            "error": tool_result.error or None,
            "attempts": 1,
        }

    def _tool_summary(self, tool_result: Any) -> str:
        data = tool_result.data if isinstance(tool_result.data, dict) else {}
        if data.get("ports"):
            ports = [str(item.get("port", "")) for item in data.get("ports", []) if isinstance(item, dict)]
            return f"Found {len(ports)} open ports: {', '.join(ports[:10])}."
        if data.get("subdomains"):
            return f"Discovered {len(data.get('subdomains', []))} subdomains."
        if data.get("responses"):
            live = [item for item in data.get("responses", []) if int(item.get("status_code", 0) or 0) > 0]
            return f"Confirmed {len(live)} live HTTP endpoints."
        if data.get("findings"):
            findings = data.get("findings", [])
            if isinstance(findings, list):
                return f"Collected {len(findings)} interesting content discovery results."
            return str(findings)[:200]
        if tool_result.error:
            return tool_result.error
        return "The tool completed successfully."

    def _has_signal(self, data: Dict[str, Any]) -> bool:
        return bool(
            data.get("ports")
            or data.get("subdomains")
            or data.get("responses")
            or data.get("findings")
        )

    def _respond(
        self,
        message: str,
        *,
        executed: bool = False,
        requires_confirmation: bool = False,
        final_report: str = "",
    ) -> ConversationResponse:
        self._record_agent_message(message)
        return ConversationResponse(
            messages=[message],
            executed=executed,
            requires_confirmation=requires_confirmation,
            final_report=final_report,
        )

    def _record_agent_message(self, message: str) -> None:
        self.logger.info("[CHAT_AGENT] %s", message)
        self.memory.add_message("agent", message)
