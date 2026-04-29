"""Follow-up answer generation using memory and the shared LLM client."""

from __future__ import annotations

import json
import logging
from typing import Any

from core.llm import generate_text
from core.memory import ConversationMemory


logger = logging.getLogger("autonomous_recon")


def answer_follow_up(message: str, memory: ConversationMemory, config: Any) -> str:
    """Search memory for context related to the user's question and answer it."""
    direct_answer = _direct_memory_answer(message, memory)
    if direct_answer:
        return direct_answer

    recent_msgs = memory.get_recent(15)
    context_lines = []
    if memory.summary:
        context_lines.append(f"[Session Summary]\n{memory.summary}\n")

    context_lines.append("[Recent Memory]")
    for item in recent_msgs:
        meta_str = f" [Meta: {json.dumps(item.get('metadata'))}]" if item.get("metadata") else ""
        context_lines.append(f"{item['role'].upper()}{meta_str}: {item['content']}")

    prompt = f"""
You are an expert security analyst answering a follow-up question from the user.
Use ONLY the provided memory context to answer the question. Do not invent new findings.
If the answer is not in the memory, say that you don't have that information.
Explain technical findings clearly.

Context:
{chr(10).join(context_lines)}

User Question: {message}

Your Response:
"""
    try:
        return generate_text(prompt, config, options={"num_predict": 220})
    except Exception as exc:
        logger.error("[ERROR] Q&A handler failed: %s", exc)
        return f"Sorry, I encountered an error while trying to answer: {exc}"


def _direct_memory_answer(message: str, memory: ConversationMemory) -> str:
    """Answer common operator questions directly from stored memory when possible."""
    lowered = str(message or "").lower()

    if any(keyword in lowered for keyword in ("final report", "give me report", "show report", "scan report")):
        final_reports = [
            msg for msg in memory.messages
            if msg.get("role") == "agent" and msg.get("metadata", {}).get("type") == "final_report"
        ]
        if final_reports:
            return str(final_reports[-1].get("content", "")).strip()
        return "I do not have a completed final report in memory yet."

    if any(keyword in lowered for keyword in ("what did you run", "commands", "command history", "ran this command")):
        tool_messages = [
            msg for msg in memory.messages
            if msg.get("metadata", {}).get("type") == "tool_output"
        ]
        if not tool_messages:
            return "I do not have any recorded tool executions in memory yet."

        lines = ["Commands executed:"]
        for msg in tool_messages[-8:]:
            meta = msg.get("metadata", {})
            command = str(meta.get("command", "")).strip()
            summary = str(meta.get("summary", "")).strip()
            if command:
                line = f"- {command}"
                if summary:
                    line += f" -> {summary}"
                lines.append(line)
        return "\n".join(lines)

    return ""
