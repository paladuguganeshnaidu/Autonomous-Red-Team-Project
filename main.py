"""Main autonomous recon loop using planner, executor, analyzer, and shared memory."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
import sys
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

from agent.analyzer import analyze_result
from agent.executor import execute_action
from agent.planner import decide_next_action
from core.config import AppConfig
from core.logger import build_logger
from core.state_manager import StateManager
from reporting.report_generator import generate_report


ProgressCallback = Callable[[str, str, Dict[str, Any]], None]


def _action_signature(action: Dict[str, Any]) -> str:
    """Build stable action signature for duplicate prevention memory."""
    action_name = str(action.get("action", "")).strip().lower()
    target = _normalize_signature_target(str(action.get("target", "")).strip())
    return f"{action_name}::{target}"

def _normalize_signature_target(target: str) -> str:
    """Normalize action signature target to host-centric value for stability."""
    clean = str(target or "").strip().lower()
    if not clean:
        return ""

    if clean.startswith("http://") or clean.startswith("https://") or "://" in clean:
        parsed = urlparse(clean)
        return (parsed.hostname or clean).strip().lower()

    return clean.split("/")[0].strip().lower()


def _emit_agent_update(
    message: str,
    logger: Any,
    memory: Any,
    callback: Optional[ProgressCallback] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Emit one conversational agent update across CLI, memory, and web callbacks."""
    payload = metadata or {}
    print(f"[Agent] {message}")
    logger.info("[CHAT_AGENT] %s", message)
    memory.add_message("agent", message, metadata=payload)
    if callback:
        callback("agent", message, payload)


def _resolve_command(action: Dict[str, Any], result: Dict[str, Any]) -> str:
    """Resolve the executed command string for reporting and chat narration."""
    data = result.get("data", {}) if isinstance(result.get("data"), dict) else {}
    return str(data.get("command") or action.get("command") or action.get("action", "")).strip()


def _summarize_result(result: Dict[str, Any]) -> str:
    """Build a compact operator-friendly summary for one action result."""
    status = str(result.get("status", "failed")).strip().lower()
    data = result.get("data", {}) if isinstance(result.get("data"), dict) else {}

    if status != "success":
        return str(result.get("error") or "The step did not complete successfully.").strip()

    if "subdomains" in data:
        return f"Discovered {len(data.get('subdomains', []))} subdomains."

    if "ports" in data:
        return f"Observed {len(data.get('ports', []))} open ports/services."

    if "responses" in data:
        live = [
            response
            for response in data.get("responses", [])
            if int(response.get("status_code", 0) or 0) > 0
        ]
        techs = []
        for response in live:
            for tech in response.get("tech", []):
                clean = str(tech).strip()
                if clean and clean not in techs:
                    techs.append(clean)
        summary = f"Confirmed {len(live)} live web endpoints."
        if techs:
            summary += f" Technology signals: {', '.join(techs[:5])}."
        return summary

    findings = data.get("findings", [])
    if isinstance(findings, list):
        return f"Found {len(findings)} interesting content discovery results."

    if data.get("findings"):
        snippet = str(data.get("findings", "")).strip().replace("\r", " ").replace("\n", " ")
        return snippet[:180]

    if data.get("message"):
        return str(data.get("message", "")).strip()

    return "Step completed successfully."


def _result_excerpt(result: Dict[str, Any], limit: int = 800) -> str:
    """Extract a bounded raw output snippet for memory and chat history."""
    data = result.get("data", {}) if isinstance(result.get("data"), dict) else {}

    if data.get("raw_output"):
        text = str(data.get("raw_output", ""))
    elif isinstance(data.get("findings"), str):
        text = str(data.get("findings", ""))
    elif result.get("error"):
        text = str(result.get("error", ""))
    else:
        text = str(data)

    compact = re.sub(r"\s+", " ", text).strip()
    return compact[:limit]


def _build_report_path(target: str) -> Path:
    """Return a stable report path for the current target."""
    slug = re.sub(r"[^a-zA-Z0-9.-]+", "_", str(target or "scan").strip()).strip("._")
    slug = slug or "scan"
    return Path("reports") / f"{slug}_final_report.txt"


def run_autonomous_scan(
    state: Dict[str, Any],
    config: AppConfig,
    logger: Any,
    memory: Any,
    state_manager: StateManager,
    progress_callback: Optional[ProgressCallback] = None,
):
    """Run the autonomous recon agent loop, updating memory."""
    iteration = 0
    max_loops = int(getattr(config, "max_iterations", 10))
    target = str(state.get("target", "unknown")).strip() or "unknown"

    _emit_agent_update(
        f"Starting reconnaissance on {target}. I will share each command I run and send the final report here.",
        logger,
        memory,
        callback=progress_callback,
        metadata={"type": "scan_status", "status": "started", "target": target},
    )
    
    while True:
        if iteration >= max_loops:
            logger.info("[INFO] Max iterations reached (%s).", max_loops)
            msg = f"Scan paused after {max_loops} iterations."
            _emit_agent_update(
                msg,
                logger,
                memory,
                callback=progress_callback,
                metadata={"type": "scan_status", "status": "paused", "target": target},
            )
            break

        action = decide_next_action(state, config, memory.get_summary(), memory.get_recent(5))
        logger.info("[DECISION] %s", action)

        if str(action.get("action", "")).strip().lower() == "stop":
            msg = f"Scan complete. {action.get('reason', '')}"
            _emit_agent_update(
                msg,
                logger,
                memory,
                callback=progress_callback,
                metadata={"type": "scan_status", "status": "stopped", "target": target},
            )
            state.setdefault("history", []).append(
                {
                    "type": "loop-stop",
                    "reason": action.get("reason", "Planner requested stop."),
                    "score": float(action.get("score", 1.0) or 1.0),
                }
            )
            state_manager.persist(state)
            break

        signature = _action_signature(action)
        if signature not in state.get("actions_taken", []):
            state.setdefault("actions_taken", []).append(signature)

        cmd = action.get("command", "")
        action_name = str(action.get("action", "")).strip().lower()
        friendly_action = action_name.replace("_", " ") or "scan step"
        step_msg = f"Step {iteration + 1}: running {friendly_action} with `{cmd}`."
        _emit_agent_update(
            step_msg,
            logger,
            memory,
            callback=progress_callback,
            metadata={
                "type": "scan_step",
                "status": "running",
                "step": iteration + 1,
                "command": cmd,
                "action": action_name,
                "target": str(action.get("target", target)).strip(),
            },
        )
        logger.info("[EXECUTING] %s", cmd)
        result = execute_action(action, config)
        logger.info("[RESULT] %s", result)
        command_used = _resolve_command(action, result)
        result_summary = _summarize_result(result)

        memory.add_message(
            "tool",
            f"Command: {command_used}\nSummary: {result_summary}\nOutput: {_result_excerpt(result)}",
            metadata={
                "type": "tool_output",
                "tool": action.get("action"),
                "target": action.get("target"),
                "command": command_used,
                "status": result.get("status"),
                "summary": result_summary,
            },
        )

        _emit_agent_update(
            f"Step {iteration + 1} finished. {result_summary}",
            logger,
            memory,
            callback=progress_callback,
            metadata={
                "type": "scan_step",
                "status": str(result.get("status", "unknown")).strip().lower(),
                "step": iteration + 1,
                "command": command_used,
                "action": action_name,
                "summary": result_summary,
            },
        )

        state = analyze_result(result, state, config)
        no_new_data = _latest_no_new_data(state)

        state.setdefault("action_history", []).append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": str(action.get("action", "")).strip().lower(),
                "target": str(action.get("target", "")).strip(),
                "score": float(action.get("score", 0.0) or 0.0),
                "reason": str(action.get("reason", "")).strip(),
                "command": command_used,
                "status": str(result.get("status", "failed")).strip().lower(),
                "summary": result_summary,
                "duration_sec": float(
                    (result.get("data", {}) if isinstance(result.get("data"), dict) else {}).get("duration_sec", 0.0)
                    or 0.0
                ),
                "no_new_data": no_new_data,
            }
        )

        state_manager.persist(state)
        iteration += 1

        max_no_data_loops = int(getattr(config, "max_no_data_loops", 3))
        if _no_new_data_streak(state, max_no_data_loops) >= max_no_data_loops:
            logger.info("[INFO] Stopping after %s consecutive loops with no new data.", max_no_data_loops)
            msg = "Stopping scan due to no new data found in recent steps."
            _emit_agent_update(
                msg,
                logger,
                memory,
                callback=progress_callback,
                metadata={"type": "scan_status", "status": "stopped", "target": target},
            )
            break

        if _has_high_confidence_vulnerability(state, float(getattr(config, "llm_min_confidence_stop", 0.85))):
            logger.info("[INFO] High-confidence vulnerability detected. Stopping autonomous loop.")
            msg = "High-confidence vulnerability found. Stopping scan early."
            _emit_agent_update(
                msg,
                logger,
                memory,
                callback=progress_callback,
                metadata={"type": "scan_status", "status": "stopped", "target": target},
            )
            break

    state_manager.persist(state)
    logger.info("[INFO] Autonomous scan complete. Generating final report.")
    final_report = generate_report(state)
    
    report_path = _build_report_path(target)
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(final_report, encoding="utf-8")
    Path("reports/final_report.txt").write_text(final_report, encoding="utf-8")

    state["latest_report_path"] = str(report_path)
    state_manager.persist(state)

    msg = f"Final Report generated and saved to {report_path}."
    _emit_agent_update(
        msg,
        logger,
        memory,
        callback=progress_callback,
        metadata={
            "type": "scan_status",
            "status": "report_ready",
            "target": target,
            "report_path": str(report_path),
        },
    )
    _emit_agent_update(
        final_report,
        logger,
        memory,
        callback=progress_callback,
        metadata={"type": "final_report", "target": target, "report_path": str(report_path)},
    )



def run() -> int:
    """Run the interactive Chat CLI."""
    from core.memory import ConversationMemory
    from core.memory_llm import summarize_memory
    from agent.interpreter import classify_intent
    from agent.qa_handler import answer_follow_up
    import json

    config = AppConfig.from_env()
    logger = build_logger(log_file=config.log_file)
    state_manager = StateManager(config.session_file)

    memory = ConversationMemory()
    print("=============================================")
    print("  Deep Recon Cognitive Agent - Chat CLI")
    print("=============================================")
    print(f"Loaded session: {memory.session_id}")
    print("Type /help for meta-commands or just talk naturally.")

    try:
        with open(config.session_file, "r") as f:
            state = json.load(f)
    except Exception:
        state = state_manager.initialize(target="", reset=True)

    while True:
        try:
            user_input = input("\n> ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                break

            if user_input.startswith("/"):
                cmd = user_input.split()[0].lower()
                if cmd == "/load":
                    name = user_input[len("/load"):].strip()
                    if memory.load_session(name):
                        print(f"[System] Loaded session '{name}'")
                    else:
                        print(f"[System] Could not load '{name}'")
                elif cmd == "/save":
                    name = user_input[len("/save"):].strip()
                    if name:
                        memory.save_session(name)
                        print(f"[System] Session saved as '{name}'")
                    else:
                        print("[System] Please provide a session name.")
                elif cmd == "/list":
                    sessions = memory.list_sessions()
                    print("[System] Available sessions:", ", ".join(sessions) if sessions else "None")
                elif cmd == "/clear":
                    memory.clear()
                    print("[System] Memory cleared.")
                elif cmd == "/help":
                    print("[System] Commands: /load <name>, /save <name>, /list, /clear, exit")
                else:
                    print(f"[System] Unknown command: {cmd}")
                continue

            memory.add_message("user", user_input)

            # Interpreter
            intent_res = classify_intent(user_input, memory.get_summary(), memory.get_recent(5), config)
            intent = intent_res.get("intent")
            target = intent_res.get("extracted_target")

            if intent == "new_scan":
                if target:
                    state["target"] = target
                print(f"[Agent] Starting scan on {state.get('target', 'unknown')}...")
                run_autonomous_scan(state, config, logger, memory, state_manager)
                
                # Ask follow up prompt
                msg = "Scan process ended. What would you like to know?"
                print(f"[Agent] {msg}")
                memory.add_message("agent", msg)

            elif intent == "follow_up":
                response = answer_follow_up(user_input, memory, config)
                print(f"\n[Agent] {response}")
                memory.add_message("agent", response)

            elif intent == "meta":
                print("[Agent] I think that's a system command. Use /load, /save, /list, or /clear.")
                memory.add_message("agent", "I instructed the user to use / commands.")

            else:
                response = answer_follow_up(user_input, memory, config)
                print(f"\n[Agent] {response}")
                memory.add_message("agent", response)

            memory.compress_if_needed(lambda txt: summarize_memory(txt, config), threshold=20, keep=10)

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"[ERROR] CLI loop: {e}")
            print(f"\n[Error] {e}")

    memory._auto_save()
    print("\nSession saved. Exiting.")
    return 0


def _latest_no_new_data(state: Dict[str, Any]) -> bool:
    """Return no-new-data flag from the latest analyzer history event."""
    history = state.get("history", [])
    if not isinstance(history, list) or not history:
        return False

    latest = history[-1]
    if not isinstance(latest, dict):
        return False

    return bool(latest.get("no_new_data", False))


def _no_new_data_streak(state: Dict[str, Any], max_loops: int) -> int:
    """Count consecutive no-new-data outcomes in action feedback history."""
    if max_loops <= 0:
        return 0

    streak = 0
    action_history = state.get("action_history", [])
    if not isinstance(action_history, list):
        return 0

    for item in reversed(action_history[-max_loops:]):
        if not isinstance(item, dict):
            break
        if bool(item.get("no_new_data", False)):
            streak += 1
            continue
        break

    return streak


def _has_high_confidence_vulnerability(state: Dict[str, Any], threshold: float) -> bool:
    """Return True when vulnerability confidence exceeds configured stop threshold."""
    vulnerabilities = state.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return False

    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        try:
            confidence = float(vulnerability.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        if confidence >= threshold:
            return True

    return False


if __name__ == "__main__":
    raise SystemExit(run())
