"""Main autonomous recon loop using planner, executor, analyzer, and shared memory."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any, Dict
from urllib.parse import urlparse

from agent.analyzer import analyze_result
from agent.executor import execute_action
from agent.planner import decide_next_action
from core.config import AppConfig
from core.logger import build_logger
from core.state_manager import StateManager
from reporting.report_generator import generate_report
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

def run_autonomous_scan(state: Dict[str, Any], config: AppConfig, logger: Any, memory: Any, state_manager: StateManager):
    """Run the autonomous recon agent loop, updating memory."""
    iteration = 0
    max_loops = int(getattr(config, "max_iterations", 10))
    
    while True:
        if iteration >= max_loops:
            logger.info("[INFO] Max iterations reached (%s).", max_loops)
            msg = f"Scan paused after {max_loops} iterations."
            print(f"[Agent] {msg}")
            memory.add_message("agent", msg)
            break

        action = decide_next_action(state, config, memory.get_summary(), memory.get_recent(5))
        logger.info("[DECISION] %s", action)

        if str(action.get("action", "")).strip().lower() == "stop":
            msg = f"Scan complete. {action.get('reason', '')}"
            print(f"[Agent] {msg}")
            memory.add_message("agent", msg)
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
        print(f"[Agent] Running: {cmd}")
        result = execute_action(action, config)
        logger.info("[RESULT] %s", result)

        memory.add_message("tool", f"Command: {cmd}\nOutput: {result.get('output', '')}", metadata={
            "type": "tool_output",
            "tool": action.get("action"),
            "target": action.get("target")
        })

        state = analyze_result(result, state, config)
        no_new_data = _latest_no_new_data(state)

        state.setdefault("action_history", []).append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": str(action.get("action", "")).strip().lower(),
                "target": str(action.get("target", "")).strip(),
                "score": float(action.get("score", 0.0) or 0.0),
                "reason": str(action.get("reason", "")).strip(),
                "status": str(result.get("status", "failed")).strip().lower(),
                "no_new_data": no_new_data,
            }
        )

        state_manager.persist(state)
        iteration += 1

        max_no_data_loops = int(getattr(config, "max_no_data_loops", 3))
        if _no_new_data_streak(state, max_no_data_loops) >= max_no_data_loops:
            logger.info("[INFO] Stopping after %s consecutive loops with no new data.", max_no_data_loops)
            msg = "Stopping scan due to no new data found in recent steps."
            print(f"[Agent] {msg}")
            memory.add_message("agent", msg)
            break

        if _has_high_confidence_vulnerability(state, float(getattr(config, "llm_min_confidence_stop", 0.85))):
            logger.info("[INFO] High-confidence vulnerability detected. Stopping autonomous loop.")
            msg = "High-confidence vulnerability found. Stopping scan early."
            print(f"[Agent] {msg}")
            memory.add_message("agent", msg)
            break

    state_manager.persist(state)


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
