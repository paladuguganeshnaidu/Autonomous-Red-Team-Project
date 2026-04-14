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


def _resolve_target(argv: list[str]) -> str:
    """Resolve target from CLI args or interactive input."""
    if len(argv) > 1:
        return argv[1].strip()
    return input("Enter target URL/domain/IP: ").strip()


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


def run() -> int:
    """Run the autonomous recon agent loop until stop conditions are met."""
    target = _resolve_target(sys.argv)
    if not target:
        print("Target is required.")
        return 1

    config = AppConfig.from_env()
    logger = build_logger(log_file=config.log_file)
    state_manager = StateManager(config.session_file)

    state = state_manager.initialize(target=target, reset=True)
    logger.info("[INFO] Starting scan for target=%s", target)

    iteration = 0

    while True:
        if iteration >= int(config.max_iterations):
            logger.info("[INFO] Max iterations reached (%s).", config.max_iterations)
            break

        action = decide_next_action(state)
        logger.info("[DECISION] %s", action)

        if str(action.get("action", "")).strip().lower() == "stop":
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

        result = execute_action(action, config)
        logger.info("[RESULT] %s", result)

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

        logger.info(
            "[STATE] subdomains=%s ports=%s services=%s technologies=%s endpoints=%s vulnerabilities=%s",
            len(state.get("subdomains", [])),
            len(state.get("ports", [])),
            len(state.get("services", [])),
            len(state.get("technologies", [])),
            len(state.get("endpoints", [])),
            len(state.get("vulnerabilities", [])),
        )

        state_manager.persist(state)
        iteration += 1

        max_no_data_loops = int(getattr(config, "max_no_data_loops", 3))
        if _no_new_data_streak(state, max_no_data_loops) >= max_no_data_loops:
            logger.info("[INFO] Stopping after %s consecutive loops with no new data.", max_no_data_loops)
            break

        if _has_high_confidence_vulnerability(state, float(getattr(config, "llm_min_confidence_stop", 0.85))):
            logger.info("[INFO] High-confidence vulnerability detected. Stopping autonomous loop.")
            break

    state_manager.persist(state)

    report = generate_report(state)
    print(report)

    report_path = Path("reports") / "final_report.txt"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    logger.info("[INFO] Final report saved to %s", report_path)

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
