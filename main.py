import sys

from agent.analyzer import Analyzer
from agent.executor import Executor
from agent.planner import Planner
from core.config import AppConfig
from core.logger import build_logger
from core.state_manager import StateManager


def _resolve_target(argv):
    if len(argv) > 1:
        return argv[1].strip()
    return input("Enter target URL/domain/IP: ").strip()


def run():
    target = _resolve_target(sys.argv)
    if not target:
        print("Target is required.")
        return 1

    app_config = AppConfig.from_env()
    logger = build_logger(log_file=app_config.log_file)
    state_manager = StateManager(app_config.session_file)

    planner = Planner(config=app_config, logger=logger)
    executor = Executor(config=app_config, logger=logger)
    analyzer = Analyzer()

    state_manager.set_target(target, reset_run=True)
    logger.info("[INFO] Run started for target=%s", target)

    for iteration in range(1, app_config.max_iterations + 1):
        state_manager.start_iteration(iteration)
        decision = planner.plan_iteration(state_manager.state)
        state_manager.record_decision(iteration, decision)

        logger.info(
            "[DECISION] iteration=%s role=%s stop=%s reason=%s",
            iteration,
            decision.get("agent_role", "recon_agent"),
            decision.get("stop", False),
            decision.get("reason", ""),
        )

        if decision.get("stop", False):
            state_manager.mark_stop(decision.get("reason", "Planner requested stop."))
            break

        actions = decision.get("actions", [])
        if not actions:
            state_manager.mark_stop("No actions returned by planner.")
            break

        results = executor.run_actions(actions)
        analysis = analyzer.analyze(results, state_manager.state)
        state_manager.record_iteration(iteration, decision, results, analysis)

        logger.info(
            "[RESULT] iteration=%s risk=%s risk_score=%.2f confidence=%.2f findings=%s vulnerabilities=%s",
            iteration,
            analysis.get("risk_level", "unknown"),
            float(analysis.get("risk_score", 0.0)),
            float(analysis.get("confidence_score", 0.0)),
            len(analysis.get("findings", [])),
            len(analysis.get("vulnerabilities", [])),
        )

        if analysis.get("stop_recommended"):
            state_manager.mark_stop(analysis.get("stop_reason", "Analyzer requested stop."))
            logger.warning("[DECISION] stopping early: %s", state_manager.state.get("stop_reason", ""))
            break

    summary = analyzer.build_final_summary(state_manager.state)
    state_manager.finish(summary)

    logger.info("[INFO] Run completed. Session persisted at %s", app_config.session_file)
    print("\nFinal Summary")
    print(f"Target: {summary.get('target', '')}")
    print(f"Run ID: {summary.get('run_id', '')}")
    print(f"Total Iterations: {summary.get('total_iterations', 0)}")
    print(f"Total Findings: {summary.get('total_findings', 0)}")
    print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    print(f"Overall Risk: {summary.get('overall_risk', 'low')}")
    print(f"Risk Score: {summary.get('risk_score', 0.0)}")
    print(f"Confidence Score: {summary.get('confidence_score', 0.0)}")
    if summary.get("stop_reason"):
        print(f"Stop Reason: {summary.get('stop_reason')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(run())