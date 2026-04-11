# main.py
import os
import re
import sys
import time
from urllib.parse import urlparse

import config
from decision_engine import DecisionEngine
from executor import Executor
from memory import Memory
from recon import ReconAgent
from reporter import Reporter
from trace_logger import TraceLogger


def _append_unique(items, value):
    if value and value not in items:
        items.append(value)


def _target_host_values(scan_state):
    values = set()

    for raw in [scan_state.get("target", ""), scan_state.get("network_target", "")]:
        raw = str(raw).strip().lower()
        if not raw:
            continue
        values.add(raw)
        parsed = urlparse(raw)
        if parsed.hostname:
            values.add(parsed.hostname.lower().strip())

    for host in scan_state.get("additional_hosts", []):
        values.add(str(host).strip().lower())

    for url in scan_state.get("urls", []):
        parsed = urlparse(str(url).strip())
        if parsed.hostname:
            values.add(parsed.hostname.lower().strip())

    return {item for item in values if item}


def _is_host_in_scope(host, scan_state):
    if not host:
        return False

    host_value = str(host).strip().lower()
    for candidate in _target_host_values(scan_state):
        if host_value == candidate or host_value.endswith(f".{candidate}"):
            return True
    return False


def _seed_urls_from_target(target, network_target):
    target_value = str(target or "").strip()
    urls = []

    if target_value.startswith("http://") or target_value.startswith("https://"):
        urls.append(target_value.rstrip("/"))
    else:
        urls.append(f"http://{network_target}")
        urls.append(f"https://{network_target}")

    deduped = []
    for item in urls:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _extract_urls_from_output(text, scan_state):
    if not text:
        return []

    urls = re.findall(r"https?://[^\s'\"<>]+", text)
    filtered = []
    for url in urls:
        parsed = urlparse(url)
        if _is_host_in_scope(parsed.hostname or "", scan_state):
            _append_unique(filtered, url.rstrip("/"))
    return filtered


def _extract_ffuf_findings(output):
    findings = []
    for line in (output or "").splitlines():
        clean = line.strip()
        if not clean:
            continue
        if any(code in clean for code in [" 200 ", " 204 ", " 301 ", " 302 ", " 307 ", " 401 ", " 403 "]):
            findings.append(clean[:220])
    return findings[:60]


def _extract_subfinder_hosts(output, scan_state):
    hosts = []
    for line in (output or "").splitlines():
        candidate = line.strip().lower()
        if candidate and " " not in candidate and "." in candidate and _is_host_in_scope(candidate, scan_state):
            _append_unique(hosts, candidate)
    return hosts


def _extract_nmap_ports(output):
    ports = {}
    for match in re.finditer(r"(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)", output or ""):
        ports[match.group(1)] = match.group(3)
    return ports


def _add_web_url_for_port(scan_state, port):
    host = scan_state.get("network_target") or scan_state.get("target")
    if not host:
        return

    if port == "80":
        _append_unique(scan_state["urls"], f"http://{host}")
    elif port == "443":
        _append_unique(scan_state["urls"], f"https://{host}")
    elif port in {"8080", "8000", "8888", "5357", "5000", "3000"}:
        _append_unique(scan_state["urls"], f"http://{host}:{port}")
    elif port == "8443":
        _append_unique(scan_state["urls"], f"https://{host}:{port}")


def _merge_vulnerability_candidates(scan_state, candidates):
    existing = scan_state.get("vulnerability_candidates", [])
    seen = {
        (item.get("title", ""), item.get("asset", ""), item.get("evidence", "")[:120])
        for item in existing
        if isinstance(item, dict)
    }

    for item in candidates:
        if not isinstance(item, dict):
            continue
        key = (item.get("title", ""), item.get("asset", ""), item.get("evidence", "")[:120])
        if key in seen:
            continue
        seen.add(key)
        existing.append(item)

    scan_state["vulnerability_candidates"] = existing


def _update_scan_state(scan_state, plan, command_results, analysis):
    for finding in analysis.get("key_findings", []):
        _append_unique(scan_state["findings"], finding)

    for risk in analysis.get("risk_signals", []):
        _append_unique(scan_state["risk_signals"], risk)

    for target in analysis.get("new_targets", []):
        text = str(target).strip()
        if not text:
            continue
        if text.startswith("http://") or text.startswith("https://"):
            parsed = urlparse(text)
            if _is_host_in_scope(parsed.hostname or "", scan_state):
                _append_unique(scan_state["urls"], text.rstrip("/"))
        elif _is_host_in_scope(text, scan_state):
            _append_unique(scan_state["additional_hosts"], text)

    _merge_vulnerability_candidates(scan_state, analysis.get("vulnerability_candidates", []))

    for result in command_results:
        tool = result.get("tool", "")
        output = result.get("analysis_input") or result.get("output", "")

        if tool == "nmap":
            ports = _extract_nmap_ports(output)
            for port, service in ports.items():
                _append_unique(scan_state["open_ports"], port)
                scan_state["services"][port] = service
                _add_web_url_for_port(scan_state, port)

        if tool == "subfinder":
            for host in _extract_subfinder_hosts(output, scan_state):
                _append_unique(scan_state["additional_hosts"], host)

        if tool == "ffuf":
            for item in _extract_ffuf_findings(output):
                _append_unique(scan_state["findings"], f"ffuf hit: {item}")

        for url in _extract_urls_from_output(output, scan_state):
            _append_unique(scan_state["urls"], url)

    next_focus = analysis.get("next_focus", "").strip()
    if next_focus:
        _append_unique(scan_state["focus_queue"], next_focus)

    if not scan_state.get("preferred_web_url") and scan_state["urls"]:
        scan_state["preferred_web_url"] = scan_state["urls"][0]


def main():
    if len(sys.argv) < 2:
        target = input("Enter target URL/domain/IP: ").strip()
    else:
        target = sys.argv[1].strip()

    os.makedirs("output", exist_ok=True)

    recon = ReconAgent(target)
    memory = Memory()
    run_id = memory.start_run(target)
    trace_logger = TraceLogger(
        target=target,
        run_id=run_id,
        output_dir=config.TRACE_OUTPUT_DIR,
        enabled=config.TRACE_JSON_ENABLED,
        environment={
            "ollama_url": config.OLLAMA_URL,
            "model": config.OLLAMA_MODEL,
            "require_llm": config.REQUIRE_LLM,
            "allow_llm_fallback": config.ALLOW_LLM_FALLBACK,
            "ollama_timeout": config.OLLAMA_TIMEOUT,
            "max_iterations": config.MAX_ITERATIONS,
            "tool_timeout": config.TOOL_TIMEOUT,
        },
    )
    ai = DecisionEngine(trace_logger=trace_logger)
    executor = Executor(timeout=config.TOOL_TIMEOUT, trace_logger=trace_logger)
    trace_logger.log_event("run_started", target=target, network_target=recon.network_target)

    llm_ready, llm_message = ai.health_check()
    trace_logger.log_event(
        "llm_health_status",
        ready=llm_ready,
        message=llm_message,
        fallback_allowed=config.ALLOW_LLM_FALLBACK,
    )
    if not llm_ready and config.REQUIRE_LLM and not config.ALLOW_LLM_FALLBACK:
        print("\n[ERROR] LLM is required but not ready.")
        print(f"Reason: {llm_message}")
        print("Fix: ensure Ollama is running and pull the configured model, then rerun.")
        print(f"Configured model: {config.OLLAMA_MODEL}")
        final_summary = {
            "executive_summary": "Run aborted because LLM was unavailable.",
            "high_value_findings": [f"LLM readiness check failed: {llm_message}"],
            "risk_signals": ["AI-driven scanning was not possible in this run."],
            "overall_risk": "unknown",
            "confidence": "low",
            "vulnerabilities": [],
            "recommended_next_steps": [
                "Start Ollama service.",
                f"Pull model: ollama pull {config.OLLAMA_MODEL}",
                "Re-run the scan after model is available.",
            ],
        }
        memory.complete_run(run_id, final_summary)
        trace_logger.complete(final_summary)
        memory.close()
        return
    if not llm_ready and config.ALLOW_LLM_FALLBACK:
        print("\n[WARN] LLM health check failed.")
        print(f"Reason: {llm_message}")
        print("Continuing with fallback command planning and heuristic analysis.")

    seeded_urls = _seed_urls_from_target(target, recon.network_target)

    scan_state = {
        "target": target,
        "network_target": recon.network_target,
        "open_ports": [],
        "services": {},
        "urls": seeded_urls,
        "preferred_web_url": seeded_urls[0] if seeded_urls else "",
        "additional_hosts": [],
        "risk_signals": [],
        "focus_queue": [],
        "findings": [
            f"Initial target: {target}",
            f"Seeded URLs: {', '.join(seeded_urls) if seeded_urls else 'none'}",
        ],
        "vulnerability_candidates": [],
    }

    print(f"\n{'=' * 72}")
    print(f"AUTONOMOUS AI RECON - Target: {target}")
    print(f"{'=' * 72}")
    print("Flow: AI plans powerful command batch -> commands execute -> AI analyzes all outputs")
    print(f"Fixed iterations: {config.MAX_ITERATIONS}\n")

    iteration_records = []

    for iteration in range(1, config.MAX_ITERATIONS + 1):
        print(f"{'-' * 56}")
        print(f"ITERATION {iteration}/{config.MAX_ITERATIONS}")
        print(f"{'-' * 56}")

        history = memory.get_history(run_id, limit=config.HISTORY_LIMIT)
        usage_summary = memory.get_tool_usage_summary(run_id)

        plan = ai.plan_iteration_commands(
            scan_state=scan_state,
            history=history,
            usage_summary=usage_summary,
            iteration=iteration,
            max_iterations=config.MAX_ITERATIONS,
        )

        commands = plan.get("commands", [])
        print(f"Goal: {plan.get('iteration_goal', '')}")
        print(f"Reasoning: {plan.get('reasoning', '')}")
        print(f"Planned commands: {len(commands)}")
        if plan.get("used_fallback"):
            print("[INFO] Using fallback command plan for this iteration.")

        if not commands:
            print("[ERROR] Planner produced no runnable commands.")
            trace_logger.log_event(
                "iteration_skipped",
                iteration=iteration,
                reason=plan.get("llm_error", "Planner produced no runnable commands."),
                used_fallback=plan.get("used_fallback", False),
            )
            if config.REQUIRE_LLM and not config.ALLOW_LLM_FALLBACK:
                print("Stopping because REQUIRE_LLM is enabled.")
                break
            print("Continuing with next iteration in fallback-compatible mode.")
            continue

        command_results = []
        for index, spec in enumerate(commands, start=1):
            tool = spec.get("tool", "unknown")
            command = spec.get("command", "")
            llm_command = spec.get("llm_command_raw", command)
            objective = spec.get("objective", "")
            timeout_sec = spec.get("timeout_sec", config.TOOL_TIMEOUT)

            print(f"\n[COMMAND {index}/{len(commands)}] {tool.upper()} - {objective}")
            result = executor.run(
                command,
                tool,
                timeout=timeout_sec,
                iteration=iteration,
                command_index=index,
                objective=objective,
                llm_command=llm_command,
            )
            command_results.append(result)

        analysis = ai.analyze_iteration(scan_state, plan, command_results, iteration)

        print("\n[ITERATION ANALYSIS]")
        print(analysis.get("summary", "No summary produced."))
        print(f"Findings: {len(analysis.get('key_findings', []))}")
        print(f"Risk signals: {len(analysis.get('risk_signals', []))}")
        print(f"Vulnerability candidates: {len(analysis.get('vulnerability_candidates', []))}")
        print(f"Confidence: {analysis.get('confidence', 'medium')}")
        if analysis.get("next_focus"):
            print(f"Next focus: {analysis.get('next_focus')}")

        _update_scan_state(scan_state, plan, command_results, analysis)
        trace_logger.log_event(
            "iteration_summary",
            iteration=iteration,
            plan_summary={
                "iteration_goal": plan.get("iteration_goal", ""),
                "reasoning": plan.get("reasoning", ""),
                "used_fallback": plan.get("used_fallback", False),
                "llm_error": plan.get("llm_error", ""),
            },
            analysis_summary=analysis,
            scan_state_snapshot=scan_state if config.TRACE_CAPTURE_SCAN_STATE else {},
        )

        for item in command_results:
            decision = {
                "tool": item.get("tool", "unknown"),
                "objective": item.get("objective", ""),
                "reasoning": plan.get("reasoning", ""),
                "command": item.get("command", ""),
            }
            memory.store_iteration(run_id, iteration, decision, item, analysis)

        memory.store_state_snapshot(run_id, iteration, scan_state)

        iteration_records.append(
            {
                "iteration": iteration,
                "iteration_goal": plan.get("iteration_goal", ""),
                "planner_reasoning": plan.get("reasoning", ""),
                "commands": command_results,
                "analysis_summary": analysis.get("summary", ""),
                "key_findings": analysis.get("key_findings", []),
                "new_targets": analysis.get("new_targets", []),
                "risk_signals": analysis.get("risk_signals", []),
                "vulnerability_candidates": analysis.get("vulnerability_candidates", []),
                "next_focus": analysis.get("next_focus", ""),
                "confidence": analysis.get("confidence", "medium"),
            }
        )

        if iteration < config.MAX_ITERATIONS:
            time.sleep(config.DELAY_BETWEEN_ACTIONS)

    print("\n[FINAL] Building complete vulnerability-focused summary...")
    final_assessment = ai.build_final_assessment(target, scan_state, iteration_records)
    memory.complete_run(run_id, final_assessment)
    trace_logger.complete(final_assessment)

    reporter = Reporter(
        target=target,
        memory=memory,
        run_id=run_id,
        scan_state=scan_state,
        final_assessment=final_assessment,
        iteration_records=iteration_records,
    )
    markdown_path = reporter.generate_markdown()
    vulns_txt_path = reporter.generate_vulnerability_text()

    print(f"Report saved to: {markdown_path}")
    print(f"Vulnerability file saved to: {vulns_txt_path}")
    print("\n" + "=" * 72)
    print("RUN SUMMARY")
    print("=" * 72)
    print(f"Run id: {run_id}")
    print(f"Iterations executed: {config.MAX_ITERATIONS}")
    tools_used = sorted({entry.get("tool") for entry in executor.log if entry.get("tool")})
    print(f"Tools used: {', '.join(tools_used) if tools_used else 'none'}")
    print(f"Total vulnerability candidates: {len(final_assessment.get('vulnerabilities', []))}")
    print("Database: redteam.db")
    print(f"Markdown report: {markdown_path}")
    print(f"Vulnerabilities text: {vulns_txt_path}")
    if trace_logger.path:
        print(f"Trace JSON: {trace_logger.path}")

    memory.close()


if __name__ == "__main__":
    main()
