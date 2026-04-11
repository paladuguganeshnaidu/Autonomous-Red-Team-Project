# decision_engine.py
import ipaddress
import json
import re
import time
from urllib.parse import urlparse

import requests

import config


class DecisionEngine:
    def __init__(self, trace_logger=None):
        self.url = config.OLLAMA_URL
        self.model = config.OLLAMA_MODEL
        self.last_error = ""
        self.trace_logger = trace_logger
        self._last_llm_meta = {}
        self._llm_bypass_active = False

    def health_check(self):
        prompt = 'Return ONLY JSON: {"ready": true}'
        raw = self._call_ollama(prompt, stage="health_check")
        parsed = self._extract_json(raw, stage="health_check")

        if not parsed or not isinstance(parsed, dict) or not bool(parsed.get("ready", False)):
            if self.last_error:
                return False, self.last_error
            return False, "LLM did not return valid JSON for health check."

        return True, "LLM is reachable and returning structured output."

    def plan_iteration_commands(self, scan_state, history, usage_summary, iteration, max_iterations):
        prompt = self._build_iteration_plan_prompt(
            scan_state=scan_state,
            history=history,
            usage_summary=usage_summary,
            iteration=iteration,
            max_iterations=max_iterations,
        )
        raw = self._call_ollama(
            prompt,
            stage="iteration_plan",
            iteration=iteration,
            prompt_context={
                "scan_state": scan_state if config.TRACE_CAPTURE_SCAN_STATE else {},
                "history": history,
                "usage_summary": usage_summary,
            },
        )
        parsed = self._extract_json(raw, stage="iteration_plan", iteration=iteration)

        plan = self._validate_iteration_plan(parsed, scan_state)
        if not plan:
            llm_error = self.last_error or "LLM returned invalid planning JSON."
            if config.ALLOW_LLM_FALLBACK or not config.REQUIRE_LLM:
                plan = self._fallback_iteration_plan(scan_state, usage_summary, iteration)
                plan["llm_error"] = llm_error
                plan["used_fallback"] = True
                plan["reasoning"] = f"{plan.get('reasoning', '')} LLM issue: {llm_error}".strip()
            else:
                plan = {
                    "iteration_goal": "LLM planning failed.",
                    "reasoning": llm_error,
                    "commands": [],
                    "llm_error": llm_error,
                    "used_fallback": False,
                }
        else:
            plan["used_fallback"] = False

        if self.trace_logger:
            self.trace_logger.log_event(
                "iteration_plan_result",
                iteration=iteration,
                iteration_goal=plan.get("iteration_goal", ""),
                reasoning=plan.get("reasoning", ""),
                commands=plan.get("commands", []),
                llm_error=plan.get("llm_error", ""),
                used_fallback=plan.get("used_fallback", False),
            )
        return plan

    def analyze_iteration(self, scan_state, plan, command_results, iteration):
        heuristic = self._heuristic_batch_analysis(scan_state, plan, command_results, iteration)
        combined_output = self._build_combined_output(command_results)

        prompt = self._build_analysis_prompt(scan_state, plan, combined_output, heuristic, iteration)
        raw = self._call_ollama(
            prompt,
            stage="iteration_analysis",
            iteration=iteration,
            prompt_context={
                "scan_state": scan_state if config.TRACE_CAPTURE_SCAN_STATE else {},
                "plan": plan,
                "heuristic": heuristic,
                "combined_output": combined_output if config.TRACE_CAPTURE_ANALYSIS_INPUT else "",
            },
        )
        parsed = self._extract_json(raw, stage="iteration_analysis", iteration=iteration)

        if not parsed:
            if config.REQUIRE_LLM:
                heuristic["risk_signals"] = self._dedupe(
                    heuristic.get("risk_signals", [])
                    + [self.last_error or "LLM analysis response was empty or invalid."]
                )
            if self.trace_logger:
                self.trace_logger.log_event(
                    "iteration_analysis_result",
                    iteration=iteration,
                    analysis=heuristic,
                    llm_error=self.last_error or "invalid-analysis-json",
                    used_fallback=True,
                )
            return heuristic

        summary = str(parsed.get("summary", "")).strip() or heuristic["summary"]
        llm_findings = [str(item).strip() for item in self._listify(parsed.get("key_findings")) if str(item).strip()]
        llm_targets = [str(item).strip() for item in self._listify(parsed.get("new_targets")) if str(item).strip()]
        llm_risks = [str(item).strip() for item in self._listify(parsed.get("risk_signals")) if str(item).strip()]

        llm_vulns = []
        for item in self._listify(parsed.get("vulnerability_candidates")):
            normalized = self._normalize_vuln_candidate(item)
            if normalized:
                llm_vulns.append(normalized)

        confidence = str(parsed.get("confidence", heuristic.get("confidence", "medium"))).strip().lower()
        if confidence not in {"low", "medium", "high"}:
            confidence = "medium"

        result = {
            "summary": summary,
            "key_findings": self._dedupe(heuristic["key_findings"] + llm_findings)[:40],
            "new_targets": self._dedupe(heuristic["new_targets"] + llm_targets)[:40],
            "risk_signals": self._dedupe(heuristic["risk_signals"] + llm_risks)[:30],
            "vulnerability_candidates": self._merge_vuln_candidates(heuristic["vulnerability_candidates"], llm_vulns)[:40],
            "next_focus": str(parsed.get("next_focus", "")).strip() or heuristic["next_focus"],
            "confidence": confidence,
        }
        if self.trace_logger:
            self.trace_logger.log_event(
                "iteration_analysis_result",
                iteration=iteration,
                analysis=result,
                llm_error="",
                used_fallback=False,
            )
        return result

    def build_final_assessment(self, target, scan_state, iteration_records):
        prompt = self._build_final_prompt(target, scan_state, iteration_records)
        raw = self._call_ollama(
            prompt,
            stage="final_assessment",
            prompt_context={
                "target": target,
                "scan_state": scan_state if config.TRACE_CAPTURE_SCAN_STATE else {},
                "iteration_records": iteration_records,
            },
        )
        parsed = self._extract_json(raw, stage="final_assessment")

        if not parsed:
            fallback_vulns = scan_state.get("vulnerability_candidates", [])[:30]
            result = {
                "executive_summary": f"Autonomous AI recon completed for {target} across {len(iteration_records)} iterations.",
                "attack_surface": self._build_attack_surface(scan_state),
                "high_value_findings": scan_state.get("findings", [])[:20],
                "risk_signals": scan_state.get("risk_signals", [])[:20],
                "overall_risk": "medium" if scan_state.get("risk_signals") else "low",
                "confidence": "medium",
                "vulnerabilities": fallback_vulns,
                "recommended_next_steps": [
                    "Validate high-confidence findings with targeted manual checks.",
                    "Prioritize internet-facing assets and sensitive endpoints first.",
                    "Run authenticated validation for confirmed candidates where in scope.",
                ],
            }
            if self.trace_logger:
                self.trace_logger.log_event(
                    "final_assessment_result",
                    assessment=result,
                    llm_error=self.last_error or "invalid-final-json",
                    used_fallback=True,
                )
            return result

        overall_risk = str(parsed.get("overall_risk", "medium")).strip().lower()
        if overall_risk not in {"low", "medium", "high", "critical"}:
            overall_risk = "medium"

        confidence = str(parsed.get("confidence", "medium")).strip().lower()
        if confidence not in {"low", "medium", "high"}:
            confidence = "medium"

        vulnerabilities = []
        for item in self._listify(parsed.get("vulnerabilities")):
            normalized = self._normalize_vuln_candidate(item)
            if normalized:
                vulnerabilities.append(normalized)

        if not vulnerabilities:
            vulnerabilities = scan_state.get("vulnerability_candidates", [])[:30]

        result = {
            "executive_summary": str(parsed.get("executive_summary", "")).strip() or f"Recon finished for {target}.",
            "attack_surface": [str(item).strip() for item in self._listify(parsed.get("attack_surface")) if str(item).strip()],
            "high_value_findings": [str(item).strip() for item in self._listify(parsed.get("high_value_findings")) if str(item).strip()],
            "risk_signals": [str(item).strip() for item in self._listify(parsed.get("risk_signals")) if str(item).strip()],
            "overall_risk": overall_risk,
            "confidence": confidence,
            "vulnerabilities": self._merge_vuln_candidates(scan_state.get("vulnerability_candidates", []), vulnerabilities)[:50],
            "recommended_next_steps": [str(item).strip() for item in self._listify(parsed.get("recommended_next_steps")) if str(item).strip()],
        }
        if self.trace_logger:
            self.trace_logger.log_event(
                "final_assessment_result",
                assessment=result,
                llm_error="",
                used_fallback=False,
            )
        return result

    def _call_ollama(self, prompt, stage="generic", iteration=None, prompt_context=None):
        request_payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "temperature": 0.2,
        }
        started = time.time()
        started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        if self.trace_logger:
            self.trace_logger.log_event(
                "llm_request",
                stage=stage,
                iteration=iteration,
                prompt=prompt,
                prompt_length_chars=len(prompt or ""),
                prompt_context=prompt_context or {},
                request_payload={
                    "model": self.model,
                    "stream": False,
                    "temperature": 0.2,
                    "timeout_sec": config.OLLAMA_TIMEOUT,
                },
            )
        if self._llm_bypass_active:
            self.last_error = "LLM bypass active after an earlier transport failure."
            self._last_llm_meta = {
                "stage": stage,
                "iteration": iteration,
                "started_at": started_at,
                "latency_ms": 0,
                "http_status": None,
                "raw_response": "",
                "response_length_chars": 0,
                "request_payload": {
                    "model": self.model,
                    "stream": False,
                    "temperature": 0.2,
                    "timeout_sec": config.OLLAMA_TIMEOUT,
                },
                "llm_error": self.last_error,
            }
            return ""
        try:
            response = requests.post(
                self.url,
                json=request_payload,
                timeout=config.OLLAMA_TIMEOUT,
            )
            latency_ms = int((time.time() - started) * 1000)
            if response.status_code >= 400:
                error_message = response.text
                try:
                    payload = response.json()
                    error_message = payload.get("error", error_message)
                except Exception:
                    pass
                self.last_error = str(error_message)
                self._last_llm_meta = {
                    "stage": stage,
                    "iteration": iteration,
                    "started_at": started_at,
                    "latency_ms": latency_ms,
                    "http_status": response.status_code,
                    "raw_response": response.text,
                    "response_length_chars": len(response.text or ""),
                    "request_payload": {
                        "model": self.model,
                        "stream": False,
                        "temperature": 0.2,
                        "timeout_sec": config.OLLAMA_TIMEOUT,
                    },
                    "llm_error": self.last_error,
                }
                if config.ALLOW_LLM_FALLBACK:
                    self._llm_bypass_active = True
                return ""

            data = response.json()
            self.last_error = ""
            raw_response = data.get("response", "")
            self._last_llm_meta = {
                "stage": stage,
                "iteration": iteration,
                "started_at": started_at,
                "latency_ms": latency_ms,
                "http_status": response.status_code,
                "raw_response": raw_response,
                "response_length_chars": len(raw_response or ""),
                "request_payload": {
                    "model": self.model,
                    "stream": False,
                    "temperature": 0.2,
                    "timeout_sec": config.OLLAMA_TIMEOUT,
                },
                "llm_error": "",
            }
            return raw_response
        except Exception as exc:
            self.last_error = str(exc)
            self._last_llm_meta = {
                "stage": stage,
                "iteration": iteration,
                "started_at": started_at,
                "latency_ms": int((time.time() - started) * 1000),
                "http_status": None,
                "raw_response": "",
                "response_length_chars": 0,
                "request_payload": {
                    "model": self.model,
                    "stream": False,
                    "temperature": 0.2,
                    "timeout_sec": config.OLLAMA_TIMEOUT,
                },
                "llm_error": self.last_error,
            }
            if config.ALLOW_LLM_FALLBACK:
                self._llm_bypass_active = True
            return ""

    def _extract_json(self, text, stage="generic", iteration=None):
        parse_mode = "failed"
        raw_json_candidate = ""
        parsed = None
        if not text:
            self._log_llm_response(stage, iteration, text, parsed, parse_mode, raw_json_candidate)
            return None

        stripped = text.strip()
        try:
            parsed = json.loads(stripped)
            parse_mode = "json.loads"
            self._log_llm_response(stage, iteration, text, parsed, parse_mode, raw_json_candidate)
            return parsed
        except Exception:
            pass

        matches = re.findall(r"\{[\s\S]*\}", stripped)
        for candidate in reversed(matches):
            try:
                parsed = json.loads(candidate)
                parse_mode = "regex_extract"
                raw_json_candidate = candidate
                self._log_llm_response(stage, iteration, text, parsed, parse_mode, raw_json_candidate)
                return parsed
            except Exception:
                continue
        self._log_llm_response(stage, iteration, text, None, parse_mode, raw_json_candidate)
        return None

    def _log_llm_response(self, stage, iteration, text, parsed, parse_mode, raw_json_candidate):
        if not self.trace_logger:
            return

        meta = self._last_llm_meta or {}
        raw_response = text if text else meta.get("raw_response", "")
        self.trace_logger.log_event(
            "llm_response",
            stage=stage,
            iteration=iteration,
            started_at=meta.get("started_at", ""),
            latency_ms=meta.get("latency_ms"),
            http_status=meta.get("http_status"),
            raw_response=raw_response,
            response_length_chars=len(raw_response or ""),
            parsed_json=parsed,
            parse_meta={
                "parse_success": parsed is not None,
                "parse_mode": parse_mode,
                "raw_json_candidate": raw_json_candidate,
            },
            llm_error=meta.get("llm_error", self.last_error),
            request_payload=meta.get("request_payload", {}),
        )

    def _validate_iteration_plan(self, parsed, scan_state):
        if not parsed or not isinstance(parsed, dict):
            return None

        commands = self._listify(parsed.get("commands"))
        iteration_goal = str(parsed.get("iteration_goal", "")).strip() or "AI-planned reconnaissance iteration."
        reasoning = str(parsed.get("reasoning", "")).strip() or iteration_goal

        normalized_commands = []
        seen = set()
        for item in commands:
            if not isinstance(item, dict):
                continue

            tool = self._normalize_tool(item.get("tool", ""))
            if tool == "invalid":
                continue

            objective = str(item.get("objective", "")).strip() or f"Run {tool} for additional reconnaissance evidence."
            timeout_sec = self._normalize_timeout(item.get("timeout_sec"))
            command = self._normalize_command(str(item.get("command", "")).strip(), tool, scan_state)
            if not command:
                continue

            key = f"{tool}|{command}"
            if key in seen:
                continue
            seen.add(key)

            normalized_commands.append(
                {
                    "tool": tool,
                    "llm_command_raw": str(item.get("command", "")).strip(),
                    "command": command,
                    "objective": objective,
                    "timeout_sec": timeout_sec,
                }
            )
            if len(normalized_commands) >= config.MAX_COMMANDS_PER_ITERATION:
                break

        if not normalized_commands:
            return None

        return {
            "iteration_goal": iteration_goal,
            "reasoning": reasoning,
            "commands": normalized_commands,
        }

    def _normalize_timeout(self, timeout_sec):
        default_timeout = max(config.TOOL_TIMEOUT, 60)
        try:
            parsed = int(timeout_sec)
        except Exception:
            parsed = default_timeout

        if parsed < 30:
            parsed = 30
        if parsed > config.MAX_COMMAND_TIMEOUT:
            parsed = config.MAX_COMMAND_TIMEOUT
        return parsed

    def _normalize_tool(self, tool):
        normalized = str(tool).strip().lower()
        valid = {"nmap", "ffuf", "nuclei", "subfinder"}
        return normalized if normalized in valid else "invalid"

    def _normalize_command(self, command, tool, scan_state):
        target = scan_state.get("target", "")
        network_target = scan_state.get("network_target", target)
        web_base = scan_state.get("preferred_web_url") or (scan_state.get("urls") or [f"http://{network_target}"])[0]

        command = command.replace("{target}", target).replace("<target>", target)
        command = command.replace("{network_target}", network_target).replace("<network_target>", network_target)
        command = command.replace("{web_base}", web_base)
        command = command.replace("{wordlist}", config.DEEP_WORDLIST)
        command = command.replace("{fast_wordlist}", config.FAST_WORDLIST)
        command = command.replace("{deep_wordlist}", config.DEEP_WORDLIST)

        if not command:
            command = self._default_command(tool, scan_state)

        binary = config.TOOL_PATHS.get(tool)
        if binary:
            quoted_binary = f'"{binary}"'
            if not command.lower().startswith(quoted_binary.lower()):
                command = re.sub(r"^\s*(\".*?\"|\S+)", quoted_binary, command, count=1)

        command = self._enforce_command_shape(command.strip(), tool, scan_state)
        return command.strip()

    def _enforce_command_shape(self, command, tool, scan_state):
        target = scan_state.get("target", "")
        network_target = scan_state.get("network_target", target)
        web_base = scan_state.get("preferred_web_url") or (scan_state.get("urls") or [f"http://{network_target}"])[0]

        if tool == "nmap":
            if " -Pn " not in f" {command} ":
                command = f"{command} -Pn"
            if " -sV " not in f" {command} ":
                command = f"{command} -sV"
            if network_target and network_target not in command:
                command = f"{command} {network_target}"

        elif tool == "subfinder":
            if not self._is_domain(target):
                return ""
            if " -d " not in f" {command} ":
                command = f"{command} -d {target}"
            if " -silent " not in f" {command} ":
                command = f"{command} -silent"

        elif tool == "ffuf":
            if " -u " not in f" {command} ":
                command = f"{command} -u {web_base}/FUZZ"
            elif "FUZZ" not in command:
                command = f"{command} -u {web_base}/FUZZ"
            if " -w " not in f" {command} ":
                command = f"{command} -w \"{config.FAST_WORDLIST}\""
            if " -mc " not in f" {command} ":
                command = f"{command} -mc 200,204,301,302,307,401,403"
            if " -maxtime-job " not in f" {command} ":
                command = f"{command} -maxtime-job 120"

        elif tool == "nuclei":
            if " -u " not in f" {command} ":
                command = f"{command} -u {web_base}"
            if " -silent " not in f" {command} ":
                command = f"{command} -silent"
            if " -severity " not in f" {command} ":
                command = f"{command} -severity critical,high,medium"

        return command

    def _default_command(self, tool, scan_state):
        target = scan_state.get("target", "")
        network_target = scan_state.get("network_target", target)
        web_base = scan_state.get("preferred_web_url") or (scan_state.get("urls") or [f"http://{network_target}"])[0]

        if tool == "nmap":
            return f'"{config.NMAP_PATH}" -sV -Pn -p 80,443,8080,8443,21,22,25,3306,3389 {network_target}'
        if tool == "subfinder":
            if not self._is_domain(target):
                return ""
            return f'"{config.SUBFINDER_PATH}" -d {target} -silent'
        if tool == "ffuf":
            return (
                f'"{config.FFUF_PATH}" -u {web_base}/FUZZ '
                f'-w "{config.FAST_WORDLIST}" -mc 200,204,301,302,307,401,403 -maxtime-job 120'
            )
        if tool == "nuclei":
            return f'"{config.NUCLEI_PATH}" -u {web_base} -severity critical,high,medium -silent'
        return ""

    def _fallback_iteration_plan(self, scan_state, usage_summary, iteration):
        target = scan_state.get("target", "")
        network_target = scan_state.get("network_target", target)
        web_urls = scan_state.get("urls", [])
        if not web_urls:
            if self._is_domain(network_target):
                web_urls = [f"http://{network_target}", f"https://{network_target}"]
            else:
                web_urls = [f"http://{network_target}"]

        best_url = scan_state.get("preferred_web_url") or web_urls[0]
        open_ports = scan_state.get("open_ports", [])
        port_csv = ",".join(open_ports[:20])

        commands = []
        if iteration == 1:
            if self._is_domain(target):
                commands.append(
                    {
                        "tool": "subfinder",
                        "command": f'"{config.SUBFINDER_PATH}" -d {target} -silent',
                        "objective": "Enumerate subdomains to expand attack surface.",
                        "timeout_sec": 120,
                    }
                )
            commands.append(
                {
                    "tool": "nmap",
                    "command": f'"{config.NMAP_PATH}" -sV -Pn -p 80,443,8080,8443,21,22,25,3306,3389 {network_target}',
                    "objective": "Map exposed ports and service versions.",
                    "timeout_sec": 180,
                }
            )
            commands.append(
                {
                    "tool": "nuclei",
                    "command": f'"{config.NUCLEI_PATH}" -u {best_url} -severity critical,high,medium -silent',
                    "objective": "Run quick vulnerability template checks on the primary endpoint.",
                    "timeout_sec": 180,
                }
            )

        elif iteration == 2:
            commands.append(
                {
                    "tool": "ffuf",
                    "command": (
                        f'"{config.FFUF_PATH}" -u {best_url}/FUZZ '
                        f'-w "{config.FAST_WORDLIST}" -mc 200,204,301,302,307,401,403 '
                        "-maxtime-job 120"
                    ),
                    "objective": "Discover hidden endpoints and sensitive paths quickly.",
                    "timeout_sec": 180,
                }
            )
            commands.append(
                {
                    "tool": "nuclei",
                    "command": f'"{config.NUCLEI_PATH}" -u {best_url} -severity critical,high,medium -silent',
                    "objective": "Correlate path discovery with known vulnerability signatures.",
                    "timeout_sec": 180,
                }
            )
            if open_ports:
                commands.append(
                    {
                        "tool": "nmap",
                        "command": f'"{config.NMAP_PATH}" -sV -Pn -p {port_csv} {network_target}',
                        "objective": "Re-validate active service versions on discovered ports.",
                        "timeout_sec": 180,
                    }
                )

        elif iteration == 3:
            if open_ports:
                commands.append(
                    {
                        "tool": "nmap",
                        "command": f'"{config.NMAP_PATH}" -Pn -sV --script vuln -p {port_csv} {network_target}',
                        "objective": "Run targeted service-level vulnerability scripts.",
                        "timeout_sec": 240,
                    }
                )
            commands.append(
                {
                    "tool": "ffuf",
                    "command": (
                        f'"{config.FFUF_PATH}" -u {best_url}/FUZZ '
                        f'-w "{config.DEEP_WORDLIST}" -mc 200,204,301,302,307,401,403 '
                        "-maxtime-job 180"
                    ),
                    "objective": "Run deeper endpoint discovery for missed attack paths.",
                    "timeout_sec": 240,
                }
            )
            commands.append(
                {
                    "tool": "nuclei",
                    "command": f'"{config.NUCLEI_PATH}" -u {best_url} -silent',
                    "objective": "Perform broader template checks on the highest-priority endpoint.",
                    "timeout_sec": 240,
                }
            )

        else:
            final_url = best_url
            commands.append(
                {
                    "tool": "nuclei",
                    "command": f'"{config.NUCLEI_PATH}" -u {final_url} -severity critical,high,medium,low -silent',
                    "objective": "Confirm and expand final vulnerability evidence.",
                    "timeout_sec": 240,
                }
            )
            commands.append(
                {
                    "tool": "ffuf",
                    "command": (
                        f'"{config.FFUF_PATH}" -u {final_url}/FUZZ '
                        f'-w "{config.FAST_WORDLIST}" -mc 200,204,301,302,307,401,403 '
                        "-maxtime-job 90"
                    ),
                    "objective": "Re-check for high-signal hidden paths with bounded runtime.",
                    "timeout_sec": 150,
                }
            )
            if self._is_domain(target):
                commands.append(
                    {
                        "tool": "subfinder",
                        "command": f'"{config.SUBFINDER_PATH}" -d {target} -silent',
                        "objective": "Final subdomain sweep for completeness.",
                        "timeout_sec": 120,
                    }
                )

        normalized_commands = []
        for item in commands[: config.MAX_COMMANDS_PER_ITERATION]:
            tool = self._normalize_tool(item.get("tool"))
            command = self._normalize_command(item.get("command", ""), tool, scan_state)
            if tool == "invalid" or not command:
                continue
            normalized_commands.append(
                {
                    "tool": tool,
                    "llm_command_raw": item.get("command", ""),
                    "command": command,
                    "objective": item.get("objective", f"Run {tool} command."),
                    "timeout_sec": self._normalize_timeout(item.get("timeout_sec")),
                }
            )

        return {
            "iteration_goal": f"AI fallback recon expansion for iteration {iteration}.",
            "reasoning": "Fallback strategy used because model response was invalid or incomplete.",
            "commands": normalized_commands,
        }

    def _build_iteration_plan_prompt(self, scan_state, history, usage_summary, iteration, max_iterations):
        return f"""
You are the autonomous planning brain for reconnaissance.

Task:
- Generate a powerful command batch for this iteration only.
- Focus on finding vulnerabilities, exposures, and high-value attack surface details.
- Use legal, non-destructive reconnaissance commands only.
- Output ONLY valid JSON.

Rules:
- Allowed tools: nmap, ffuf, nuclei, subfinder.
- Generate 2 to {config.MAX_COMMANDS_PER_ITERATION} commands.
- Each command must have tool, command, objective, timeout_sec.
- Timeout should be between 30 and {config.MAX_COMMAND_TIMEOUT} seconds.
- Prefer commands that increase evidence quality over noisy repetition.

Context:
- Target: {scan_state.get('target')}
- Network target: {scan_state.get('network_target')}
- Open ports: {scan_state.get('open_ports', [])}
- Services: {scan_state.get('services', {})}
- URLs: {scan_state.get('urls', [])}
- Additional hosts: {scan_state.get('additional_hosts', [])}
- Findings so far: {scan_state.get('findings', [])[-20:]}
- Risk signals so far: {scan_state.get('risk_signals', [])[-20:]}
- Previous focus queue: {scan_state.get('focus_queue', [])[-10:]}
- History: {history[-config.HISTORY_LIMIT:]}
- Tool usage summary: {usage_summary}
- Iteration: {iteration}/{max_iterations}

Placeholders you may use in commands:
- {{target}}
- {{network_target}}
- {{web_base}}
- {{fast_wordlist}}
- {{deep_wordlist}}

Return exact JSON shape:
{{
  "iteration_goal": "short goal",
  "reasoning": "why these commands",
  "commands": [
    {{
      "tool": "nmap|ffuf|nuclei|subfinder",
      "command": "full command",
      "objective": "what signal this command should produce",
      "timeout_sec": 120
    }}
  ]
}}
"""

    def _build_analysis_prompt(self, scan_state, plan, combined_output, heuristic, iteration):
        return f"""
You are analyzing results of an AI-planned reconnaissance batch.

Target: {scan_state.get('target')}
Iteration: {iteration}
Iteration goal: {plan.get('iteration_goal')}
Planner reasoning: {plan.get('reasoning')}
Heuristic pre-analysis:
{heuristic}

Combined command output:
{combined_output[:22000]}

Return ONLY JSON with this exact shape:
{{
  "summary": "2-5 sentence concise summary",
  "key_findings": ["finding1", "finding2"],
  "new_targets": ["url_or_host1", "url_or_host2"],
  "risk_signals": ["risk1", "risk2"],
  "vulnerability_candidates": [
    {{
      "title": "finding title",
      "severity": "critical|high|medium|low|info",
      "asset": "host_or_url",
      "evidence": "direct evidence snippet",
      "source": "tool/command context",
      "recommendation": "next validation step"
    }}
  ],
  "next_focus": "what the next iteration should probe deeper",
  "confidence": "low|medium|high"
}}

Do not invent exploitation results. Use only evidence from the provided output.
"""

    def _build_final_prompt(self, target, scan_state, iteration_records):
        compact_iterations = []
        for item in iteration_records:
            compact_iterations.append(
                {
                    "iteration": item.get("iteration"),
                    "goal": item.get("iteration_goal"),
                    "summary": item.get("analysis_summary"),
                    "findings": item.get("key_findings", [])[:12],
                    "risks": item.get("risk_signals", [])[:12],
                    "vulns": item.get("vulnerability_candidates", [])[:12],
                    "commands": [
                        {
                            "tool": cmd.get("tool"),
                            "exit_code": cmd.get("exit_code"),
                            "timed_out": cmd.get("timed_out"),
                            "duration_sec": cmd.get("duration_sec"),
                        }
                        for cmd in item.get("commands", [])
                    ],
                }
            )

        return f"""
Create the final vulnerability-focused reconnaissance assessment for target {target}.

Evidence context:
- Attack surface: {self._build_attack_surface(scan_state)}
- Consolidated findings: {scan_state.get('findings', [])}
- Consolidated risk signals: {scan_state.get('risk_signals', [])}
- Consolidated vulnerability candidates: {scan_state.get('vulnerability_candidates', [])}
- Iteration records: {compact_iterations}

Return ONLY JSON:
{{
  "executive_summary": "short paragraph",
  "attack_surface": ["asset1", "asset2"],
  "high_value_findings": ["finding1", "finding2"],
  "risk_signals": ["risk1", "risk2"],
  "overall_risk": "low|medium|high|critical",
  "confidence": "low|medium|high",
  "vulnerabilities": [
    {{
      "title": "finding title",
      "severity": "critical|high|medium|low|info",
      "asset": "host_or_url",
      "evidence": "evidence snippet",
      "source": "tool/iteration",
      "recommendation": "next action"
    }}
  ],
  "recommended_next_steps": ["step1", "step2", "step3"]
}}
"""

    def _build_combined_output(self, command_results):
        blocks = []
        for item in command_results:
            blocks.append(
                "\n".join(
                    [
                        f"[TOOL] {item.get('tool')}",
                        f"[OBJECTIVE] {item.get('objective', '')}",
                        f"[COMMAND] {item.get('command', '')}",
                        f"[EXIT] {item.get('exit_code')} timed_out={item.get('timed_out')}",
                        f"[OUTPUT]\n{item.get('analysis_input', '')}",
                    ]
                )
            )
        return "\n\n".join(blocks)

    def _heuristic_batch_analysis(self, scan_state, plan, command_results, iteration):
        findings = []
        new_targets = []
        risk_signals = []
        vulnerabilities = []

        for result in command_results:
            tool = result.get("tool", "unknown")
            output = result.get("analysis_input") or result.get("output", "")
            lines = [line.strip() for line in output.splitlines() if line.strip()]

            for url in re.findall(r"https?://[^\s'\"<>]+", output):
                parsed = urlparse(url)
                if self._is_in_scope_host(parsed.hostname, scan_state):
                    new_targets.append(url)

            if tool == "nmap":
                for match in re.finditer(r"(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)", output):
                    port = match.group(1)
                    proto = match.group(2).upper()
                    service = match.group(3)
                    findings.append(f"Open {proto} port {port} running {service}.")
                    if port in {"21", "22", "23", "25", "445", "3389"}:
                        vulnerabilities.append(
                            {
                                "title": f"Sensitive service exposed on port {port}",
                                "severity": "medium",
                                "asset": scan_state.get("network_target", scan_state.get("target", "")),
                                "evidence": f"{proto} {port}/{service} reported open by nmap.",
                                "source": "nmap",
                                "recommendation": "Validate service exposure and restrict access if unnecessary.",
                            }
                        )

            elif tool == "ffuf":
                for line in lines:
                    if any(code in line for code in [" 200 ", " 204 ", " 301 ", " 302 ", " 307 ", " 401 ", " 403 "]):
                        findings.append(f"Interesting ffuf response: {line[:180]}")
                        if any(keyword in line.lower() for keyword in ["admin", "login", "backup", "debug", "config"]):
                            vulnerabilities.append(
                                {
                                    "title": "Potential sensitive endpoint discovered",
                                    "severity": "medium",
                                    "asset": scan_state.get("preferred_web_url", scan_state.get("target", "")),
                                    "evidence": line[:220],
                                    "source": "ffuf",
                                    "recommendation": "Manually validate access controls and response behavior.",
                                }
                            )

            elif tool == "nuclei":
                for line in lines[:200]:
                    lowered = line.lower()
                    if "[" in line and "]" in line:
                        findings.append(f"Nuclei match: {line[:180]}")
                        severity = "info"
                        for level in ["critical", "high", "medium", "low"]:
                            if level in lowered:
                                severity = level
                                break
                        vulnerabilities.append(
                            {
                                "title": "Nuclei template match",
                                "severity": severity,
                                "asset": scan_state.get("preferred_web_url", scan_state.get("target", "")),
                                "evidence": line[:220],
                                "source": "nuclei",
                                "recommendation": "Confirm template finding manually and triage by severity.",
                            }
                        )

            elif tool == "subfinder":
                for line in lines[:300]:
                    candidate = line.strip().lower()
                    if candidate and " " not in candidate and "." in candidate and self._is_in_scope_host(candidate, scan_state):
                        findings.append(f"Discovered subdomain: {candidate}")
                        new_targets.append(candidate)

            if result.get("timed_out"):
                risk_signals.append(f"{tool} command timed out; visibility may be incomplete.")
            if result.get("exit_code", 0) != 0:
                risk_signals.append(f"{tool} returned exit code {result.get('exit_code')}.")

        summary = "No significant findings parsed from this iteration output."
        if findings or risk_signals or vulnerabilities:
            summary = (
                f"Iteration {iteration} produced {len(findings)} findings, "
                f"{len(vulnerabilities)} vulnerability candidates, and {len(risk_signals)} risk signals."
            )

        return {
            "summary": summary,
            "key_findings": self._dedupe(findings)[:40],
            "new_targets": self._dedupe(new_targets)[:40],
            "risk_signals": self._dedupe(risk_signals)[:30],
            "vulnerability_candidates": self._merge_vuln_candidates([], vulnerabilities)[:40],
            "next_focus": "Prioritize high-confidence endpoints and confirm vulnerability evidence.",
            "confidence": "medium",
        }

    def _normalize_vuln_candidate(self, item):
        if not isinstance(item, dict):
            return None

        title = str(item.get("title", "")).strip()
        if not title:
            return None

        severity = str(item.get("severity", "info")).strip().lower()
        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "info"

        asset = str(item.get("asset", "")).strip()
        evidence = str(item.get("evidence", "")).strip()
        source = str(item.get("source", "")).strip()
        recommendation = str(item.get("recommendation", "")).strip()

        return {
            "title": title,
            "severity": severity,
            "asset": asset,
            "evidence": evidence,
            "source": source,
            "recommendation": recommendation,
        }

    def _merge_vuln_candidates(self, base, extra):
        merged = []
        seen = set()
        for item in list(base) + list(extra):
            normalized = self._normalize_vuln_candidate(item)
            if not normalized:
                continue
            key = (
                normalized.get("title", ""),
                normalized.get("asset", ""),
                normalized.get("evidence", "")[:120],
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(normalized)
        return merged

    @staticmethod
    def _listify(value):
        if isinstance(value, list):
            return value
        if value is None:
            return []
        return [value]

    @staticmethod
    def _dedupe(items):
        seen = set()
        result = []
        for item in items:
            key = str(item).strip()
            if not key or key in seen:
                continue
            seen.add(key)
            result.append(key)
        return result

    @staticmethod
    def _is_domain(target):
        candidate = (target or "").strip()
        if not candidate:
            return False
        try:
            ipaddress.ip_address(candidate)
            return False
        except ValueError:
            return "." in candidate

    @staticmethod
    def _is_in_scope_host(host, scan_state):
        if not host:
            return False

        host_value = str(host).lower().strip()
        candidates = {
            str(scan_state.get("target", "")).lower().strip(),
            str(scan_state.get("network_target", "")).lower().strip(),
        }

        for item in scan_state.get("additional_hosts", []):
            candidates.add(str(item).lower().strip())

        for url in scan_state.get("urls", []):
            parsed = urlparse(url)
            if parsed.hostname:
                candidates.add(parsed.hostname.lower().strip())

        for candidate in candidates:
            if not candidate:
                continue
            if host_value == candidate or host_value.endswith(f".{candidate}"):
                return True
        return False

    def _build_attack_surface(self, scan_state):
        surface = []
        target = scan_state.get("target")
        if target:
            surface.append(f"Primary target: {target}")

        for port in scan_state.get("open_ports", []):
            service = scan_state.get("services", {}).get(port, "unknown")
            surface.append(f"Open port {port} ({service})")

        for url in scan_state.get("urls", []):
            surface.append(f"Web endpoint: {url}")

        for host in scan_state.get("additional_hosts", []):
            surface.append(f"Discovered host: {host}")

        return self._dedupe(surface)[:30]
