# executor.py
import subprocess
import time
from datetime import datetime

import config
from result_validator import validate_result


class Executor:
    def __init__(self, timeout=60, trace_logger=None):
        self.timeout = timeout
        self.log = []
        self.trace_logger = trace_logger

    def run(self, command, tool_name, timeout=None, iteration=None, command_index=None, objective="", llm_command=None):
        print(f"\n[EXEC] {tool_name.upper()}")
        print(f"[CMD ] {command}\n")
        start = time.time()
        effective_timeout = timeout or self.timeout
        started_at = datetime.now().isoformat()
        try:
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=effective_timeout,
            )

            duration = time.time() - start
            stdout = process.stdout or ""
            stderr = process.stderr or ""
            combined_output = stdout + stderr
            preview = combined_output[: config.OUTPUT_PREVIEW_CHARS]
            if len(combined_output) > config.OUTPUT_PREVIEW_CHARS:
                preview += "\n... [truncated]"

            analysis_input = combined_output[: config.ANALYSIS_INPUT_CHARS]
            if len(combined_output) > config.ANALYSIS_INPUT_CHARS:
                analysis_input += "\n... [analysis truncated]"

            if preview.strip():
                print(preview)
            else:
                print("[INFO] Command produced no output.")

            entry = {
                "timestamp": datetime.now().isoformat(),
                "started_at": started_at,
                "finished_at": datetime.now().isoformat(),
                "tool": tool_name,
                "command": command,
                "llm_command": llm_command or command,
                "objective": objective,
                "command_index": command_index,
                "iteration": iteration,
                "exit_code": process.returncode,
                "output": preview,
                "analysis_input": analysis_input,
                "stdout": stdout,
                "stderr": stderr,
                "raw_output_size": len(combined_output),
                "duration_sec": round(duration, 2),
                "timed_out": False,
                "timeout_sec": effective_timeout,
            }
            entry["verification"] = validate_result(tool_name, analysis_input)
            self.log.append(entry)
            if self.trace_logger:
                self.trace_logger.log_event(
                    "command_execution",
                    iteration=iteration,
                    command_index=command_index,
                    tool=tool_name,
                    objective=objective,
                    llm_command_raw=llm_command or command,
                    command_executed=command,
                    started_at=started_at,
                    finished_at=entry["finished_at"],
                    exit_code=process.returncode,
                    duration_sec=entry["duration_sec"],
                    timed_out=False,
                    timeout_sec=effective_timeout,
                    stdout=stdout if config.TRACE_CAPTURE_STDOUT_STDERR else "",
                    stderr=stderr if config.TRACE_CAPTURE_STDOUT_STDERR else "",
                    output_preview=preview,
                    analysis_input=analysis_input if config.TRACE_CAPTURE_ANALYSIS_INPUT else "",
                    raw_output_size=len(combined_output),
                )
            return entry

        except subprocess.TimeoutExpired as exc:
            duration = time.time() - start
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            partial = stdout + stderr
            preview = partial[: config.OUTPUT_PREVIEW_CHARS]
            if len(partial) > config.OUTPUT_PREVIEW_CHARS:
                preview += "\n... [truncated]"

            analysis_input = partial[: config.ANALYSIS_INPUT_CHARS]
            if len(partial) > config.ANALYSIS_INPUT_CHARS:
                analysis_input += "\n... [analysis truncated]"

            entry = {
                "timestamp": datetime.now().isoformat(),
                "started_at": started_at,
                "finished_at": datetime.now().isoformat(),
                "tool": tool_name,
                "command": command,
                "llm_command": llm_command or command,
                "objective": objective,
                "command_index": command_index,
                "iteration": iteration,
                "exit_code": -1,
                "output": preview,
                "analysis_input": analysis_input,
                "stdout": stdout,
                "stderr": stderr,
                "raw_output_size": len(partial),
                "duration_sec": round(duration, 2),
                "timed_out": True,
                "timeout_sec": effective_timeout,
                "error": f"Command timed out after {effective_timeout}s",
            }
            entry["verification"] = validate_result(tool_name, analysis_input)
            self.log.append(entry)
            if self.trace_logger:
                self.trace_logger.log_event(
                    "command_execution",
                    iteration=iteration,
                    command_index=command_index,
                    tool=tool_name,
                    objective=objective,
                    llm_command_raw=llm_command or command,
                    command_executed=command,
                    started_at=started_at,
                    finished_at=entry["finished_at"],
                    exit_code=-1,
                    duration_sec=entry["duration_sec"],
                    timed_out=True,
                    timeout_sec=effective_timeout,
                    stdout=stdout if config.TRACE_CAPTURE_STDOUT_STDERR else "",
                    stderr=stderr if config.TRACE_CAPTURE_STDOUT_STDERR else "",
                    output_preview=preview,
                    analysis_input=analysis_input if config.TRACE_CAPTURE_ANALYSIS_INPUT else "",
                    raw_output_size=len(partial),
                    error=entry["error"],
                )
            return entry

        except Exception as e:
            duration = time.time() - start
            entry = {
                "timestamp": datetime.now().isoformat(),
                "started_at": started_at,
                "finished_at": datetime.now().isoformat(),
                "tool": tool_name,
                "command": command,
                "llm_command": llm_command or command,
                "objective": objective,
                "command_index": command_index,
                "iteration": iteration,
                "exit_code": -1,
                "output": "",
                "analysis_input": "",
                "stdout": "",
                "stderr": "",
                "raw_output_size": 0,
                "duration_sec": round(duration, 2),
                "timed_out": False,
                "timeout_sec": effective_timeout,
                "error": str(e),
            }
            entry["verification"] = {"useful": False, "signals": []}
            self.log.append(entry)
            if self.trace_logger:
                self.trace_logger.log_event(
                    "command_execution",
                    iteration=iteration,
                    command_index=command_index,
                    tool=tool_name,
                    objective=objective,
                    llm_command_raw=llm_command or command,
                    command_executed=command,
                    started_at=started_at,
                    finished_at=entry["finished_at"],
                    exit_code=-1,
                    duration_sec=entry["duration_sec"],
                    timed_out=False,
                    timeout_sec=effective_timeout,
                    stdout="",
                    stderr="",
                    output_preview="",
                    analysis_input="",
                    raw_output_size=0,
                    error=str(e),
                )
            return entry
