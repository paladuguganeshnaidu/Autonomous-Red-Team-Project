import random
import time

from tools.http_probe import run_ffuf_scan
from tools.http_probe import run_http_probe
from tools.http_probe import run_whatweb_detect
from tools.nmap_tool import run_nmap
from tools.subdomain_tool import run_subdomain_enum


class Executor:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self._last_action_at = 0.0
        self._ua_index = 0

    def run_actions(self, actions):
        results = []

        for index, action in enumerate(actions, start=1):
            tool = action.get("tool", "")
            params = action.get("params", {})
            description = action.get("description", "")
            self.logger.info("Executing step %s with tool=%s | %s", index, tool, description)

            self._apply_stealth_delay()

            attempts = max(0, int(self.config.command_retries)) + 1
            result = None
            for attempt in range(1, attempts + 1):
                result = self._execute_one(tool, params)
                result["attempt"] = attempt

                if int(result.get("exit_code", -1)) == 0:
                    break

                if attempt < attempts:
                    self.logger.warning(
                        "Tool %s failed on attempt %s/%s: %s",
                        tool,
                        attempt,
                        attempts,
                        result.get("error", "unknown-error"),
                    )

            if result is None:
                result = {
                    "tool": tool,
                    "exit_code": -1,
                    "error": "Execution failed without result payload.",
                    "raw_output": "",
                }

            results.append(result)
            self.logger.info("Tool %s finished with exit_code=%s", tool, result.get("exit_code"))

        return results

    def _execute_one(self, tool, params):
        try:
            if tool == "nmap":
                return run_nmap(
                    target=params.get("target", ""),
                    nmap_path=self.config.nmap_path,
                    timeout=self.config.command_timeout,
                )

            if tool == "subdomain":
                return run_subdomain_enum(
                    domain=params.get("domain", ""),
                    subfinder_path=self.config.subfinder_path,
                    timeout=self.config.command_timeout,
                )

            if tool == "http_probe":
                return run_http_probe(
                    urls=params.get("urls", []),
                    httpx_path=self.config.httpx_path,
                    timeout=self.config.request_timeout,
                    user_agent=self._next_user_agent(),
                )

            if tool == "ffuf":
                return run_ffuf_scan(
                    base_url=params.get("base_url", ""),
                    ffuf_path=self.config.ffuf_path,
                    wordlist=self.config.ffuf_wordlist,
                    match_codes=self.config.ffuf_match_codes,
                    timeout=self.config.command_timeout,
                    max_time=self.config.ffuf_max_time,
                    rate=self.config.ffuf_rate,
                )

            if tool == "whatweb":
                return run_whatweb_detect(
                    urls=params.get("urls", []),
                    whatweb_path=self.config.whatweb_path,
                    timeout=self.config.command_timeout,
                )

            return {
                "tool": tool,
                "exit_code": -1,
                "error": f"Unsupported tool: {tool}",
                "raw_output": "",
            }
        except Exception as exc:
            return {
                "tool": tool,
                "exit_code": -1,
                "error": f"Executor exception: {exc}",
                "raw_output": "",
            }

    def _next_user_agent(self):
        user_agents = self.config.user_agents or ["AutonomousRedTeam/1.0"]
        self._ua_index = (self._ua_index + 1) % len(user_agents)
        return user_agents[self._ua_index]

    def _apply_stealth_delay(self):
        now = time.time()

        rate = float(self.config.rate_limit_per_sec)
        if rate > 0:
            min_interval = 1.0 / rate
            elapsed = now - self._last_action_at
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)

        if self.config.enable_jitter:
            jitter_min = float(self.config.jitter_min_sec)
            jitter_max = float(self.config.jitter_max_sec)
            if jitter_max < jitter_min:
                jitter_min, jitter_max = jitter_max, jitter_min
            time.sleep(random.uniform(jitter_min, jitter_max))

        self._last_action_at = time.time()
