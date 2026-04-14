"""Runtime configuration for the autonomous recon agent."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import List


def _env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable with a safe default."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Read an integer environment variable with fallback on invalid values."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    """Read a float environment variable with fallback on invalid values."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


def _resolve_wordlist(default_path: str) -> str:
    """Resolve the first existing wordlist path from environment and defaults."""
    env_path = os.getenv("DIRSEARCH_WORDLIST", "").strip()
    candidates = [
        env_path,
        default_path,
        str(Path("wordlists") / "fuzz_wordlist.txt"),
    ]

    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return default_path


def _resolve_user_agents() -> List[str]:
    """Resolve user-agent rotation list from environment or defaults."""
    raw = os.getenv("HTTP_USER_AGENTS", "").strip()
    if raw:
        parsed = [item.strip() for item in raw.split("||") if item.strip()]
        if parsed:
            return parsed

    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    ]


@dataclass
class AppConfig:
    """Application-level settings loaded from environment variables."""

    max_iterations: int = 8
    command_timeout: int = 120
    command_retries: int = 2

    nmap_path: str = "nmap"
    subfinder_path: str = "subfinder"
    httpx_path: str = "httpx"
    ffuf_path: str = "ffuf"

    dirsearch_wordlist: str = str(Path("wordlists") / "fuzz_wordlist.txt")
    dirsearch_match_codes: str = "200,204,301,302,307,401,403"
    dirsearch_max_time: int = 90
    dirsearch_rate: int = 25

    request_timeout: int = 10
    user_agents: List[str] = field(default_factory=_resolve_user_agents)

    enable_jitter: bool = True
    jitter_min_sec: float = 0.3
    jitter_max_sec: float = 1.2
    rate_limit_per_sec: float = 2.0

    stop_on_vuln: bool = True
    use_llm_planner: bool = False
    ollama_url: str = "http://localhost:11434/api/generate"
    ollama_model: str = "mistral"
    llm_timeout: int = 45
    enable_llm_analysis: bool = True
    llm_min_confidence_stop: float = 0.85
    max_no_data_loops: int = 3

    log_file: str = str(Path("logs") / "session.log")
    session_file: str = str(Path("memory") / "session.json")

    @classmethod
    def from_env(cls) -> "AppConfig":
        """Build a configuration object from environment variables."""
        default_wordlist = str(Path("wordlists") / "fuzz_wordlist.txt")

        return cls(
            max_iterations=_env_int("MAX_ITERATIONS", 8),
            command_timeout=_env_int("COMMAND_TIMEOUT", 120),
            command_retries=min(2, max(0, _env_int("COMMAND_RETRIES", 2))),
            nmap_path=os.getenv("NMAP_PATH", "nmap"),
            subfinder_path=os.getenv("SUBFINDER_PATH", "subfinder"),
            httpx_path=os.getenv("HTTPX_PATH", "httpx"),
            ffuf_path=os.getenv("FFUF_PATH", "ffuf"),
            dirsearch_wordlist=_resolve_wordlist(default_wordlist),
            dirsearch_match_codes=os.getenv("DIRSEARCH_MATCH_CODES", "200,204,301,302,307,401,403"),
            dirsearch_max_time=_env_int("DIRSEARCH_MAX_TIME", 90),
            dirsearch_rate=_env_int("DIRSEARCH_RATE", 25),
            request_timeout=_env_int("REQUEST_TIMEOUT", 10),
            user_agents=_resolve_user_agents(),
            enable_jitter=_env_bool("ENABLE_JITTER", True),
            jitter_min_sec=_env_float("JITTER_MIN_SEC", 0.3),
            jitter_max_sec=_env_float("JITTER_MAX_SEC", 1.2),
            rate_limit_per_sec=_env_float("RATE_LIMIT_PER_SEC", 2.0),
            stop_on_vuln=_env_bool("STOP_ON_VULN", True),
            use_llm_planner=_env_bool("USE_LLM_PLANNER", False),
            ollama_url=os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate"),
            ollama_model=os.getenv("OLLAMA_MODEL", "mistral"),
            llm_timeout=_env_int("LLM_TIMEOUT", 45),
            enable_llm_analysis=_env_bool("ENABLE_LLM_ANALYSIS", True),
            llm_min_confidence_stop=_env_float("LLM_MIN_CONFIDENCE_STOP", 0.85),
            max_no_data_loops=max(1, _env_int("MAX_NO_DATA_LOOPS", 3)),
            log_file=os.getenv("LOG_FILE", str(Path("logs") / "session.log")),
            session_file=os.getenv("SESSION_FILE", str(Path("memory") / "session.json")),
        )
