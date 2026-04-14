from dataclasses import dataclass, field
import os


@dataclass
class AppConfig:
    max_iterations: int = 4
    command_timeout: int = 120
    command_retries: int = 1

    nmap_path: str = "nmap"
    subfinder_path: str = "subfinder"
    httpx_path: str = "httpx"
    ffuf_path: str = "ffuf"
    whatweb_path: str = "whatweb"

    ffuf_wordlist: str = os.path.join("wordlists", "Wordlists", "fuzz_wordlist.txt")
    ffuf_match_codes: str = "200,204,301,302,307,401,403"
    ffuf_max_time: int = 90
    ffuf_rate: int = 25

    request_timeout: int = 10
    user_agents: list[str] = field(
        default_factory=lambda: [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15"
            " (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        ]
    )

    enable_jitter: bool = True
    jitter_min_sec: float = 0.3
    jitter_max_sec: float = 1.2
    rate_limit_per_sec: float = 2.0

    stop_on_vuln: bool = True
    use_llm_planner: bool = False
    ollama_url: str = "http://localhost:11434/api/generate"
    ollama_model: str = "mistral"
    llm_timeout: int = 45

    log_file: str = os.path.join("logs", "session.log")
    session_file: str = os.path.join("memory", "session.json")

    @classmethod
    def from_env(cls):
        user_agents_raw = os.getenv("HTTP_USER_AGENTS", "").strip()
        if user_agents_raw:
            user_agents = [item.strip() for item in user_agents_raw.split("||") if item.strip()]
        else:
            user_agents = cls().user_agents

        ffuf_wordlist = os.getenv("FFUF_WORDLIST", os.path.join("wordlists", "Wordlists", "fuzz_wordlist.txt"))
        if not os.path.exists(ffuf_wordlist):
            fallback_wordlist = os.path.join("wordlists", "Wordlists", "wordlist.txt")
            if os.path.exists(fallback_wordlist):
                ffuf_wordlist = fallback_wordlist

        return cls(
            max_iterations=int(os.getenv("MAX_ITERATIONS", "4")),
            command_timeout=int(os.getenv("COMMAND_TIMEOUT", "120")),
            command_retries=int(os.getenv("COMMAND_RETRIES", "1")),
            nmap_path=os.getenv("NMAP_PATH", "nmap"),
            subfinder_path=os.getenv("SUBFINDER_PATH", "subfinder"),
            httpx_path=os.getenv("HTTPX_PATH", "httpx"),
            ffuf_path=os.getenv("FFUF_PATH", "ffuf"),
            whatweb_path=os.getenv("WHATWEB_PATH", "whatweb"),
            ffuf_wordlist=ffuf_wordlist,
            ffuf_match_codes=os.getenv("FFUF_MATCH_CODES", "200,204,301,302,307,401,403"),
            ffuf_max_time=int(os.getenv("FFUF_MAX_TIME", "90")),
            ffuf_rate=int(os.getenv("FFUF_RATE", "25")),
            request_timeout=int(os.getenv("REQUEST_TIMEOUT", "10")),
            user_agents=user_agents,
            enable_jitter=os.getenv("ENABLE_JITTER", "true").strip().lower() == "true",
            jitter_min_sec=float(os.getenv("JITTER_MIN_SEC", "0.3")),
            jitter_max_sec=float(os.getenv("JITTER_MAX_SEC", "1.2")),
            rate_limit_per_sec=float(os.getenv("RATE_LIMIT_PER_SEC", "2.0")),
            stop_on_vuln=os.getenv("STOP_ON_VULN", "true").strip().lower() == "true",
            use_llm_planner=os.getenv("USE_LLM_PLANNER", "false").strip().lower() == "true",
            ollama_url=os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate"),
            ollama_model=os.getenv("OLLAMA_MODEL", "mistral"),
            llm_timeout=int(os.getenv("LLM_TIMEOUT", "45")),
            log_file=os.getenv("LOG_FILE", os.path.join("logs", "session.log")),
            session_file=os.getenv("SESSION_FILE", os.path.join("memory", "session.json")),
        )
