"""Robust streaming LLM client with retries for Ollama-compatible APIs."""

from __future__ import annotations

from dataclasses import dataclass
import json
import time
from typing import Any, Dict, Iterable, Optional, Tuple

import requests


class LLMUnavailableError(RuntimeError):
    """Raised when the configured LLM backend cannot produce a response."""


@dataclass
class LLMClientConfig:
    """Runtime configuration for the shared LLM client."""

    url: str
    model: str
    connect_timeout: int = 5
    read_timeout: int = 30
    max_retries: int = 3


class RobustLLMClient:
    """Stateful HTTP client for LLM requests with pooling and backoff."""

    def __init__(self, config: LLMClientConfig) -> None:
        self.config = config
        self.session = requests.Session()

    def close(self) -> None:
        """Close the underlying pooled session."""
        self.session.close()

    def generate(
        self,
        prompt: str,
        *,
        system: str = "",
        options: Optional[Dict[str, Any]] = None,
        max_retries: Optional[int] = None,
        timeout: Optional[Tuple[int, int]] = None,
        stream: bool = True,
    ) -> str:
        """Generate text with retries and streamed parsing."""
        retries = self.config.max_retries if max_retries is None else max(1, int(max_retries))
        request_timeout = timeout or (self.config.connect_timeout, self.config.read_timeout)
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": stream,
        }
        if system:
            payload["system"] = system
        if options:
            payload["options"] = options

        last_error: Optional[Exception] = None
        for attempt in range(retries):
            try:
                response = self.session.post(
                    self.config.url,
                    json=payload,
                    timeout=request_timeout,
                    stream=stream,
                )
                response.raise_for_status()
                return self._parse_stream(response) if stream else self._parse_single(response)
            except (requests.Timeout, requests.ConnectionError, requests.HTTPError, ValueError) as exc:
                last_error = exc
                if attempt == retries - 1:
                    break
                time.sleep(min(8, 2 ** attempt))

        raise LLMUnavailableError(f"LLM not responding after {retries} attempts: {last_error}")

    def _parse_single(self, response: requests.Response) -> str:
        """Parse a non-streaming Ollama response payload."""
        payload = response.json()
        return str(payload.get("response", "")).strip()

    def _parse_stream(self, response: requests.Response) -> str:
        """Parse a streamed Ollama response into a single text string."""
        chunks = []
        for line in response.iter_lines(decode_unicode=True):
            if not line:
                continue
            data = json.loads(line)
            chunks.append(str(data.get("response", "")))
            if bool(data.get("done", False)):
                break
        return "".join(chunks).strip()


_CLIENTS: Dict[Tuple[str, str, int, int, int], RobustLLMClient] = {}


def get_llm_client(config: Any) -> RobustLLMClient:
    """Return a shared stateful LLM client keyed by config values."""
    url = str(getattr(config, "ollama_url", "http://localhost:11434/api/generate"))
    model = str(getattr(config, "ollama_model", "mistral"))
    connect_timeout = int(getattr(config, "llm_connect_timeout", 5))
    read_timeout = int(getattr(config, "llm_read_timeout", 30))
    max_retries = int(getattr(config, "llm_max_retries", 3))

    key = (url, model, connect_timeout, read_timeout, max_retries)
    if key not in _CLIENTS:
        _CLIENTS[key] = RobustLLMClient(
            LLMClientConfig(
                url=url,
                model=model,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                max_retries=max_retries,
            )
        )
    return _CLIENTS[key]
