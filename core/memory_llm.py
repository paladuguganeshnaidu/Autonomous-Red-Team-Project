import logging
import requests
from typing import Any

logger = logging.getLogger("autonomous_recon")

def summarize_memory(text_to_compress: str, config: Any) -> str:
    """
    Summarize a chunk of conversation history into a concise factual summary.
    """
    prompt = f"""
Summarize the key facts discovered so far in the following conversation.
Focus on targets scanned, tools used, vulnerabilities found, and important decisions.
Keep it under 3 sentences.

Conversation:
{text_to_compress}

Summary:
"""
    try:
        response = requests.post(
            str(getattr(config, "ollama_url", "http://localhost:11434/api/generate")),
            json={
                "model": str(getattr(config, "ollama_model", "mistral")),
                "prompt": prompt,
                "stream": False,
            },
            timeout=int(getattr(config, "llm_timeout", 180)),
        )
        response.raise_for_status()

        return str(response.json().get("response", "")).strip()
    except Exception as exc:
        logger.error(f"[ERROR] Memory summarization failed: {exc}")
        return ""
