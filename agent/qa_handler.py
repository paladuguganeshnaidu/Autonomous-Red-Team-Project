import json
import logging
import requests
from typing import Any, Dict, List
from core.memory import ConversationMemory

logger = logging.getLogger("autonomous_recon")

def answer_follow_up(message: str, memory: ConversationMemory, config: Any) -> str:
    """
    Search memory for context related to the user's question and answer it using the LLM.
    """
    recent_msgs = memory.get_recent(15)
    
    # We build a context block from the recent messages and the session summary
    context_lines = []
    if memory.summary:
        context_lines.append(f"[Session Summary]\n{memory.summary}\n")
        
    context_lines.append("[Recent Memory]")
    for m in recent_msgs:
        meta_str = f" [Meta: {json.dumps(m.get('metadata'))}]" if m.get("metadata") else ""
        context_lines.append(f"{m['role'].upper()}{meta_str}: {m['content']}")
        
    context_str = "\n".join(context_lines)
    
    prompt = f"""
You are an expert security analyst answering a follow-up question from the user.
Use ONLY the provided memory context to answer the question. Do not invent new findings.
If the answer is not in the memory, say that you don't have that information.
Explain technical findings clearly.

Context:
{context_str}

User Question: {message}

Your Response:
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
        logger.error(f"[ERROR] Q&A handler failed: {exc}")
        return f"Sorry, I encountered an error while trying to answer: {exc}"
