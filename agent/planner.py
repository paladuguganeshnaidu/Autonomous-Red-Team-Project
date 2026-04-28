"""Scoring-based planner for adaptive autonomous recon decisions."""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse


from core.llm import plan_with_llm

def decide_next_action(state: dict, config: Any, memory_summary: str = "", recent_messages: List[Dict[str, Any]] = None) -> dict:
    """Use the LLM to decide the next action dynamically."""
    return plan_with_llm(state, config, memory_summary=memory_summary, recent_messages=recent_messages)

