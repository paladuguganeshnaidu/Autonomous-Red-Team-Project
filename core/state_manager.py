"""Shared memory state persistence for the autonomous recon loop."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


class StateManager:
    """Persist and load shared state from memory/session.json."""

    def __init__(self, session_file: str) -> None:
        """Initialize state manager with a session file path."""
        self.session_file = Path(session_file)

    def load(self) -> Dict[str, Any]:
        """Load state from disk or return a default state."""
        if self.session_file.exists():
            try:
                with self.session_file.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                if isinstance(payload, dict):
                    return self._normalize_state(payload)
            except (OSError, json.JSONDecodeError):
                pass
        return self._default_state("")

    def initialize(self, target: str, reset: bool = True) -> Dict[str, Any]:
        """Initialize state for a target, resetting previous run data when requested."""
        if reset:
            state = self._default_state(target)
        else:
            state = self.load()
            state["target"] = target

        self.persist(state)
        return state

    def persist(self, state: Dict[str, Any]) -> None:
        """Persist normalized state to disk."""
        normalized = self._normalize_state(state)
        self.session_file.parent.mkdir(parents=True, exist_ok=True)
        with self.session_file.open("w", encoding="utf-8") as handle:
            json.dump(normalized, handle, indent=2)

    def _default_state(self, target: str) -> Dict[str, Any]:
        """Create a default state object aligned to required memory schema."""
        return {
            "target": str(target).strip(),
            "subdomains": [],
            "ports": [],
            "services": [],
            "technologies": [],
            "endpoints": [],
            "vulnerabilities": [],
            "actions_taken": [],
            "action_history": [],
            "history": [],
        }

    def _normalize_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize arbitrary state data into safe schema and list types."""
        normalized = self._default_state(str(state.get("target", "")).strip())

        for key in [
            "subdomains",
            "ports",
            "services",
            "technologies",
            "endpoints",
            "vulnerabilities",
            "actions_taken",
            "action_history",
            "history",
        ]:
            value = state.get(key, [])
            normalized[key] = value if isinstance(value, list) else []

        return normalized
