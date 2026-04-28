import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

class ConversationMemory:
    def __init__(self, session_id: str = "default", persist_dir: str = "~/.autonomous_redteaming/sessions"):
        self.session_id = session_id
        self.persist_dir = Path(os.path.expanduser(persist_dir))
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.messages: List[Dict[str, Any]] = []
        self.summary: str = ""
        self.load_session(session_id)

    def add_message(self, role: str, content: str, metadata: Optional[Dict[str, Any]] = None):
        """Add a message to the memory."""
        msg = {
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "role": role,
            "content": content,
            "metadata": metadata or {}
        }
        self.messages.append(msg)
        self._auto_save()

    def get_recent(self, n: int = 10) -> List[Dict[str, Any]]:
        """Get the N most recent messages."""
        return self.messages[-n:] if n > 0 else self.messages

    def get_summary(self) -> str:
        """Return the current running summary."""
        return self.summary

    def search_by_metadata(self, **kwargs) -> List[Dict[str, Any]]:
        """Search memory messages by matching metadata keys and values."""
        results = []
        for msg in self.messages:
            meta = msg.get("metadata", {})
            match = True
            for k, v in kwargs.items():
                if meta.get(k) != v:
                    match = False
                    break
            if match and kwargs:
                results.append(msg)
        return results

    def save_session(self, name: str):
        """Save current memory to a session file."""
        self.session_id = name
        self._auto_save()

    def load_session(self, name: str) -> bool:
        """Load a session by name, returns True if successful."""
        file_path = self.persist_dir / f"{name}.json"
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.session_id = data.get("session_id", name)
                    self.messages = data.get("messages", [])
                    self.summary = data.get("summary", "")
                return True
            except Exception:
                pass
        self.session_id = name
        self.messages = []
        self.summary = ""
        return False

    def list_sessions(self) -> List[str]:
        """List all available session names."""
        sessions = []
        for f in self.persist_dir.glob("*.json"):
            sessions.append(f.stem)
        return sorted(sessions)

    def clear(self):
        """Clear current session messages."""
        self.messages = []
        self.summary = ""
        self._auto_save()

    def _auto_save(self):
        file_path = self.persist_dir / f"{self.session_id}.json"
        data = {
            "session_id": self.session_id,
            "summary": self.summary,
            "messages": self.messages
        }
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def compress_if_needed(self, compress_func, threshold: int = 20, keep: int = 10):
        """
        If message count exceeds threshold, compress the oldest (threshold - keep) messages 
        into the summary using the provided compress_func.
        """
        if len(self.messages) > threshold:
            to_compress_count = len(self.messages) - keep
            messages_to_compress = self.messages[:to_compress_count]
            
            # Format messages for the LLM
            text_to_compress = "\n".join([f"{m['role'].upper()}: {m['content']}" for m in messages_to_compress])
            
            # Use the provided function to generate a new summary
            new_summary_addendum = compress_func(text_to_compress)
            
            if self.summary:
                self.summary = f"{self.summary}\n{new_summary_addendum}"
            else:
                self.summary = new_summary_addendum
                
            # Remove the compressed messages and auto-save
            self.messages = self.messages[to_compress_count:]
            self._auto_save()
