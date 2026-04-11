import json
import os
import re
from datetime import datetime


class TraceLogger:
    def __init__(self, target, run_id, output_dir="output", enabled=True, environment=None):
        self.enabled = bool(enabled)
        self.path = ""
        self.payload = {
            "schema_version": "1.0",
            "run_id": run_id,
            "target": target,
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "environment": environment or {},
            "events": [],
            "final_assessment": None,
        }

        if not self.enabled:
            return

        os.makedirs(output_dir, exist_ok=True)
        safe_target = self._safe_filename_component(target)
        self.path = os.path.join(output_dir, f"session_{safe_target}_{run_id}.json")
        self._write()

    def log_event(self, event_type, **fields):
        if not self.enabled:
            return

        event = {"type": event_type, "timestamp": fields.pop("timestamp", datetime.now().isoformat())}
        event.update(fields)
        self.payload["events"].append(event)
        self._write()

    def complete(self, final_assessment):
        self.payload["completed_at"] = datetime.now().isoformat()
        self.payload["final_assessment"] = final_assessment
        if self.enabled:
            self._write()

    def _write(self):
        with open(self.path, "w", encoding="utf-8") as file_handle:
            json.dump(self.payload, file_handle, indent=2, ensure_ascii=False, default=str)

    @staticmethod
    def _safe_filename_component(value):
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or ""))
        cleaned = cleaned.strip("._")
        return cleaned or "target"
