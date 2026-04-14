import json
import os
import uuid
from datetime import datetime, timezone


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


class StateManager:
    def __init__(self, session_file):
        self.session_file = session_file
        self.state = self._load_or_init()

    def _default_state(self):
        return {
            "run_id": str(uuid.uuid4()),
            "target": "",
            "status": "initialized",
            "active_agent": "recon_agent",
            "current_iteration": 0,
            "iterations": [],
            "subdomains": [],
            "ports": [],
            "services": [],
            "vulnerabilities": [],
            "scores": {
                "confidence_score": 0.0,
                "risk_score": 0.0,
            },
            "decisions": [],
            "tool_failures": [],
            "stop_reason": "",
            "created_at": _utc_now_iso(),
            "updated_at": _utc_now_iso(),
            "summary": {},
        }

    def _normalize_loaded_state(self, payload):
        normalized = self._default_state()
        normalized.update(payload)

        if not normalized.get("run_id"):
            normalized["run_id"] = str(uuid.uuid4())

        if "open_ports" in payload and not normalized.get("ports"):
            normalized["ports"] = payload.get("open_ports", [])

        if "discovered_subdomains" in payload and not normalized.get("subdomains"):
            normalized["subdomains"] = payload.get("discovered_subdomains", [])

        if not isinstance(normalized.get("scores"), dict):
            normalized["scores"] = {
                "confidence_score": 0.0,
                "risk_score": 0.0,
            }

        normalized["scores"].setdefault("confidence_score", 0.0)
        normalized["scores"].setdefault("risk_score", 0.0)

        for key in [
            "iterations",
            "subdomains",
            "ports",
            "services",
            "vulnerabilities",
            "decisions",
            "tool_failures",
        ]:
            if not isinstance(normalized.get(key), list):
                normalized[key] = []

        if not normalized.get("created_at"):
            normalized["created_at"] = _utc_now_iso()

        return normalized

    def _load_or_init(self):
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                if isinstance(payload, dict):
                    normalized = self._normalize_loaded_state(payload)
                    normalized["updated_at"] = _utc_now_iso()
                    return normalized
            except (OSError, json.JSONDecodeError):
                pass
        return self._default_state()

    def _save(self):
        os.makedirs(os.path.dirname(self.session_file), exist_ok=True)
        self.state["updated_at"] = _utc_now_iso()
        with open(self.session_file, "w", encoding="utf-8") as handle:
            json.dump(self.state, handle, indent=2)

    def set_target(self, target, reset_run=True):
        if reset_run:
            self.state = self._default_state()
            self.state["target"] = target
            self.state["status"] = "running"
            self._save()
            return

        self.state["target"] = target
        self.state["status"] = "running"
        self._save()

    def start_iteration(self, iteration):
        self.state["current_iteration"] = iteration
        self._save()

    def _append_unique(self, key, values):
        existing = self.state.get(key, [])
        for value in values:
            if value not in existing:
                existing.append(value)
        self.state[key] = existing

    def _append_unique_dict(self, key, values, fields):
        existing = self.state.get(key, [])
        seen = {
            tuple(item.get(field) for field in fields)
            for item in existing
            if isinstance(item, dict)
        }

        for value in values:
            if not isinstance(value, dict):
                continue
            signature = tuple(value.get(field) for field in fields)
            if signature in seen:
                continue
            seen.add(signature)
            existing.append(value)

        self.state[key] = existing

    def record_decision(self, iteration, decision):
        self.state["active_agent"] = decision.get("agent_role", "recon_agent")
        self.state.setdefault("decisions", []).append(
            {
                "iteration": iteration,
                "agent_role": decision.get("agent_role", "recon_agent"),
                "reason": decision.get("reason", ""),
                "stop": bool(decision.get("stop", False)),
                "recorded_at": _utc_now_iso(),
            }
        )
        self._save()

    def record_iteration(self, iteration, plan, results, analysis):
        record = {
            "iteration": iteration,
            "plan": plan,
            "results": results,
            "analysis": analysis,
            "recorded_at": _utc_now_iso(),
        }
        self.state.setdefault("iterations", []).append(record)

        self._append_unique("ports", analysis.get("ports", []))
        self._append_unique("subdomains", analysis.get("subdomains", []))
        self._append_unique_dict("services", analysis.get("services", []), ["port", "service"])
        self._append_unique_dict("vulnerabilities", analysis.get("vulnerabilities", []), ["title", "asset", "evidence"])

        scores = self.state.setdefault("scores", {"confidence_score": 0.0, "risk_score": 0.0})
        scores["confidence_score"] = float(analysis.get("confidence_score", scores.get("confidence_score", 0.0)))
        scores["risk_score"] = float(analysis.get("risk_score", scores.get("risk_score", 0.0)))

        for result in results:
            if int(result.get("exit_code", -1)) != 0:
                self.state.setdefault("tool_failures", []).append(
                    {
                        "iteration": iteration,
                        "tool": result.get("tool", "unknown"),
                        "error": result.get("error", "unknown-error"),
                        "recorded_at": _utc_now_iso(),
                    }
                )

        if analysis.get("stop_recommended") and not self.state.get("stop_reason"):
            self.state["stop_reason"] = str(analysis.get("stop_reason", "High-risk finding detected.")).strip()

        self._save()

    def should_stop(self):
        return bool(self.state.get("stop_reason"))

    def mark_stop(self, reason):
        self.state["stop_reason"] = str(reason or "Stopped by decision engine.").strip()
        self.state["status"] = "stopped"
        self._save()

    def finish(self, summary):
        if self.state.get("status") != "stopped":
            self.state["status"] = "completed"
        self.state["summary"] = summary
        self._save()
