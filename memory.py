# memory.py
import sqlite3
import json
import uuid
from datetime import datetime


class Memory:
    def __init__(self, db_path="redteam.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self._init_tables()

    def _init_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                target TEXT,
                started_at TEXT,
                completed_at TEXT,
                final_summary_json TEXT
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS run_iterations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                iteration INTEGER,
                timestamp TEXT,
                tool TEXT,
                objective TEXT,
                reasoning TEXT,
                command TEXT,
                output_preview TEXT,
                exit_code INTEGER,
                duration_sec REAL,
                timed_out INTEGER,
                analysis_summary TEXT,
                key_findings_json TEXT,
                new_targets_json TEXT,
                FOREIGN KEY(run_id) REFERENCES runs(run_id)
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS run_state_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                iteration INTEGER,
                timestamp TEXT,
                state_json TEXT,
                FOREIGN KEY(run_id) REFERENCES runs(run_id)
            )
        ''')

        self._ensure_column("run_iterations", "risk_signals_json", "TEXT")
        self._ensure_column("run_iterations", "next_focus", "TEXT")
        self._ensure_column("run_iterations", "confidence", "TEXT")
        self.conn.commit()

    def _ensure_column(self, table_name, column_name, definition):
        self.cursor.execute(f"PRAGMA table_info({table_name})")
        existing_columns = {row[1] for row in self.cursor.fetchall()}
        if column_name not in existing_columns:
            self.cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")

    def start_run(self, target):
        run_id = uuid.uuid4().hex
        self.cursor.execute(
            "INSERT INTO runs (run_id, target, started_at) VALUES (?,?,?)",
            (run_id, target, datetime.now().isoformat()),
        )
        self.conn.commit()
        return run_id

    def store_iteration(self, run_id, iteration, decision, execution_result, analysis):
        self.cursor.execute(
            """
            INSERT INTO run_iterations (
                run_id, iteration, timestamp, tool, objective, reasoning, command,
                output_preview, exit_code, duration_sec, timed_out,
                analysis_summary, key_findings_json, new_targets_json,
                risk_signals_json, next_focus, confidence
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                run_id,
                iteration,
                execution_result.get("timestamp", datetime.now().isoformat()),
                decision.get("tool"),
                decision.get("objective", ""),
                decision.get("reasoning", ""),
                decision.get("command", ""),
                execution_result.get("output", "")[:4000],
                execution_result.get("exit_code", -1),
                execution_result.get("duration_sec", 0.0),
                1 if execution_result.get("timed_out", False) else 0,
                analysis.get("summary", ""),
                json.dumps(analysis.get("key_findings", [])),
                json.dumps(analysis.get("new_targets", [])),
                json.dumps(analysis.get("risk_signals", [])),
                analysis.get("next_focus", ""),
                analysis.get("confidence", "medium"),
            ),
        )
        self.conn.commit()

    def get_history(self, run_id, limit=6):
        self.cursor.execute(
            """
            SELECT ri.iteration, ri.tool, ri.objective, ri.analysis_summary
            FROM run_iterations ri
            INNER JOIN (
                SELECT iteration, MAX(id) AS max_id
                FROM run_iterations
                WHERE run_id = ?
                GROUP BY iteration
            ) latest ON latest.max_id = ri.id
            WHERE ri.run_id = ?
            ORDER BY ri.iteration DESC
            LIMIT ?
            """,
            (run_id, run_id, limit),
        )
        rows = self.cursor.fetchall()
        history = []
        for row in rows:
            history.append(
                f"iter={row['iteration']} tool={row['tool']} objective={row['objective']} outcome={row['analysis_summary']}"
            )
        history.reverse()
        return history

    def get_iterations(self, run_id):
        self.cursor.execute(
            """
            SELECT iteration, timestamp, tool, objective, reasoning, command, output_preview,
                   exit_code, duration_sec, timed_out, analysis_summary,
                     key_findings_json, new_targets_json, risk_signals_json, next_focus, confidence
            FROM run_iterations
            WHERE run_id = ?
            ORDER BY iteration ASC, id ASC
            """,
            (run_id,),
        )
        rows = self.cursor.fetchall()

        result = []
        for row in rows:
            result.append(
                {
                    "iteration": row["iteration"],
                    "timestamp": row["timestamp"],
                    "tool": row["tool"],
                    "objective": row["objective"],
                    "reasoning": row["reasoning"],
                    "command": row["command"],
                    "output_preview": row["output_preview"],
                    "exit_code": row["exit_code"],
                    "duration_sec": row["duration_sec"],
                    "timed_out": bool(row["timed_out"]),
                    "analysis_summary": row["analysis_summary"],
                    "key_findings": self._safe_json_list(row["key_findings_json"]),
                    "new_targets": self._safe_json_list(row["new_targets_json"]),
                    "risk_signals": self._safe_json_list(row["risk_signals_json"]),
                    "next_focus": row["next_focus"] or "",
                    "confidence": row["confidence"] or "medium",
                }
            )
        return result

    def store_state_snapshot(self, run_id, iteration, scan_state):
        self.cursor.execute(
            """
            INSERT INTO run_state_snapshots (run_id, iteration, timestamp, state_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                run_id,
                iteration,
                datetime.now().isoformat(),
                json.dumps(scan_state),
            ),
        )
        self.conn.commit()

    def get_tool_usage_summary(self, run_id):
        self.cursor.execute(
            """
            SELECT
                tool,
                COUNT(*) AS total,
                SUM(CASE WHEN exit_code = 0 THEN 1 ELSE 0 END) AS success_count,
                SUM(CASE WHEN exit_code != 0 THEN 1 ELSE 0 END) AS failure_count,
                SUM(CASE WHEN timed_out = 1 THEN 1 ELSE 0 END) AS timeout_count,
                MAX(iteration) AS last_iteration
            FROM run_iterations
            WHERE run_id = ?
            GROUP BY tool
            """,
            (run_id,),
        )
        rows = self.cursor.fetchall()

        summary = {}
        for row in rows:
            summary[row["tool"]] = {
                "total": int(row["total"] or 0),
                "success_count": int(row["success_count"] or 0),
                "failure_count": int(row["failure_count"] or 0),
                "timeout_count": int(row["timeout_count"] or 0),
                "last_iteration": int(row["last_iteration"] or 0),
            }
        return summary

    def get_recent_findings(self, run_id, limit=12):
        self.cursor.execute(
            """
            SELECT key_findings_json
            FROM run_iterations
            WHERE run_id = ?
            ORDER BY iteration DESC, id DESC
            LIMIT ?
            """,
            (run_id, limit),
        )
        rows = self.cursor.fetchall()

        findings = []
        for row in rows:
            findings.extend(self._safe_json_list(row["key_findings_json"]))
        findings = [item for item in findings if item]
        findings.reverse()
        return findings[-limit:]

    def complete_run(self, run_id, final_summary):
        self.cursor.execute(
            "UPDATE runs SET completed_at = ?, final_summary_json = ? WHERE run_id = ?",
            (datetime.now().isoformat(), json.dumps(final_summary), run_id),
        )
        self.conn.commit()

    @staticmethod
    def _safe_json_list(value):
        if not value:
            return []
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []

    def close(self):
        self.conn.close()