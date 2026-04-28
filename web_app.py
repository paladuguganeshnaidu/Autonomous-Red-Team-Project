import asyncio
import logging
import threading
import sys
import os
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import uvicorn

import main
from core.config import AppConfig
from core.logger import build_logger
from core.state_manager import StateManager
from agent.planner import decide_next_action
from agent.executor import execute_action
from agent.analyzer import analyze_result
from main import _latest_no_new_data, _no_new_data_streak, _has_high_confidence_vulnerability, _action_signature

app = FastAPI()

connected_clients = set()
loop = None

class WebSocketLogHandler(logging.Handler):
    def emit(self, record):
        if loop is None:
            return
        log_entry = self.format(record)
        # Send to all connected websockets
        async def broadcast():
            for client in list(connected_clients):
                try:
                    await client.send_text(log_entry)
                except Exception:
                    connected_clients.remove(client)
        
        asyncio.run_coroutine_threadsafe(broadcast(), loop)

logger = logging.getLogger("autonomous_recon")
logger.setLevel(logging.INFO)
ws_handler = WebSocketLogHandler()
formatter = logging.Formatter("%(message)s")
ws_handler.setFormatter(formatter)
logger.addHandler(ws_handler)

def run_scan_in_background(target: str):
    logger.info(f"[SYSTEM] Starting scan for target={target}")
    try:
        config = AppConfig.from_env()
        if not getattr(config, "max_iterations", None):
            config.max_iterations = 10
            
        state_manager = StateManager(config.session_file)
        state = state_manager.initialize(target=target, reset=True)
        
        iteration = 0
        while True:
            if iteration >= int(config.max_iterations):
                logger.info("[SYSTEM] Max iterations reached.")
                break

            action = decide_next_action(state, config)
            logger.info(f"[DECISION] {action}")

            if str(action.get("action", "")).strip().lower() == "stop":
                logger.info("[SYSTEM] Planner decided to stop.")
                state.setdefault("history", []).append({
                    "type": "loop-stop",
                    "reason": action.get("reason", "Planner requested stop."),
                    "score": float(action.get("score", 1.0) or 1.0),
                })
                state_manager.persist(state)
                break

            signature = _action_signature(action)
            if signature not in state.get("actions_taken", []):
                state.setdefault("actions_taken", []).append(signature)

            cmd_to_run = action.get('command', '')
            logger.info(f"[EXECUTING] {cmd_to_run}")
            result = execute_action(action, config)
            logger.info(f"[RESULT] {result}")

            state = analyze_result(result, state, config)
            no_new_data = _latest_no_new_data(state)

            state.setdefault("action_history", []).append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": str(action.get("action", "")).strip().lower(),
                "target": str(action.get("target", "")).strip(),
                "score": float(action.get("score", 0.0) or 0.0),
                "reason": str(action.get("reason", "")).strip(),
                "status": str(result.get("status", "failed")).strip().lower(),
                "no_new_data": no_new_data,
            })

            logger.info(f"[STATE] subdomains={len(state.get('subdomains', []))} ports={len(state.get('ports', []))} vulnerabilities={len(state.get('vulnerabilities', []))}")

            state_manager.persist(state)
            iteration += 1

            max_no_data_loops = int(getattr(config, "max_no_data_loops", 3))
            if _no_new_data_streak(state, max_no_data_loops) >= max_no_data_loops:
                logger.info(f"[SYSTEM] Stopping after {max_no_data_loops} loops with no new data.")
                break

            if _has_high_confidence_vulnerability(state, float(getattr(config, "llm_min_confidence_stop", 0.85))):
                logger.info("[SYSTEM] High-confidence vulnerability detected. Stopping.")
                break

        state_manager.persist(state)
        logger.info("[SYSTEM] Scan completed.")
    except Exception as e:
        logger.info(f"[ERROR] Scan failed: {e}")

@app.on_event("startup")
async def startup_event():
    global loop
    loop = asyncio.get_running_loop()

os.makedirs("web/static", exist_ok=True)
app.mount("/static", StaticFiles(directory="web/static"), name="static")

@app.get("/")
async def get():
    with open("web/static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.post("/start")
async def start_scan(target: str):
    threading.Thread(target=run_scan_in_background, args=(target,), daemon=True).start()
    return {"message": "Scan started in background."}

from pydantic import BaseModel
from typing import Optional
import uuid
import os
import json
from datetime import datetime, timezone
from pathlib import Path

CHATS_DIR = Path("memory") / "chats"
os.makedirs(CHATS_DIR, exist_ok=True)

class ChatMessage(BaseModel):
    target: str
    message: str
    chat_id: Optional[str] = None

@app.get("/chats")
def get_chats():
    chats = []
    for file in CHATS_DIR.glob("*.json"):
        try:
            with open(file, "r") as f:
                data = json.load(f)
                chats.append({
                    "chat_id": data.get("chat_id"),
                    "target": data.get("target"),
                    "created_at": data.get("created_at", ""),
                })
        except:
            pass
    chats.sort(key=lambda x: x["created_at"], reverse=True)
    return chats

@app.get("/chat/{chat_id}")
def get_chat(chat_id: str):
    file_path = CHATS_DIR / f"{chat_id}.json"
    if file_path.exists():
        with open(file_path, "r") as f:
            return json.load(f)
    return {"error": "Chat not found"}

@app.post("/chat")
def chat_endpoint(data: ChatMessage):
    if data.chat_id and (CHATS_DIR / f"{data.chat_id}.json").exists():
        chat_id = data.chat_id
        with open(CHATS_DIR / f"{chat_id}.json", "r") as f:
            chat_doc = json.load(f)
    else:
        chat_id = str(uuid.uuid4())
        chat_doc = {
            "chat_id": chat_id,
            "target": data.target,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "messages": []
        }

    config = AppConfig.from_env()
    
    try:
        with open(config.session_file, "r") as f:
            state = json.load(f)
    except:
        state = {"target": data.target}
        
    from core.llm import chat_with_agent
    
    chat_doc["messages"].append({
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": data.message,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    agent_output = chat_with_agent(data.message, state, chat_doc["messages"], config)
    
    if isinstance(agent_output, dict):
        response_text = agent_output.get("response", str(agent_output))
        action = agent_output.get("action", "")
        command = agent_output.get("command", "")
    else:
        response_text = str(agent_output)
        action = ""
        command = ""
    
    if action == "run_command" and command:
        response_text += f"\n\n**Executing Command:** `{command}`"
        
    logger.info(f"[CHAT_AGENT] {response_text}")

    chat_doc["messages"].append({
        "id": str(uuid.uuid4()),
        "role": "agent",
        "content": response_text,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    with open(CHATS_DIR / f"{chat_id}.json", "w") as f:
        json.dump(chat_doc, f, indent=2)
        
    if action == "run_command" and command:
        def run_copilot_command(cmd, tgt, current_state):
            logger.info(f"[SYSTEM] Copilot executing: {cmd}")
            act = {"action": "run_command", "command": cmd, "target": tgt}
            res = execute_action(act, config)
            logger.info(f"[RESULT] {res}")
            new_state = analyze_result(res, current_state, config)
            StateManager(config.session_file).persist(new_state)

        threading.Thread(target=run_copilot_command, args=(command, data.target, state), daemon=True).start()
        
    return {"response": response_text, "chat_id": chat_id, "command": command}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
