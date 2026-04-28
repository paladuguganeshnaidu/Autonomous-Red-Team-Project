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

def run_scan_in_background(target: str, session_id: str = None):
    logger.info(f"[SYSTEM] Starting scan for target={target}")
    try:
        config = AppConfig.from_env()
        if not getattr(config, "max_iterations", None):
            config.max_iterations = 10
            
        state_manager = StateManager(config.session_file)
        state = state_manager.initialize(target=target, reset=True)
        
        from core.memory import ConversationMemory
        from main import run_autonomous_scan
        
        memory = ConversationMemory()
        if session_id:
            memory.load_session(session_id)
        else:
            memory.add_message("user", f"Start a new scan on {target}")

        run_autonomous_scan(state, config, logger, memory, state_manager)
        
        if session_id:
            memory.save_session(session_id)

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

from typing import Optional

@app.post("/start")
async def start_scan(target: str, chat_id: Optional[str] = None):
    threading.Thread(target=run_scan_in_background, args=(target, chat_id), daemon=True).start()
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
        
    from core.memory import ConversationMemory
    from agent.interpreter import classify_intent
    from agent.qa_handler import answer_follow_up
    
    memory = ConversationMemory()
    if chat_id:
        memory.load_session(chat_id)
        
    memory.add_message("user", data.message)
    
    chat_doc["messages"].append({
        "id": str(uuid.uuid4()),
        "role": "user",
        "content": data.message,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    intent_res = classify_intent(data.message, memory.get_summary(), memory.get_recent(5), config)
    intent = intent_res.get("intent")
    extracted_target = intent_res.get("extracted_target")
    
    command = ""
    action = ""
    
    if intent == "new_scan":
        if extracted_target:
            state["target"] = extracted_target
        response_text = f"Starting new scan on {state.get('target', 'unknown')}...\nIf you want to view the output, you can monitor the background process."
        action = "start_scan"
    elif intent == "meta":
        response_text = "I think that's a system command. (Note: System commands like /load or /save work better in CLI, via Web I sync automatically)."
    else:
        response_text = answer_follow_up(data.message, memory, config)

    memory.add_message("agent", response_text)
    if chat_id:
        memory.save_session(chat_id)
        
    logger.info(f"[CHAT_AGENT] {response_text}")

    chat_doc["messages"].append({
        "id": str(uuid.uuid4()),
        "role": "agent",
        "content": response_text,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    with open(CHATS_DIR / f"{chat_id}.json", "w") as f:
        json.dump(chat_doc, f, indent=2)
        
    if action == "start_scan":
        threading.Thread(target=run_scan_in_background, args=(state.get("target"), chat_id), daemon=True).start()
        
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
