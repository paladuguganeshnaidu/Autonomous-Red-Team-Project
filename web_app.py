import asyncio
import logging
import os
import socket
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

from core.config import AppConfig
from core.state_manager import StateManager
import json
import uuid

connected_clients = set()
loop = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global loop
    loop = asyncio.get_running_loop()
    yield


app = FastAPI(lifespan=lifespan)

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


CHATS_DIR = Path("memory") / "chats"
os.makedirs(CHATS_DIR, exist_ok=True)


def _chat_path(chat_id: str) -> Path:
    """Return the persistent path for a chat transcript."""
    return CHATS_DIR / f"{chat_id}.json"


def _load_chat_doc(chat_id: str, target: str = "") -> Dict[str, Any]:
    """Load a chat transcript or initialize a new one."""
    file_path = _chat_path(chat_id)
    if file_path.exists():
        with open(file_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if target and not data.get("target"):
            data["target"] = target
        return data

    return {
        "chat_id": chat_id,
        "target": target,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "messages": [],
    }


def _save_chat_doc(chat_doc: Dict[str, Any]) -> None:
    """Persist a chat transcript to disk."""
    with open(_chat_path(str(chat_doc.get("chat_id"))), "w", encoding="utf-8") as handle:
        json.dump(chat_doc, handle, indent=2)


def _append_chat_message(
    chat_id: str,
    role: str,
    content: str,
    metadata: Optional[Dict[str, Any]] = None,
    target: str = "",
) -> None:
    """Append one message to a chat transcript."""
    chat_doc = _load_chat_doc(chat_id, target=target)
    if target:
        chat_doc["target"] = target

    chat_doc.setdefault("messages", []).append(
        {
            "id": str(uuid.uuid4()),
            "role": role,
            "content": content,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
    )
    _save_chat_doc(chat_doc)


def _build_progress_callback(chat_id: str, target: str):
    """Mirror scan progress updates into the active chat transcript."""
    def callback(role: str, content: str, metadata: Dict[str, Any]) -> None:
        persisted_role = role if role in {"user", "agent"} else "agent"
        _append_chat_message(chat_id, persisted_role, content, metadata=metadata, target=target)

    return callback


def _log_and_store_user_message(chat_id: str, target: str, message: str, memory: Any) -> None:
    """Record an operator message across logs, memory, and chat history."""
    logger.info("[CHAT_USER] %s", message)
    memory.add_message("user", message)
    _append_chat_message(chat_id, "user", message, metadata={"type": "user_message"}, target=target)


def _log_and_store_agent_message(chat_id: str, target: str, message: str, memory: Any) -> None:
    """Record an agent message across logs, memory, and chat history."""
    logger.info("[CHAT_AGENT] %s", message)
    memory.add_message("agent", message, metadata={"type": "agent_message"})
    _append_chat_message(chat_id, "agent", message, metadata={"type": "agent_message"}, target=target)


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

        callback = _build_progress_callback(session_id, target) if session_id else None
        run_autonomous_scan(state, config, logger, memory, state_manager, progress_callback=callback)
        
        if session_id:
            memory.save_session(session_id)

    except Exception as e:
        logger.info(f"[ERROR] Scan failed: {e}")
        if session_id:
            error_text = f"Scan failed for {target}: {e}"
            logger.info("[CHAT_AGENT] %s", error_text)
            _append_chat_message(
                session_id,
                "agent",
                error_text,
                metadata={"type": "scan_status", "status": "failed", "target": target},
                target=target,
            )

os.makedirs("web/static", exist_ok=True)
app.mount("/static", StaticFiles(directory="web/static"), name="static")

@app.get("/")
async def get():
    with open("web/static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.post("/start")
async def start_scan(target: str, chat_id: Optional[str] = None):
    from core.memory import ConversationMemory

    resolved_chat_id = chat_id or str(uuid.uuid4())
    memory = ConversationMemory()
    memory.load_session(resolved_chat_id)

    user_message = f"Make a basic scan on {target} and give me the report."
    response_text = (
        f"I'm starting a basic scan on {target}. "
        "I'll share each step, the commands I run, and the final report in this chat."
    )

    _log_and_store_user_message(resolved_chat_id, target, user_message, memory)
    _log_and_store_agent_message(resolved_chat_id, target, response_text, memory)
    memory.save_session(resolved_chat_id)

    threading.Thread(target=run_scan_in_background, args=(target, resolved_chat_id), daemon=True).start()
    return {"message": response_text, "chat_id": resolved_chat_id}

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
    file_path = _chat_path(chat_id)
    if file_path.exists():
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"error": "Chat not found"}

@app.post("/chat")
def chat_endpoint(data: ChatMessage):
    chat_id = data.chat_id if data.chat_id and _chat_path(data.chat_id).exists() else str(uuid.uuid4())

    config = AppConfig.from_env()
    
    try:
        with open(config.session_file, "r", encoding="utf-8") as f:
            state = json.load(f)
    except Exception:
        state = {"target": data.target}
        
    from core.memory import ConversationMemory
    from agent.interpreter import classify_intent
    from agent.qa_handler import answer_follow_up
    
    memory = ConversationMemory()
    if chat_id:
        memory.load_session(chat_id)

    _log_and_store_user_message(chat_id, data.target, data.message, memory)
    
    intent_res = classify_intent(data.message, memory.get_summary(), memory.get_recent(5), config)
    intent = intent_res.get("intent")
    extracted_target = intent_res.get("extracted_target") or data.target
    
    command = ""
    action = ""
    
    if intent == "new_scan":
        if extracted_target:
            state["target"] = extracted_target
        response_text = (
            f"I'm starting a basic scan on {state.get('target', 'unknown')}. "
            "I'll share progress here, show the commands I run, and post the final report when it's ready."
        )
        action = "start_scan"
    elif intent == "meta":
        response_text = "I think that's a system command. (Note: System commands like /load or /save work better in CLI, via Web I sync automatically)."
    else:
        response_text = answer_follow_up(data.message, memory, config)

    _log_and_store_agent_message(chat_id, extracted_target or data.target, response_text, memory)
    if chat_id:
        memory.save_session(chat_id)
        
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


def _find_available_port(host: str, preferred_port: int, max_attempts: int = 10) -> int:
    """Return the first available port, starting at the preferred one."""
    for port in range(preferred_port, preferred_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError:
                continue
            return port
    raise RuntimeError(
        f"Could not find an available port in range {preferred_port}-{preferred_port + max_attempts - 1}."
    )


if __name__ == "__main__":
    host = os.getenv("WEB_APP_HOST", "0.0.0.0")
    preferred_port = int(os.getenv("WEB_APP_PORT", os.getenv("PORT", "8000")))
    port = _find_available_port(host, preferred_port)
    if port != preferred_port:
        logger.info(
            f"[SYSTEM] Port {preferred_port} is in use, starting web UI on available port {port} instead."
        )
    uvicorn.run(app, host=host, port=port)
