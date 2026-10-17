"""API HTTP del agente (FastAPI).

Ejecutar:
    ARCHITECTURE=unsecure uvicorn app.server:app --port 8001
    ARCHITECTURE=secure   uvicorn app.server:app --port 8002

Con EXPOSE_EVAL_METADATA=true la respuesta incluye eventos de seguridad y
llamadas a herramientas para que el evaluador pueda medir. Esto SOLO debe
activarse en el laboratorio, nunca en producción.
"""
from __future__ import annotations

import os
import threading

from fastapi import FastAPI, Header, Request
from pydantic import BaseModel, Field

from app.agent import Session, build_agent
from app.config import load_settings
from app.llm.factory import create_llm

ARCHITECTURE = os.getenv("ARCHITECTURE", "secure").lower()
EXPOSE_METADATA = os.getenv("EXPOSE_EVAL_METADATA", "true").lower() == "true"

settings = load_settings()
agent = build_agent(ARCHITECTURE, create_llm(seed=settings["evaluation"]["seed"]), settings)
_sessions: dict[str, Session] = {}
_lock = threading.Lock()

app = FastAPI(title=f"TiendaECI Assistant ({ARCHITECTURE})", version="1.0.0")


class ChatRequest(BaseModel):
    message: str = Field(..., description="Mensaje del usuario")
    session_id: str | None = Field(None, description="Id de sesión para conversaciones multi-turno")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "architecture": ARCHITECTURE, "llm": agent.llm.name}


@app.post("/chat")
def chat(req: ChatRequest, request: Request, x_client_id: str | None = Header(default=None)) -> dict:
    client_id = x_client_id or (request.client.host if request.client else "anon")
    with _lock:
        session = _sessions.get(req.session_id or "")
        if session is None:
            session = Session(client_id=client_id, customer_id=settings["agent"]["session_customer_id"])
            if req.session_id:
                session.session_id = req.session_id
            _sessions[session.session_id] = session
    result = agent.handle(req.message, session)
    body = {"session_id": session.session_id, "response": result.text, "blocked": result.blocked}
    if EXPOSE_METADATA:
        body.update(security_events=result.events, tool_calls=result.tool_calls,
                    latency_ms=result.latency_ms, architecture=ARCHITECTURE)
    return body
