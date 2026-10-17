"""Objetivos de evaluación: la misma interfaz para el agente en proceso o vía HTTP.

- InProcessTarget: instancia el agente directamente (rápido y 100 % reproducible).
- HttpTarget: ataca la API FastAPI desplegada (p. ej. con docker compose).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.agent import Session, build_agent
from app.config import load_settings
from app.llm.factory import create_llm


@dataclass
class Reply:
    text: str
    blocked: bool
    events: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0


class Conversation(Protocol):
    def send(self, message: str) -> Reply: ...


class Target(Protocol):
    architecture: str

    def conversation(self, seed: int) -> Conversation: ...


class _InProcessConversation:
    def __init__(self, agent, customer_id: int):
        self.agent = agent
        self.session = Session(client_id=f"eval-{uuid.uuid4().hex[:8]}", customer_id=customer_id)

    def send(self, message: str) -> Reply:
        r = self.agent.handle(message, self.session)
        return Reply(r.text, r.blocked, r.events, r.tool_calls, r.latency_ms)


class InProcessTarget:
    """Crea un agente nuevo por conversación: mismas condiciones para cada prueba."""

    def __init__(self, architecture: str, provider: str | None = None, audit_path: str | None = None):
        self.architecture = architecture
        self.provider = provider
        self.settings = load_settings()
        self.audit_path = audit_path

    def conversation(self, seed: int) -> Conversation:
        llm = create_llm(self.provider, seed=seed)
        kwargs = {"audit_path": self.audit_path} if self.architecture == "secure" else {}
        agent = build_agent(self.architecture, llm, self.settings, **kwargs)
        return _InProcessConversation(agent, self.settings["agent"]["session_customer_id"])


class _HttpConversation:
    def __init__(self, client, url: str):
        self.client, self.url = client, url
        self.session_id = uuid.uuid4().hex[:12]
        self.client_id = f"eval-{uuid.uuid4().hex[:8]}"

    def send(self, message: str) -> Reply:
        t0 = time.perf_counter()
        r = self.client.post(f"{self.url}/chat", json={"message": message, "session_id": self.session_id},
                             headers={"X-Client-Id": self.client_id})
        r.raise_for_status()
        body = r.json()
        latency = body.get("latency_ms", (time.perf_counter() - t0) * 1000)
        return Reply(body["response"], body.get("blocked", False), body.get("security_events", []),
                     body.get("tool_calls", []), latency)


class HttpTarget:
    def __init__(self, architecture: str, url: str, timeout_s: float = 120):
        import httpx

        self.architecture = architecture
        self.url = url.rstrip("/")
        self.client = httpx.Client(timeout=timeout_s)

    def conversation(self, seed: int) -> Conversation:  # la semilla la controla el servidor
        return _HttpConversation(self.client, self.url)
