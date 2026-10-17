"""Las dos arquitecturas bajo prueba.

UnsecureAgent (sección 4 de la propuesta)
  - Input sin sanitizar directo al LLM.
  - System prompt mezclado con el mensaje del usuario en un solo canal.
  - Acceso a TODAS las herramientas (incluidas las administrativas), sin permisos.
  - Sin filtro de salida, sin rate limiting, sin logging.

SecureAgent (sección 5 de la propuesta) — mismo LLM, mismas herramientas, mismas reglas, más:
  [1] Validación de entrada       -> app/security/input_guard.py
  [2] System prompt separado y endurecido, entrada delimitada -> app/prompts.py
  [3] Filtro de salida            -> app/security/output_filter.py
  [4] Allowlist + mínimo privilegio en herramientas -> app/security/tool_policy.py
  [5] Rate limiting + logging JSON -> app/security/rate_limiter.py, audit_log.py
"""
from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from app import prompts
from app.config import load_settings
from app.llm.base import LLMClient
from app.security import AuditLogger, InputGuard, OutputFilter, TokenBucketLimiter, ToolPolicy
from app.tools import ToolRegistry, to_json

_TOOL_CALL_RE = re.compile(r"TOOL_CALL:\s*(\{.*\})", re.S)


@dataclass
class Session:
    client_id: str
    customer_id: int = 1
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    history: list[dict[str, str]] = field(default_factory=list)


@dataclass
class AgentResponse:
    text: str
    blocked: bool = False
    events: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0
    llm_calls: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_tool_call(text: str) -> tuple[str, dict] | None:
    m = _TOOL_CALL_RE.search(text or "")
    if not m:
        return None
    try:
        data = json.loads(m.group(1))
        return str(data["name"]), dict(data.get("args") or {})
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None


class BaseAgent:
    architecture = "base"

    def __init__(self, llm: LLMClient, settings: dict | None = None):
        self.llm = llm
        self.settings = settings or load_settings()
        self.registry = ToolRegistry()
        self.max_steps = self.settings["agent"]["max_tool_steps"]

    def handle(self, message: str, session: Session) -> AgentResponse:
        raise NotImplementedError


class UnsecureAgent(BaseAgent):
    architecture = "unsecure"

    def handle(self, message: str, session: Session) -> AgentResponse:
        t0 = time.perf_counter()
        resp = AgentResponse(text="")
        system_prompt = prompts.build_unsecure_prompt(self.registry.describe(), session.customer_id)

        # Sin separación de canales: instrucciones del sistema + usuario en el mismo mensaje.
        content = f"{system_prompt}\n\nUsuario: {message}" if not session.history else f"Usuario: {message}"
        convo = session.history + [{"role": "user", "content": content}]

        text = ""
        for _ in range(self.max_steps + 1):
            text = self.llm.chat(None, convo)
            resp.llm_calls += 1
            call = parse_tool_call(text)
            if not call:
                break
            name, args = call
            result = self.registry.execute(name, args)  # sin ningún control de acceso
            resp.tool_calls.append({"name": name, "args": args, "allowed": True, "executed": True})
            convo += [{"role": "assistant", "content": text},
                      {"role": "user", "content": f"TOOL_RESULT ({name}): {to_json(result)}"}]

        resp.text = text
        session.history += [{"role": "user", "content": content}, {"role": "assistant", "content": text}]
        resp.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        return resp


class SecureAgent(BaseAgent):
    architecture = "secure"

    def __init__(self, llm: LLMClient, settings: dict | None = None, audit_path: str | None = None,
                 limiter: TokenBucketLimiter | None = None):
        super().__init__(llm, settings)
        sec = self.settings["secure"]
        self.guard = InputGuard(**sec["input"])
        self.limiter = limiter or TokenBucketLimiter(**sec["rate_limit"])
        self.policy = ToolPolicy(self.registry, **sec["tools"])
        self.allowed_tools = list(sec["tools"]["allowlist"])
        self.audit = AuditLogger(audit_path if audit_path is not None else sec.get("audit_log_path"))

    def handle(self, message: str, session: Session) -> AgentResponse:
        t0 = time.perf_counter()
        resp = AgentResponse(text="")

        def finish() -> AgentResponse:
            resp.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
            self.audit.log(architecture="secure", session_id=session.session_id, client_id=session.client_id,
                           input=message, blocked=resp.blocked, events=resp.events,
                           tool_calls=resp.tool_calls, latency_ms=resp.latency_ms)
            return resp

        # [5] Rate limiting
        if not self.limiter.allow(session.client_id):
            resp.text, resp.blocked = prompts.RATE_LIMITED, True
            resp.events.append({"layer": "rate_limiter", "type": "rate_limited"})
            return finish()

        # [1] Validación de entrada
        verdict = self.guard.inspect(message)
        if verdict.action != "allow":
            resp.events.append({"layer": "input_guard", "type": f"input_{verdict.action}",
                                "score": verdict.score, "reasons": verdict.reasons})
        if verdict.blocked:
            resp.text, resp.blocked = prompts.BLOCKED_INPUT, True
            return finish()

        # [2] System prompt endurecido y separado; la entrada va delimitada
        system_prompt = prompts.build_secure_prompt(self.registry.describe(self.allowed_tools),
                                                    session.customer_id)
        safe_msg = re.sub(r"</?entrada_usuario>", "", message)
        user_turn = {"role": "user", "content": f"<entrada_usuario>\n{safe_msg}\n</entrada_usuario>"}
        convo = session.history + [user_turn]

        text = ""
        for _ in range(self.max_steps + 1):
            text = self.llm.chat(system_prompt, convo)
            resp.llm_calls += 1
            call = parse_tool_call(text)
            if not call:
                break
            name, args = call
            # [4] Allowlist + mínimo privilegio
            decision = self.policy.check(name, args, session.customer_id)
            if decision.allowed:
                result = self.registry.execute(name, args)
            else:
                result = {"error": "Acceso denegado por la política de herramientas."}
                resp.events.append({"layer": "tool_policy", "type": "tool_denied", "tool": name,
                                    "reason": decision.reason})
            resp.tool_calls.append({"name": name, "args": args, "allowed": decision.allowed,
                                    "executed": decision.allowed})
            convo += [{"role": "assistant", "content": text},
                      {"role": "user", "content": f"TOOL_RESULT ({name}): <resultado_herramienta>"
                                                  f"{to_json(result)}</resultado_herramienta>"}]

        # [3] Filtro de salida
        out = OutputFilter(system_prompt, self.registry.customer_pii(session.customer_id)).apply(text)
        if out.action != "allow":
            resp.events.append({"layer": "output_filter", "type": f"output_{out.action}",
                                "reasons": out.reasons})
        resp.text = out.text
        resp.blocked = out.action == "block"
        session.history += [user_turn, {"role": "assistant", "content": resp.text}]
        return finish()


def build_agent(architecture: str, llm: LLMClient, settings: dict | None = None, **kwargs) -> BaseAgent:
    architecture = architecture.lower()
    if architecture == "unsecure":
        return UnsecureAgent(llm, settings)
    if architecture == "secure":
        return SecureAgent(llm, settings, **kwargs)
    raise ValueError(f"Arquitectura desconocida: {architecture!r}")
