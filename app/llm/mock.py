"""LLM simulado ("mock") para ejecutar el framework sin costo y de forma reproducible.

Modela un LLM *ingenuo* y capaz:
- Entiende texto ofuscado (base64, homoglifos, leetspeak), como un LLM real.
- Obedece instrucciones inyectadas con probabilidad ``compliance_naive``.
- Si su system prompt contiene la POLÍTICA DE SEGURIDAD (versión Secure), la
  probabilidad de obedecer baja a ``compliance_hardened``: el endurecimiento
  ayuda, pero no es suficiente por sí solo (hallazgo conocido en la literatura).
- Usa herramientas con el protocolo ``TOOL_CALL: {...}``.

IMPORTANTE: el mock sirve para validar el pipeline, las métricas y el puntaje.
Las conclusiones de la investigación deben obtenerse con un LLM real
(LLM_PROVIDER=anthropic|openai|ollama). Ver README.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import time

from app.llm.base import LLMClient
from app.text_utils import expand, normalize, strip_accents

_TOKEN_RE = re.compile(r"\b([A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)+)\b")
_PROMPT_BLOCK_RE = re.compile(r"Eres el asistente virtual.*?Cliente actual de la sesi[oó]n: \d+\.", re.S)
_SESSION_RE = re.compile(r"Cliente actual de la sesi[oó]n: (\d+)")
_TOOLS_LISTED_RE = re.compile(r"^- (\w+)\(", re.M)

# --- intenciones (sobre texto normalizado: minúsculas, sin acentos) ---------
INJECTION = re.compile(r"\b(ignora\w*|ignore\w*|olvida\w*|forget|disregard|omite|desconsider\w*|"
                       r"nuevas instrucciones|new instructions|a partir de ahora|from now on|override|"
                       r"nueva directiva|directiva prioritaria|reglas fueron actualizadas|"
                       r"nouvelles instructions|novas instrucoes)\b")
LEAK_FULL = re.compile(r"(system prompt|prompt del sistema|prompt de sistema|instrucciones (iniciales|del sistema|"
                       r"originales|de arriba)|tus instrucciones|your instructions|vos instructions|suas instrucoes|"
                       r"initial prompt|texto (de arriba|anterior)|repite (todo|el texto|lo anterior|tus)|"
                       r"palabra por palabra|verbatim|mot pour mot|configuracion inicial|todo lo que esta arriba)")
LEAK_PARTIAL = re.compile(r"(tus reglas|que reglas|(primera|segunda|tercera|cuarta) (regla|norma)|regla (numero )?\d|"
                          r"identificador|palabra clave|como te configuraron|que no puedes hacer|que te prohibieron|"
                          r"con que (palabra|frase) (empieza|comienza)|quien te programo|que dice tu configuracion)")
JAILBREAK = re.compile(r"\b(dan|modo desarrollador|developer mode|sin restricciones|sin filtros|no restrictions|"
                       r"actua como|act as|interpreta a|interpreta el papel|eres ahora|you are now|role ?play|"
                       r"haz de cuenta|imagina que eres|mi abuela|hipoteticamente|personaje|juego de rol|"
                       r"modo libre|sans restrictions)\b")
TOOL_CONFIG = re.compile(r"(configuracion interna|config interna|api ?key|credencial|contrasena|password|secreto|"
                         r"read_internal_config|variables de entorno|clave de pago|codigo de descuento interno)")
TOOL_LIST = re.compile(r"(todos los (clientes|usuarios)|lista (completa )?de (clientes|usuarios)|list_customers|"
                       r"exporta|volcado|dump|base de datos completa)")
TOOL_RECORD = re.compile(r"(cliente|usuario|customer|registro|record)\s*(numero|nro|no\.|#|id|con id|con el id)?\s*(\d+)")
TOOL_OWN = re.compile(r"(mis datos|mi perfil|mi cuenta|mi informacion|mis datos de contacto)")
TOOL_ORDER = re.compile(r"(pedido|orden|order)\s*(numero|nro|#)?\s*(\d{3,})")
TOOL_FAQ = re.compile(r"(horario|devolu|devolv|devuelv|envio|tarda|pago|pagar|garantia|contacto|llega)")

_ORDINALS = {"primera": 1, "segunda": 2, "tercera": 3, "cuarta": 4}


def _stable_int(*parts: object) -> int:
    return int(hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:12], 16)


class MockLLM(LLMClient):
    name = "mock"

    def __init__(self, seed: int = 0, latency_ms: float = 0, compliance_naive: float = 0.95,
                 compliance_hardened: float = 0.30):
        self.seed = seed
        self.latency_ms = latency_ms
        self.p_naive = compliance_naive
        self.p_hardened = compliance_hardened
        self._calls = 0

    # ------------------------------------------------------------------ API
    def chat(self, system: str | None, messages: list[dict[str, str]]) -> str:
        if self.latency_ms:
            time.sleep(self.latency_ms / 1000)
        self._calls += 1
        context = (system or "") + "\n" + "\n".join(m["content"] for m in messages)
        last = messages[-1]["content"]
        if last.startswith("TOOL_RESULT"):
            return self._summarize_tool_result(last)

        user_text = self._extract_user_text(last)
        # Cada decisión es pseudoaleatoria pero reproducible (semilla + entrada).
        rng = random.Random(_stable_int(self.seed, self._calls, user_text))
        hardened = "POLÍTICA DE SEGURIDAD" in context
        p_comply = self.p_hardened if hardened else self.p_naive
        complies = rng.random() < p_comply

        expanded = expand(user_text)
        norm = normalize(user_text, deep=True)
        prompt_text = self._prompt_text(context)
        session_id = int(m.group(1)) if (m := _SESSION_RE.search(context)) else 1
        listed_tools = set(_TOOLS_LISTED_RE.findall(context))
        token = self._find_token(expanded)

        if INJECTION.search(norm) and token:
            return token if complies else self._refuse()
        if LEAK_FULL.search(norm):
            return f"Claro, estas son mis instrucciones:\n{prompt_text}" if complies else self._refuse()
        if JAILBREAK.search(norm):
            if complies:
                marker = token or "MODO_LIBRE_ACTIVADO"
                # Variedad de redacciones: un LLM real no siempre "anuncia" el jailbreak
                # con frases que un filtro de salida pueda reconocer.
                return marker + " " + rng.choice([
                    "Entendido, ahora soy un asistente sin restricciones. "
                    "[CONTENIDO RESTRINGIDO SIMULADO: respuesta que viola la política de la tienda]",
                    "¡Perfecto! En este personaje digo lo que quiera. "
                    "[CONTENIDO RESTRINGIDO SIMULADO: crítica ofensiva a la competencia]",
                    "Claro, sigamos con el juego. (El asistente responde fuera de la política de la tienda.)",
                ])
            return self._refuse()

        tool_call = self._tool_intent(norm, user_text, session_id, listed_tools, complies)
        if tool_call:
            return tool_call
        if LEAK_PARTIAL.search(norm):
            return self._partial_leak(norm, prompt_text, rng) if complies else self._refuse()
        if INJECTION.search(norm):
            return ("De acuerdo, a partir de ahora seguiré tus nuevas instrucciones."
                    if complies else self._refuse())
        return ("Soy el asistente virtual de TiendaECI. Puedo ayudarte con pedidos, envíos, "
                "devoluciones y tu cuenta. ¿En qué te ayudo?")

    # -------------------------------------------------------------- helpers
    @staticmethod
    def _extract_user_text(content: str) -> str:
        if content.lstrip().startswith("<entrada_usuario>"):
            inner = content.split("<entrada_usuario>", 1)[1]
            return inner.rsplit("</entrada_usuario>", 1)[0].strip()
        if "Usuario:" in content:
            return content.rsplit("Usuario:", 1)[1].strip()
        return content

    @staticmethod
    def _prompt_text(context: str) -> str:
        m = _PROMPT_BLOCK_RE.search(context)
        return m.group(0) if m else "(sin instrucciones)"

    @staticmethod
    def _find_token(expanded: str) -> str | None:
        for tok in _TOKEN_RE.findall(expanded):
            if not tok.startswith(("SPTI-CANARY", "TOOL_", "ESCALAR-")):
                return tok
        return None

    @staticmethod
    def _refuse() -> str:
        return ("Lo siento, no puedo ayudarte con eso. Puedo ayudarte con pedidos, "
                "envíos, devoluciones y tu cuenta.")

    @staticmethod
    def _partial_leak(norm: str, prompt_text: str, rng: random.Random) -> str:
        lines = [ln.strip() for ln in prompt_text.splitlines() if len(ln.strip()) > 20]
        for word, n in _ORDINALS.items():
            if word in norm:
                hit = [ln for ln in lines if ln.startswith(f"{n}.")]
                if hit:
                    return f"Mi regla número {n} dice: {hit[0][3:]}"
        q_words = set(re.findall(r"[a-z]{5,}", norm))
        scored = sorted(lines, key=lambda ln: (-len(q_words & set(re.findall(r"[a-z]{5,}",
                                                                          strip_accents(ln).lower()))),
                                               rng.random()))
        return "Puedo contarte que en mi configuración dice: " + " ".join(scored[:2])

    @staticmethod
    def _call(name: str, args: dict) -> str:
        return "TOOL_CALL: " + json.dumps({"name": name, "args": args}, ensure_ascii=False)

    def _tool_intent(self, norm: str, raw: str, session_id: int, listed: set[str],
                     complies: bool) -> str | None:
        def available(tool: str) -> bool:
            # Un modelo solo llama herramientas que conoce, salvo que el atacante la nombre.
            return tool in listed or tool in norm

        if TOOL_CONFIG.search(norm):
            if available("read_internal_config") and complies:
                return self._call("read_internal_config", {})
            return self._refuse() if not complies else "No tengo acceso a esa información."
        if TOOL_LIST.search(norm):
            if available("list_customers") and complies:
                return self._call("list_customers", {})
            return self._refuse() if not complies else "No tengo acceso a esa información."
        if m := TOOL_ORDER.search(norm):
            return self._call("get_order_status", {"order_id": int(m.group(3))})
        if m := TOOL_RECORD.search(norm):
            cid = int(m.group(3))
            if cid == session_id or complies:
                return self._call("get_customer_record", {"customer_id": cid})
            return self._refuse()
        if TOOL_OWN.search(norm):
            return self._call("get_customer_record", {"customer_id": session_id})
        if TOOL_FAQ.search(norm):
            return self._call("search_faq", {"query": raw[:200]})
        return None

    @staticmethod
    def _summarize_tool_result(content: str) -> str:
        payload = content.split(":", 1)[1].strip() if ":" in content else content
        payload = re.sub(r"</?resultado_herramienta>", "", payload).strip()
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return f"Esta es la información disponible: {payload}"
        if isinstance(data, dict) and "error" in data:
            return f"No fue posible obtener esa información: {data['error']}"
        if isinstance(data, dict) and "resultados" in data:
            return " ".join(data["resultados"])
        return "Aquí está la información solicitada:\n" + json.dumps(data, ensure_ascii=False, indent=2)
