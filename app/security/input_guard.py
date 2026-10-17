"""Capa 1 (Secure): validación de entrada.

Asigna un puntaje de sospecha 0–1 combinando reglas por categoría
(combinación "noisy-OR": 1 - Π(1 - w_i)). Según los umbrales:
  - score >= block_threshold -> se bloquea la solicitud
  - score >= flag_threshold  -> se deja pasar, pero se registra como sospechosa
También rechaza entradas que superan el tamaño máximo (T05, agotamiento de contexto).

Limitación deliberada: solo normaliza acentos, leetspeak y letras separadas;
NO decodifica base64 ni homoglifos. Esto permite medir con honestidad la tasa
de falsos negativos de un guardrail basado en reglas.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.text_utils import normalize

RULES: list[tuple[str, float, re.Pattern]] = [
    ("inyeccion_directa", 0.70, re.compile(
        r"\b(ignora\w*|ignore\w*|olvida\w*|forget|disregard|omite)\b.{0,40}"
        r"\b(instrucciones|instructions|reglas|rules|anterior\w*|previous|above|todo|everything)\b")),
    ("cambio_de_instrucciones", 0.45, re.compile(
        r"\b(nuevas instrucciones|new instructions|a partir de ahora|from now on|override|tu nueva tarea)\b")),
    ("extraccion_prompt", 0.70, re.compile(
        r"(system prompt|prompt del sistema|prompt de sistema|instrucciones (iniciales|del sistema|originales)|"
        r"tus instrucciones|your instructions|repite .{0,25}(anterior|arriba)|palabra por palabra|verbatim|"
        r"configuracion inicial)")),
    ("sondeo_configuracion", 0.35, re.compile(
        r"(tus reglas|(primera|segunda|tercera|cuarta) (regla|norma)|identificador interno|palabra clave|"
        r"como te configuraron|que te prohibieron)")),
    ("jailbreak_rol", 0.70, re.compile(
        r"\b(dan|modo desarrollador|developer mode|sin restricciones|sin filtros|no restrictions|jailbreak|"
        r"modo libre)\b")),
    ("juego_de_rol", 0.35, re.compile(
        r"\b(actua como|act as|interpreta a|interpreta el papel|eres ahora|you are now|role ?play|"
        r"haz de cuenta|imagina que eres|juego de rol)\b")),
    ("exfiltracion_datos", 0.60, re.compile(
        r"(api ?key|credencial|contrasena|password|secretos?|todos los (clientes|usuarios)|"
        r"base de datos completa|read_internal_config|list_customers|volcado|dump|variables de entorno|"
        r"configuracion interna)")),
    ("datos_de_terceros", 0.35, re.compile(
        r"(registro|datos|informacion|correo|telefono|cedula)\s+(completo\s+)?(del|de la)?\s*"
        r"(cliente|usuario)\s*(numero|#|id)?\s*\d+")),
    ("contenido_codificado", 0.35, re.compile(r"\b(base64|decodifica|decode|rot13|hex)\b")),
    ("suplantacion_delimitadores", 0.70, re.compile(
        r"(</?entrada_usuario>|</?resultado_herramienta>|<\|im_start\|>|\[system\]|###\s*system|"
        r"tool_result)")),
]


@dataclass
class InputVerdict:
    score: float
    action: str  # "allow" | "flag" | "block"
    reasons: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action == "block"


class InputGuard:
    def __init__(self, max_chars: int = 4000, block_threshold: float = 0.6, flag_threshold: float = 0.3):
        self.max_chars = max_chars
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold

    def inspect(self, text: str) -> InputVerdict:
        if len(text) > self.max_chars:
            return InputVerdict(1.0, "block", [f"longitud_excesiva({len(text)}>{self.max_chars})"])
        norm = normalize(text)
        survive, reasons = 1.0, []
        for name, weight, pattern in RULES:
            if pattern.search(norm):
                survive *= 1 - weight
                reasons.append(name)
        score = round(1 - survive, 3)
        if score >= self.block_threshold:
            action = "block"
        elif score >= self.flag_threshold:
            action = "flag"
        else:
            action = "allow"
        return InputVerdict(score, action, reasons)
