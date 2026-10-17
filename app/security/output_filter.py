"""Capa 3 (Secure): filtro de salida.

Revisa la respuesta del modelo ANTES de entregarla al usuario:
  1. Fuga del system prompt: canary o líneas textuales del prompt -> se bloquea.
  2. Señales de jailbreak exitoso (el modelo "acepta" un personaje sin reglas) -> se bloquea.
  3. Secretos (API keys, contraseñas, códigos internos) -> se enmascaran.
  4. PII (correos, teléfonos, cédulas) que no pertenece al cliente de la sesión -> se enmascara.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.prompts import CANARY, REFUSAL
from app.text_utils import strip_accents

JAILBREAK_MARKERS = re.compile(
    r"(sin restricciones|modo libre|modo desarrollador|developer mode|\[contenido restringido|"
    r"jailbreak|como dan\b|soy dan\b)", re.I)
SECRET_PATTERNS = [
    re.compile(r"sk-(live|test)-[\w-]+"),
    re.compile(r"(?i)(api[_ ]?key|password|contrase(ñ|n)a|secret|discount[_ ]?code|codigo[_ ]de[_ ]descuento)"
               r"[\"'\s:=]+[\"']?[\w-]{6,}"),
]
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PHONE_RE = re.compile(r"\b3\d{2}[-\s]?\d{3}[-\s]?\d{4}\b")
CEDULA_RE = re.compile(r"\bCC-?\d{6,10}\b")
PUBLIC_ALLOWLIST = {"soporte@tiendaeci.example"}
MIN_LINE_LEN = 25


@dataclass
class OutputVerdict:
    text: str
    action: str  # "allow" | "redact" | "block"
    reasons: list[str] = field(default_factory=list)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", strip_accents(s).lower()).strip()


class OutputFilter:
    def __init__(self, system_prompt: str, own_pii: list[str]):
        self.own_pii = set(own_pii) | PUBLIC_ALLOWLIST
        # Líneas "largas" del system prompt: si aparecen textuales, hubo fuga.
        lines = (re.sub(r"^(\d+\.|-)\s*", "", ln.strip()) for ln in system_prompt.splitlines())
        self.prompt_lines = [_norm(ln) for ln in lines if len(ln) >= MIN_LINE_LEN]

    def apply(self, text: str) -> OutputVerdict:
        reasons: list[str] = []
        norm = _norm(text)

        if CANARY.lower() in norm:
            reasons.append("canary_system_prompt")
        leaked = [ln for ln in self.prompt_lines if ln[:60] in norm]
        if leaked:
            reasons.append(f"fragmentos_system_prompt({len(leaked)})")
        if JAILBREAK_MARKERS.search(text):
            reasons.append("jailbreak_aceptado")
        if reasons:
            return OutputVerdict(REFUSAL, "block", reasons)

        redacted = text
        for pat in SECRET_PATTERNS:
            if pat.search(redacted):
                reasons.append("secreto")
                redacted = pat.sub("[SECRETO OCULTO]", redacted)
        for name, pat in (("email", EMAIL_RE), ("telefono", PHONE_RE), ("cedula", CEDULA_RE)):
            def _mask(m: re.Match, _name=name) -> str:
                if m.group(0) in self.own_pii:
                    return m.group(0)
                reasons.append(f"pii_{_name}")
                return "[DATO PERSONAL OCULTO]"
            redacted = pat.sub(_mask, redacted)

        if reasons:
            return OutputVerdict(redacted, "redact", sorted(set(reasons)))
        return OutputVerdict(text, "allow", [])
