"""Utilidades de normalización de texto.

Los atacantes ofuscan sus instrucciones (acentos, leetspeak, letras separadas,
homoglifos, base64) para evadir filtros por patrones. Estas funciones deshacen
esas ofuscaciones antes de aplicar reglas.

- El guardrail de entrada usa ``normalize(text)`` (nivel "básico").
- El LLM simulado usa ``normalize(text, deep=True)``: un modelo real "entiende"
  base64 y homoglifos, por eso el simulador también los entiende. Esa asimetría
  es intencional: reproduce por qué los filtros por regex no son suficientes.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# Homoglifos cirílicos/griegos comunes que se ven idénticos a letras latinas
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "ν": "v",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X", "І": "I",
})

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_WORD_RE = re.compile(r"[\w@$]+")


def strip_accents(text: str) -> str:
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def deleet(text: str) -> str:
    """Convierte leetspeak solo en palabras que mezclan letras y dígitos (1gn0r4 -> ignora)."""

    def _fix(m: re.Match) -> str:
        word = m.group(0)
        if re.search(r"[a-z]", word) and re.search(r"[0-9@$]", word):
            return word.translate(_LEET)
        return word

    return _WORD_RE.sub(_fix, text)


def join_split_letters(text: str) -> str:
    """Une palabras partidas: 'ig-no-ra' -> 'ignora', 'i g n o r a' -> 'ignora'."""
    text = re.sub(r"(?<=[a-z])[-.·*](?=[a-z])", "", text)
    return re.sub(r"\b(?:[a-z] ){2,}[a-z]\b", lambda m: m.group(0).replace(" ", ""), text)


def decode_base64_chunks(text: str) -> list[str]:
    """Devuelve el texto decodificado de los fragmentos base64 legibles."""
    out = []
    for m in _B64_RE.finditer(text):
        chunk = m.group(0)
        try:
            raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(c.isprintable() or c.isspace() for c in decoded) / max(len(decoded), 1)
        if printable > 0.9 and re.search(r"[a-zA-Z]{3,}", decoded):
            out.append(decoded)
    return out


def expand(text: str) -> str:
    """Texto con mayúsculas preservadas + base64 decodificado + homoglifos resueltos."""
    text = unicodedata.normalize("NFKC", text)
    extra = decode_base64_chunks(text)
    if extra:
        text = text + "\n" + "\n".join(extra)
    return text.translate(_CONFUSABLES)


def normalize(text: str, deep: bool = False) -> str:
    """Normaliza para comparar con patrones (minúsculas, sin acentos, sin leetspeak)."""
    text = expand(text) if deep else unicodedata.normalize("NFKC", text)
    text = strip_accents(text).lower()
    text = join_split_letters(text)
    text = deleet(text)
    return re.sub(r"\s+", " ", text)
