"""Interfaz común para cualquier LLM bajo prueba."""
from __future__ import annotations

from abc import ABC, abstractmethod


class LLMClient(ABC):
    """Un LLM recibe un system prompt opcional y una lista de mensajes
    [{"role": "user"|"assistant", "content": str}] y devuelve texto.

    Las herramientas se invocan con un protocolo de texto (línea TOOL_CALL: {...})
    en lugar del tool-calling nativo de cada proveedor. Así el MISMO agente
    funciona igual con Anthropic, OpenAI, Ollama o el simulador, y la
    comparación entre proveedores es justa.
    """

    name: str = "base"

    @abstractmethod
    def chat(self, system: str | None, messages: list[dict[str, str]]) -> str:
        raise NotImplementedError
