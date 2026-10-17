"""Conectores a LLM reales. Se importan de forma perezosa para que el proyecto
funcione sin tener instaladas las librerías de proveedores que no se usan."""
from __future__ import annotations

import os

from app.llm.base import LLMClient


class AnthropicLLM(LLMClient):
    name = "anthropic"

    def __init__(self, model: str, temperature: float, max_tokens: int, timeout_s: float = 60):
        import anthropic  # pip install anthropic ; requiere ANTHROPIC_API_KEY

        self.client = anthropic.Anthropic(timeout=timeout_s)
        self.model, self.temperature, self.max_tokens = model, temperature, max_tokens

    def chat(self, system: str | None, messages: list[dict[str, str]]) -> str:
        kwargs = {"model": self.model, "max_tokens": self.max_tokens,
                  "temperature": self.temperature, "messages": messages}
        if system:
            kwargs["system"] = system
        resp = self.client.messages.create(**kwargs)
        return "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")


class OpenAILLM(LLMClient):
    name = "openai"

    def __init__(self, model: str, temperature: float, max_tokens: int, timeout_s: float = 60):
        import openai  # pip install openai ; requiere OPENAI_API_KEY

        self.client = openai.OpenAI(timeout=timeout_s)
        self.model, self.temperature, self.max_tokens = model, temperature, max_tokens

    def chat(self, system: str | None, messages: list[dict[str, str]]) -> str:
        msgs = ([{"role": "system", "content": system}] if system else []) + messages
        resp = self.client.chat.completions.create(model=self.model, messages=msgs,
                                                   temperature=self.temperature,
                                                   max_tokens=self.max_tokens)
        return resp.choices[0].message.content or ""


class OllamaLLM(LLMClient):
    """Modelo local gratuito vía Ollama (https://ollama.com). Ej.: `ollama pull llama3.1:8b`."""

    name = "ollama"

    def __init__(self, model: str, url: str, temperature: float, max_tokens: int, timeout_s: float = 120):
        import httpx

        self.http = httpx.Client(timeout=timeout_s)
        self.model, self.url = model, os.getenv("OLLAMA_URL", url).rstrip("/")
        self.temperature, self.max_tokens = temperature, max_tokens

    def chat(self, system: str | None, messages: list[dict[str, str]]) -> str:
        msgs = ([{"role": "system", "content": system}] if system else []) + messages
        resp = self.http.post(f"{self.url}/api/chat", json={
            "model": self.model, "messages": msgs, "stream": False,
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        })
        resp.raise_for_status()
        return resp.json()["message"]["content"]
