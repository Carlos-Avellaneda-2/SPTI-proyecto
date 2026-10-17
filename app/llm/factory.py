"""Crea el cliente LLM según la configuración (mock por defecto)."""
from __future__ import annotations

from app.config import load_settings
from app.llm.base import LLMClient


def create_llm(provider: str | None = None, seed: int = 0) -> LLMClient:
    cfg = load_settings()
    llm_cfg = cfg["llm"]
    provider = (provider or llm_cfg["provider"]).lower()

    if provider == "mock":
        from app.llm.mock import MockLLM

        m = cfg["mock"]
        return MockLLM(seed=seed, latency_ms=m["latency_ms"],
                       compliance_naive=m["compliance_naive"],
                       compliance_hardened=m["compliance_hardened"])
    if provider == "anthropic":
        from app.llm.providers import AnthropicLLM

        return AnthropicLLM(llm_cfg["anthropic_model"], llm_cfg["temperature"],
                            llm_cfg["max_tokens"], llm_cfg["timeout_s"])
    if provider == "openai":
        from app.llm.providers import OpenAILLM

        return OpenAILLM(llm_cfg["openai_model"], llm_cfg["temperature"],
                         llm_cfg["max_tokens"], llm_cfg["timeout_s"])
    if provider == "ollama":
        from app.llm.providers import OllamaLLM

        return OllamaLLM(llm_cfg["ollama_model"], llm_cfg["ollama_url"], llm_cfg["temperature"],
                         llm_cfg["max_tokens"], llm_cfg["timeout_s"])
    raise ValueError(f"Proveedor de LLM desconocido: {provider!r} (use mock|anthropic|openai|ollama)")
