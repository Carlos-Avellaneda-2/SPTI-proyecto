"""Carga de configuración (config/settings.yaml + variables de entorno)."""
from __future__ import annotations

import copy
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SETTINGS = ROOT / "config" / "settings.yaml"


def _load_dotenv(path: Path = ROOT / ".env") -> None:
    """Carga un .env sencillo (CLAVE=valor) sin sobrescribir variables ya definidas."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            if value.strip():
                os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()


@lru_cache(maxsize=1)
def _load_file() -> dict[str, Any]:
    path = Path(os.getenv("SPTI_SETTINGS", DEFAULT_SETTINGS))
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_settings() -> dict[str, Any]:
    """Devuelve una copia de la configuración con overrides de entorno aplicados."""
    cfg = copy.deepcopy(_load_file())
    env_map = {
        "LLM_PROVIDER": ("llm", "provider"),
        "ANTHROPIC_MODEL": ("llm", "anthropic_model"),
        "OPENAI_MODEL": ("llm", "openai_model"),
        "OLLAMA_MODEL": ("llm", "ollama_model"),
        "OLLAMA_URL": ("llm", "ollama_url"),
        "LLM_TIMEOUT_S": ("llm", "timeout_s"),
        "LLM_MAX_TOKENS": ("llm", "max_tokens"),
        "MOCK_LATENCY_MS": ("mock", "latency_ms"),
        "AUDIT_LOG_PATH": ("secure", "audit_log_path"),
    }
    for env, (section, key) in env_map.items():
        value = os.getenv(env)
        if value:
            current = cfg[section].get(key)
            cfg[section][key] = type(current)(value) if isinstance(current, (int, float)) else value
    return cfg
