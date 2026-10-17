"""Carga del banco de ataques (YAML)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ATTACKS_DIR = Path(__file__).resolve().parent / "attacks"


@dataclass
class Variant:
    id: str
    technique: str = ""
    kind: str = "single"          # single | multi_turn | burst | long_input
    prompt: str | None = None
    turns: list[str] = field(default_factory=list)
    success_token: str | None = None
    expect_any: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)

    def messages(self) -> list[str]:
        """Mensajes a enviar (para burst y long_input se generan aquí)."""
        if self.kind == "multi_turn":
            return list(self.turns)
        if self.kind == "burst":
            start = int(self.params.get("start", 1))
            n = int(self.params["n_requests"])
            return [self.params["template"].format(i=i) for i in range(start, start + n)]
        if self.kind == "long_input":
            filler, chars = self.params["filler"], int(self.params["chars"])
            body = (filler * (chars // len(filler) + 1))[:chars]
            return [body + "\n" + self.params.get("suffix", "")]
        return [self.prompt or ""]


@dataclass
class AttackTest:
    id: str
    name: str
    judge: str
    owasp: list[str]
    atlas: list[str]
    variants: list[Variant]


_KNOWN = {"id", "technique", "kind", "prompt", "turns", "success_token", "expect_any"}


def _variant(raw: dict) -> Variant:
    kind = raw.get("kind") or ("multi_turn" if raw.get("turns") else "single")
    return Variant(id=raw["id"], technique=raw.get("technique", ""), kind=kind, prompt=raw.get("prompt"),
                   turns=raw.get("turns") or [], success_token=raw.get("success_token"),
                   expect_any=raw.get("expect_any") or [],
                   params={k: v for k, v in raw.items() if k not in _KNOWN})


def load_attacks(directory: Path = ATTACKS_DIR, only: list[str] | None = None) -> list[AttackTest]:
    tests = []
    for path in sorted(directory.glob("T*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if only and data["id"] not in only:
            continue
        tests.append(AttackTest(id=data["id"], name=data["name"], judge=data["judge"],
                                owasp=data.get("owasp", []), atlas=data.get("atlas", []),
                                variants=[_variant(v) for v in data["variants"]]))
    return tests


def load_benign(directory: Path = ATTACKS_DIR) -> list[Variant]:
    data = yaml.safe_load((directory / "benign.yaml").read_text(encoding="utf-8"))
    return [_variant(v) for v in data["variants"]]
