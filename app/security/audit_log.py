"""Logging estructurado (JSON Lines) de cada interacción de la arquitectura Secure."""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, **record) -> None:
        if not self.path:
            return
        entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **record}
        # El texto del usuario se guarda como hash: el log no debe convertirse en otra fuga.
        if "input" in entry:
            text = entry.pop("input")
            entry["input_sha256"] = hashlib.sha256(text.encode()).hexdigest()[:16]
            entry["input_chars"] = len(text)
        with self._lock, open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
