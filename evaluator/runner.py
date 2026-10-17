"""Orquestador: ejecuta el MISMO banco de ataques y el MISMO tráfico legítimo
contra ambas arquitecturas, con las mismas semillas, y guarda los resultados."""
from __future__ import annotations

import hashlib
import json
import platform
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from app.config import ROOT, load_settings
from evaluator.judges import benign_utility, judge
from evaluator.loader import AttackTest, Variant, load_attacks, load_benign
from evaluator.metrics import compute_summary
from evaluator.report import write_markdown_report
from evaluator.targets import Reply, Target


def trial_seed(base_seed: int, variant_id: str, rep: int) -> int:
    """Semilla idéntica para ambas arquitecturas -> condiciones idénticas."""
    return int(hashlib.sha256(f"{base_seed}|{variant_id}|{rep}".encode()).hexdigest()[:8], 16)


def _run_attack(target: Target, test: AttackTest, variant: Variant, rep: int, seed: int,
                cfg: dict) -> dict[str, Any]:
    conv = target.conversation(seed)
    replies: list[Reply] = [conv.send(msg) for msg in variant.messages()]
    verdict = judge(test.judge, variant, replies, cfg)
    return {
        "type": "attack", "architecture": target.architecture, "test_id": test.id, "test_name": test.name,
        "owasp": test.owasp, "variant_id": variant.id, "technique": variant.technique, "kind": variant.kind,
        "rep": rep, "seed": seed, "success": verdict.success, "detected": verdict.detected,
        "blocked": any(r.blocked for r in replies), "requests": len(replies),
        "latency_ms": round(sum(r.latency_ms for r in replies) / len(replies), 3),
        "evidence": verdict.evidence, **verdict.extra,
        "security_events": sorted({e.get("type", "") for r in replies for e in r.events}),
        "response_sample": replies[-1].text[:300],
    }


def _run_benign(target: Target, variant: Variant, rep: int, seed: int) -> dict[str, Any]:
    reply = target.conversation(seed).send(variant.messages()[0])
    return {
        "type": "benign", "architecture": target.architecture, "test_id": "BENIGN", "variant_id": variant.id,
        "rep": rep, "seed": seed, "blocked": reply.blocked, "utility": benign_utility(variant, reply),
        "flagged": bool(reply.events), "latency_ms": reply.latency_ms,
        "security_events": sorted({e.get("type", "") for e in reply.events}),
        "response_sample": reply.text[:300],
    }


def run_evaluation(targets: list[Target], repetitions: int | None = None, seed: int | None = None,
                   only_tests: list[str] | None = None, out_dir: Path | None = None,
                   provider: str = "mock",
                   progress: Callable[[str], None] | None = None) -> tuple[dict, Path]:
    cfg = load_settings()
    repetitions = repetitions or cfg["evaluation"]["repetitions"]
    seed = cfg["evaluation"]["seed"] if seed is None else seed
    tests, benign = load_attacks(only=only_tests), load_benign()
    say = progress or (lambda _m: None)

    records: list[dict[str, Any]] = []
    for target in targets:
        say(f"[{target.architecture}] ejecutando {sum(len(t.variants) for t in tests)} variantes x {repetitions}")
        for test in tests:
            for variant in test.variants:
                for rep in range(repetitions):
                    records.append(_run_attack(target, test, variant, rep,
                                               trial_seed(seed, variant.id, rep), cfg))
        for variant in benign:
            for rep in range(repetitions):
                records.append(_run_benign(target, variant, rep, trial_seed(seed, variant.id, rep)))

    summary = compute_summary(records, cfg)
    summary["meta"] = {
        "timestamp": datetime.now().isoformat(timespec="seconds"), "provider": provider,
        "repetitions": repetitions, "seed": seed, "tests": [t.id for t in tests],
        "variants": {t.id: len(t.variants) for t in tests}, "benign_prompts": len(benign),
        "python": platform.python_version(), "weights": cfg["scoring"]["weights"],
    }

    out_dir = out_dir or ROOT / "results" / datetime.now().strftime("run_%Y%m%d_%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "results.jsonl", "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    write_markdown_report(summary, out_dir / "report.md")
    return summary, out_dir
