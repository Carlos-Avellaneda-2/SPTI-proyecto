"""CLI del evaluador.

Ejemplos:
    python -m evaluator                       # evaluación completa con la config por defecto
    python -m evaluator --repetitions 5       # más repeticiones
    python -m evaluator --tests T01 T03       # solo algunas pruebas
    python -m evaluator --provider ollama     # contra un LLM real
    python -m evaluator --target http --unsecure-url http://localhost:8001 --secure-url http://localhost:8002
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from app.config import load_settings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m evaluator",
                                description="Evaluación diferencial de seguridad LLM (Unsecure vs. Secure)")
    p.add_argument("--provider", choices=["mock", "anthropic", "openai", "ollama"],
                   help="LLM bajo prueba (por defecto: settings.yaml / LLM_PROVIDER)")
    p.add_argument("--repetitions", type=int, help="repeticiones por variante")
    p.add_argument("--seed", type=int, help="semilla base")
    p.add_argument("--tests", nargs="+", metavar="TXX", help="ejecutar solo estas pruebas (p. ej. T01 T04)")
    p.add_argument("--target", choices=["inprocess", "http"], default="inprocess")
    p.add_argument("--unsecure-url", default="http://localhost:8001")
    p.add_argument("--secure-url", default="http://localhost:8002")
    p.add_argument("--out", type=Path, help="carpeta de salida (por defecto results/run_<fecha>)")
    args = p.parse_args(argv)

    if args.provider:
        os.environ["LLM_PROVIDER"] = args.provider
    provider = load_settings()["llm"]["provider"]

    from evaluator.runner import run_evaluation
    from evaluator.targets import HttpTarget, InProcessTarget

    from datetime import datetime

    from app.config import ROOT

    out = args.out or ROOT / "results" / datetime.now().strftime("run_%Y%m%d_%H%M%S")
    if args.target == "http":
        # Una solicitud puede encadenar varias llamadas al LLM (herramientas): el cliente
        # debe esperar más que el timeout de una sola llamada del servidor.
        llm_cfg = load_settings()
        http_timeout = max(120, llm_cfg["llm"]["timeout_s"] * (llm_cfg["agent"]["max_tool_steps"] + 1))
        targets = [HttpTarget("unsecure", args.unsecure_url, http_timeout),
                   HttpTarget("secure", args.secure_url, http_timeout)]
    else:
        audit = str(out / "audit_secure.jsonl")  # log estructurado de la arquitectura Secure
        targets = [InProcessTarget("unsecure", provider), InProcessTarget("secure", provider, audit_path=audit)]

    summary, out_dir = run_evaluation(targets, args.repetitions, args.seed, args.tests, out,
                                      provider=provider, progress=lambda m: print(m, flush=True))
    u, s = summary["architectures"]["unsecure"], summary["architectures"]["secure"]
    print("\n================ RESULTADO ================")
    print(f"Unsecure: puntaje {u['score']:6.2f} | ASR {u['asr_macro']:.1%} | FNR {u['fnr']:.1%} | FPR {u['fpr']:.1%}")
    print(f"Secure  : puntaje {s['score']:6.2f} | ASR {s['asr_macro']:.1%} | FNR {s['fnr']:.1%} | FPR {s['fpr']:.1%}")
    print(f"Diferencia: {summary['score_gap']} puntos | latencia extra: {s['latency_overhead_ms']} ms")
    for c in summary["checks"]:
        print(f"  [{'OK' if c['cumple'] else 'NO'}] {c['criterio']}: {c['valor']} ({c['umbral']})")
    print(f"Hipótesis soportada: {'Sí' if summary['hypothesis_supported'] else 'No'}")
    print(f"Resultados en: {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
