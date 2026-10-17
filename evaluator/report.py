"""Reporte en Markdown, listo para pegar en el informe del proyecto."""
from __future__ import annotations

from pathlib import Path


def _pct(x: float) -> str:
    return f"{100 * x:.1f} %"


def write_markdown_report(summary: dict, path: Path) -> None:
    u, s = summary["architectures"]["unsecure"], summary["architectures"]["secure"]
    meta = summary["meta"]
    lines = [
        "# Reporte de evaluación de seguridad LLM — SPTI-01",
        "",
        f"- Fecha: {meta['timestamp']}",
        f"- Proveedor LLM: `{meta['provider']}`",
        f"- Repeticiones por variante: {meta['repetitions']} · Semilla: {meta['seed']}",
        f"- Variantes por prueba: {meta['variants']} · Prompts legítimos: {meta['benign_prompts']}",
        "",
        "## Puntaje de seguridad compuesto",
        "",
        "| Arquitectura | Puntaje (0–100) | ASR macro | IC 95 % ASR (micro) | FNR | FPR | Utilidad | Latencia media |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for name, m in (("Unsecure", u), ("Secure", s)):
        lines.append(f"| {name} | **{m['score']}** | {_pct(m['asr_macro'])} | "
                     f"{_pct(m['asr_ci95'][0])} – {_pct(m['asr_ci95'][1])} | {_pct(m['fnr'])} | "
                     f"{_pct(m['fpr'])} | {_pct(m['utility'])} | {m['latency_mean_ms']} ms |")
    lines += [
        "",
        f"**Diferencia de puntaje:** {summary['score_gap']} puntos · "
        f"**z-test ASR:** z = {summary['significance']['z']}, p = {summary['significance']['p_value']}",
        "",
        "## ASR por prueba",
        "",
        "| Prueba | OWASP | ASR Unsecure | ASR Secure | Detección Secure | n |",
        "|---|---|---|---|---|---|",
    ]
    for tid, tu in u["per_test"].items():
        ts = s["per_test"].get(tid, {})
        lines.append(f"| {tid} — {tu['name']} | {', '.join(tu['owasp'])} | {_pct(tu['asr'])} | "
                     f"{_pct(ts.get('asr', 0))} | {_pct(ts.get('detection_rate', 0))} | {tu['n']} |")
    lines += ["", "## Verificación de criterios (sección 7)", "",
              "| Criterio | Valor | Umbral | ¿Cumple? |", "|---|---|---|---|"]
    for c in summary["checks"]:
        lines.append(f"| {c['criterio']} | {c['valor']} | {c['umbral']} | {'Sí' if c['cumple'] else 'No'} |")
    lines += ["", f"**Hipótesis soportada:** {'Sí' if summary['hypothesis_supported'] else 'No'}", "",
              "> Si el proveedor es `mock`, estos números validan el funcionamiento del framework, "
              "no el comportamiento de un LLM real. Ver README.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
