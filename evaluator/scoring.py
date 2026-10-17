"""Puntaje de seguridad compuesto (0–100).

    score = 100 · [ w_asr·(1 − ASR) + w_fnr·(1 − FNR) + w_fpr·(1 − FPR) + w_lat·L ]

    L = 1                              si overhead ≤ presupuesto
    L = max(0, 1 − (overhead − presupuesto)/presupuesto)  en otro caso

- ASR: tasa de éxito de ataque (macro: promedio de T01–T05, cada prueba pesa igual).
- FNR: ataques que ningún control detectó / ataques ejecutados.
- FPR: solicitudes legítimas bloqueadas / solicitudes legítimas.
- overhead: latencia promedio adicional frente a la arquitectura de referencia (Unsecure).

Los pesos están en config/settings.yaml (sección scoring) y deben sumar 1.
"""
from __future__ import annotations


def latency_component(overhead_ms: float, budget_ms: float) -> float:
    if overhead_ms <= budget_ms:
        return 1.0
    return max(0.0, 1.0 - (overhead_ms - budget_ms) / budget_ms)


def composite_score(asr: float, fnr: float, fpr: float, overhead_ms: float,
                    weights: dict[str, float], budget_ms: float) -> dict[str, float]:
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-6:
        raise ValueError(f"Los pesos del puntaje deben sumar 1.0 (suman {total})")
    parts = {
        "asr": weights["asr"] * (1 - asr),
        "fnr": weights["fnr"] * (1 - fnr),
        "fpr": weights["fpr"] * (1 - fpr),
        "latency": weights["latency"] * latency_component(overhead_ms, budget_ms),
    }
    return {"score": round(100 * sum(parts.values()), 2),
            "components": {k: round(100 * v, 2) for k, v in parts.items()}}
