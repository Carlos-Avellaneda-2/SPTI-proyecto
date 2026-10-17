"""Dashboard comparativo Unsecure vs. Secure (Streamlit).

Ejecutar:  streamlit run dashboard/app.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = ROOT / "results"

# Paleta categórica en orden fijo (slot 1 y 2 de la paleta validada del proyecto)
COLORS = {"Unsecure": "#2a78d6", "Secure": "#eb6834"}
ARCH_LABEL = {"unsecure": "Unsecure", "secure": "Secure"}

st.set_page_config(page_title="SPTI-01 · Evaluación LLM", layout="wide")
st.title("Evaluación automatizada de seguridad de LLM")
st.caption("SPTI-01 · Comparación diferencial de las arquitecturas Unsecure y Secure")


def list_runs() -> list[Path]:
    return sorted((p for p in RESULTS.glob("*/summary.json")), key=lambda p: p.stat().st_mtime, reverse=True)


with st.sidebar:
    st.header("Ejecución")
    reps = st.number_input("Repeticiones por variante", 1, 50, 5)
    provider = st.selectbox("LLM", ["mock", "anthropic", "openai", "ollama"])
    if st.button("Ejecutar nueva evaluación", type="primary"):
        import os

        os.environ["LLM_PROVIDER"] = provider
        from evaluator.runner import run_evaluation
        from evaluator.targets import InProcessTarget

        with st.spinner("Atacando ambas arquitecturas…"):
            run_evaluation([InProcessTarget("unsecure", provider), InProcessTarget("secure", provider)],
                           repetitions=int(reps), provider=provider)
        st.success("Evaluación terminada")

    runs = list_runs()
    if not runs:
        st.info("Aún no hay resultados. Ejecuta una evaluación.")
        st.stop()
    run_path = st.selectbox("Resultado", runs, format_func=lambda p: p.parent.name)

summary = json.loads(run_path.read_text(encoding="utf-8"))
records = pd.read_json(run_path.parent / "results.jsonl", lines=True)
u, s = summary["architectures"]["unsecure"], summary["architectures"]["secure"]
meta = summary["meta"]

if meta["provider"] == "mock":
    st.warning("Resultados con LLM simulado: validan el framework, no el comportamiento de un modelo real.")

# ---------------------------------------------------------------- titulares
c1, c2, c3, c4 = st.columns(4)
c1.metric("Puntaje Unsecure", f"{u['score']:.1f}")
c2.metric("Puntaje Secure", f"{s['score']:.1f}", f"{summary['score_gap']:+.1f} pts")
c3.metric("ASR Secure", f"{s['asr_macro']:.1%}", f"{s['asr_macro'] - u['asr_macro']:+.1%}", delta_color="inverse")
c4.metric("Latencia adicional", f"{s['latency_overhead_ms']:.1f} ms")

verdict = "soportada" if summary["hypothesis_supported"] else "no soportada en todos los criterios"
st.subheader(f"Hipótesis: {verdict}")
checks = pd.DataFrame(summary["checks"])
checks["cumple"] = checks["cumple"].map({True: "✔ Sí", False: "✘ No"})
checks["valor"] = checks["valor"].map(lambda v: f"{v:.3g}")
st.dataframe(checks, hide_index=True, width="stretch")

# ------------------------------------------------------------ ASR por prueba
rows = []
for arch_key, m in (("unsecure", u), ("secure", s)):
    for tid, t in m["per_test"].items():
        rows.append({"Prueba": tid, "Nombre": t["name"], "Arquitectura": ARCH_LABEL[arch_key],
                     "ASR": t["asr"], "IC bajo": t["ci95"][0], "IC alto": t["ci95"][1],
                     "Detección": t["detection_rate"], "n": t["n"]})
per_test = pd.DataFrame(rows)

color = alt.Color("Arquitectura:N", scale=alt.Scale(domain=list(COLORS), range=list(COLORS.values())),
                  legend=alt.Legend(orient="top", title=None))
tooltip = ["Prueba", "Nombre", "Arquitectura", alt.Tooltip("ASR:Q", format=".1%"),
           alt.Tooltip("IC bajo:Q", format=".1%"), alt.Tooltip("IC alto:Q", format=".1%"), "n"]

st.subheader("Tasa de éxito de ataque por prueba")
base = alt.Chart(per_test).encode(
    x=alt.X("Prueba:N", title=None, axis=alt.Axis(labelAngle=0)),
    xOffset=alt.XOffset("Arquitectura:N", sort=list(COLORS)),
)
bars = base.mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=26).encode(
    y=alt.Y("ASR:Q", title="ASR", axis=alt.Axis(format="%", grid=True, gridOpacity=0.3), scale=alt.Scale(domain=[0, 1])),
    color=color, tooltip=tooltip)
errs = base.mark_rule(strokeWidth=2, color="#52514e").encode(y="IC bajo:Q", y2="IC alto:Q", tooltip=tooltip)
st.altair_chart((bars + errs).properties(height=320), width="stretch")
with st.expander("Ver tabla"):
    st.dataframe(per_test, hide_index=True, width="stretch")

# ------------------------------------------------------ componentes del puntaje
st.subheader("Composición del puntaje (0–100)")
comp = pd.DataFrame([{"Arquitectura": ARCH_LABEL[a], "Componente": k, "Puntos": v}
                     for a, m in (("unsecure", u), ("secure", s)) for k, v in m["components"].items()])
comp["Componente"] = comp["Componente"].map({"asr": "1 − ASR", "fnr": "1 − FNR", "fpr": "1 − FPR",
                                              "latency": "Latencia"})
comp_chart = alt.Chart(comp).mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, size=18).encode(
    y=alt.Y("Componente:N", title=None, sort=["1 − ASR", "1 − FNR", "1 − FPR", "Latencia"]),
    yOffset=alt.YOffset("Arquitectura:N", sort=list(COLORS)),
    x=alt.X("Puntos:Q", title="Puntos aportados", axis=alt.Axis(grid=True, gridOpacity=0.3)),
    color=color, tooltip=["Arquitectura", "Componente", alt.Tooltip("Puntos:Q", format=".2f")])
st.altair_chart(comp_chart.properties(height=260), width="stretch")

# ----------------------------------------------------------- otras métricas
st.subheader("Costo de la seguridad")
cost = pd.DataFrame([
    {"Métrica": "Falsos positivos (FPR)", "Unsecure": f"{u['fpr']:.1%}", "Secure": f"{s['fpr']:.1%}"},
    {"Métrica": "Utilidad en tráfico legítimo", "Unsecure": f"{u['utility']:.1%}", "Secure": f"{s['utility']:.1%}"},
    {"Métrica": "Latencia media", "Unsecure": f"{u['latency_mean_ms']} ms", "Secure": f"{s['latency_mean_ms']} ms"},
    {"Métrica": "Latencia p95", "Unsecure": f"{u['latency_p95_ms']} ms", "Secure": f"{s['latency_p95_ms']} ms"},
    {"Métrica": "Falsos negativos (FNR)", "Unsecure": f"{u['fnr']:.1%}", "Secure": f"{s['fnr']:.1%}"},
])
st.dataframe(cost, hide_index=True, width="stretch")

# ------------------------------------------------------------ detalle crudo
st.subheader("Detalle de ejecuciones")
f1, f2, f3 = st.columns(3)
arch_f = f1.multiselect("Arquitectura", ["unsecure", "secure"], ["secure"])
type_f = f2.multiselect("Tipo", ["attack", "benign"], ["attack"])
only_success = f3.checkbox("Solo ataques exitosos")
view = records[records["architecture"].isin(arch_f) & records["type"].isin(type_f)]
if only_success and "success" in view:
    view = view[view["success"] == True]  # noqa: E712
cols = [c for c in ["architecture", "variant_id", "technique", "rep", "success", "detected", "blocked",
                    "utility", "security_events", "evidence", "response_sample"] if c in view.columns]
st.dataframe(view[cols], hide_index=True, width="stretch")
st.caption(f"Ejecución {meta['timestamp']} · LLM {meta['provider']} · {meta['repetitions']} repeticiones · "
           f"semilla {meta['seed']}")
