#!/usr/bin/env bash
# Arranca Ollama y las dos APIs (Unsecure :8001, Secure :8002).
# Uso (Git Bash en Windows, o Linux/Mac):  ./start.sh
# Ctrl+C detiene todo lo que este script arrancó. Si Ollama ya estaba
# corriendo antes, lo deja como estaba.
set -u

cd "$(dirname "$0")"
ROOT="$(pwd)"
LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR"

OLLAMA_PORT=11434
UNSECURE_PORT=8001
SECURE_PORT=8002

# --- localizar ejecutables -------------------------------------------------
if [ -x .venv/Scripts/python.exe ]; then PY=.venv/Scripts/python.exe
elif [ -x .venv/bin/python ]; then PY=.venv/bin/python
else
    echo "No existe .venv. Créalo primero:"
    echo "  python -m venv .venv && .venv/Scripts/python -m pip install -r requirements.txt"
    exit 1
fi

if command -v ollama >/dev/null 2>&1; then OLLAMA=ollama
elif [ -x "/f/Ollama/app/ollama.exe" ]; then OLLAMA="/f/Ollama/app/ollama.exe"
else OLLAMA=""
fi

# Modelos en F: (evita llenar C:). Se fija explícitamente porque en este PC hay
# una variable de sistema OLLAMA_MODELS=F:\Ollama_Models que apunta a una carpeta vacía.
if [ -d "/f/Ollama/models" ]; then
    export OLLAMA_MODELS='F:\Ollama\models'
fi

PIDS=()

stop_tree() {  # mata el proceso y sus hijos (en Windows el python del venv lanza otro python)
    local pid=$1
    if [ -r "/proc/$pid/winpid" ] && command -v taskkill >/dev/null 2>&1; then
        taskkill //F //T //PID "$(cat "/proc/$pid/winpid")" >/dev/null 2>&1
    else
        pkill -TERM -P "$pid" 2>/dev/null
        kill "$pid" 2>/dev/null
    fi
}

cleanup() {
    echo
    echo "Deteniendo servicios..."
    for pid in "${PIDS[@]}"; do
        stop_tree "$pid"
    done
    echo "Listo."
}
trap cleanup EXIT
trap 'exit 130' INT TERM

wait_for() {  # wait_for <url> <nombre> <segundos>
    local url=$1 name=$2 secs=$3
    for _ in $(seq 1 "$secs"); do
        curl -s -o /dev/null "$url" && { echo "  [OK] $name"; return 0; }
        sleep 1
    done
    echo "  [ERROR] $name no respondió en ${secs}s ($url)"
    return 1
}

port_busy() { curl -s -o /dev/null "http://localhost:$1/" 2>/dev/null; }

# --- 1. Ollama --------------------------------------------------------------
echo "== Ollama"
if port_busy "$OLLAMA_PORT"; then
    echo "  [OK] ya estaba corriendo en :$OLLAMA_PORT (no se detendrá al salir)"
else
    if [ -z "$OLLAMA" ]; then
        echo "  [ERROR] no se encontró ollama. Instálalo o agrégalo al PATH."
        exit 1
    fi
    "$OLLAMA" serve > "$LOG_DIR/ollama.log" 2>&1 &
    PIDS+=($!)
    wait_for "http://localhost:$OLLAMA_PORT/api/version" "Ollama :$OLLAMA_PORT" 30 || exit 1
fi

MODEL=$(grep -E '^OLLAMA_MODEL=' .env 2>/dev/null | cut -d= -f2 | tr -d '\r')
MODEL=${MODEL:-llama3.2}
if curl -s "http://localhost:$OLLAMA_PORT/api/tags" | grep -q "\"$MODEL"; then
    echo "  [OK] modelo $MODEL disponible"
else
    echo "  [AVISO] el modelo $MODEL no está descargado. Ejecuta: ollama pull $MODEL"
fi

# --- 2. APIs ----------------------------------------------------------------
echo "== APIs"
for port in "$UNSECURE_PORT" "$SECURE_PORT"; do
    if port_busy "$port"; then
        echo "  [ERROR] el puerto $port ya está en uso. Cierra lo que lo ocupa y vuelve a intentar."
        exit 1
    fi
done

ARCHITECTURE=unsecure PYTHONIOENCODING=utf-8 "$PY" -m uvicorn app.server:app --port "$UNSECURE_PORT" \
    > "$LOG_DIR/api_unsecure.log" 2>&1 &
PIDS+=($!)
ARCHITECTURE=secure PYTHONIOENCODING=utf-8 "$PY" -m uvicorn app.server:app --port "$SECURE_PORT" \
    > "$LOG_DIR/api_secure.log" 2>&1 &
PIDS+=($!)

wait_for "http://localhost:$UNSECURE_PORT/health" "Unsecure :$UNSECURE_PORT" 30 || exit 1
wait_for "http://localhost:$SECURE_PORT/health" "Secure   :$SECURE_PORT" 30 || exit 1

cat <<EOF

Servicios arriba:
  Unsecure  http://localhost:$UNSECURE_PORT   (docs: /docs)
  Secure    http://localhost:$SECURE_PORT   (docs: /docs)
  Ollama    http://localhost:$OLLAMA_PORT
Logs en logs/ (ollama.log, api_unsecure.log, api_secure.log)

Ctrl+C para detener todo.
EOF

# Bucle en vez de `wait`: en Git Bash `wait` puede no atender Ctrl+C a tiempo.
while true; do
    for pid in "${PIDS[@]}"; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "  [ERROR] un servicio se detuvo inesperadamente; revisa logs/."
            exit 1
        fi
    done
    sleep 1
done
