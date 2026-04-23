#!/bin/bash
# Inicia backend GHOST v3 (:8000) e, opcionalmente, HexStrike (:8888) quando GHOST_START_HEXSTRIKE=1.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HEX_DIR="$REPO_ROOT/hexstrike-ai"

PORT="${PORT:-8000}"
HEX_PORT="${HEXSTRIKE_PORT:-8888}"

# ── HexStrike (opcional) ─────────────────────────────────────────
start_hexstrike_background() {
  if [ ! -f "$HEX_DIR/hexstrike_server.py" ]; then
    echo "[GHOST] Pasta hexstrike-ai não encontrada — só o GHOST será iniciado."
    return 0
  fi
  if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | grep -q ":${HEX_PORT} "; then
    echo "[GHOST] HexStrike já à escuta na porta ${HEX_PORT}."
    return 0
  fi
  echo "[GHOST] A iniciar HexStrike em http://127.0.0.1:${HEX_PORT} (log: hexstrike-ai/hexstrike.log)..."
  (
    cd "$HEX_DIR"
    if [ -x ./hexstrike-env/bin/python3 ]; then
      nohup ./hexstrike-env/bin/python3 hexstrike_server.py --port "$HEX_PORT" >>hexstrike.log 2>&1 &
    else
      nohup python3 hexstrike_server.py --port "$HEX_PORT" >>hexstrike.log 2>&1 &
    fi
  )
  for _ in $(seq 1 50); do
    if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | grep -q ":${HEX_PORT} "; then
      echo "[GHOST] HexStrike pronto."
      return 0
    fi
    sleep 0.4
  done
  echo "[GHOST] Aviso: HexStrike não respondeu a tempo — vê $HEX_DIR/hexstrike.log (o GHOST continua)."
  return 0
}

if [ "${GHOST_START_HEXSTRIKE:-0}" = "1" ]; then
  set +e
  start_hexstrike_background
  set -e
else
  echo "[GHOST] HexStrike desativado por padrao (define GHOST_START_HEXSTRIKE=1 para iniciar junto)."
fi

# ── GHOST backend ───────────────────────────────────────────────
cd "$SCRIPT_DIR/backend"

# Ollama por defeito em IPv4 literal (evita «localhost» → ::1 sem listener).
if [ -z "${GHOST_OLLAMA_URL:-}" ] && [ -z "${OLLAMA_HOST:-}" ]; then
  export GHOST_OLLAMA_URL="http://127.0.0.1:11434"
fi

if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | grep -q ":${PORT} "; then
  echo "Porta ${PORT} ocupada — a terminar instância anterior (uvicorn main:app)..."
  pkill -f "uvicorn main:app" 2>/dev/null || true
  sleep 1
fi

if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | grep -q ":${PORT} "; then
  echo "ERRO: a porta ${PORT} continua em uso." >&2
  echo "  Ver: ss -tlnp | grep ${PORT}   ou   fuser -v ${PORT}/tcp" >&2
  echo "  Outra porta GHOST:  PORT=8001 $0" >&2
  exit 1
fi

if [ ! -d venv ]; then
  echo "Criando venv e instalando dependências..."
  python3 -m venv venv
  ./venv/bin/pip install -U pip -q
  ./venv/bin/pip install -r requirements.txt -q
fi

echo "[GHOST] API http://0.0.0.0:${PORT}  |  UI http://127.0.0.1:${PORT}/gui/  |  HexStrike bridge → http://127.0.0.1:${HEX_PORT}"
exec ./venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port "$PORT"
