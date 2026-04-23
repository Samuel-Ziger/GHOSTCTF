#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GHOST_START_SCRIPT="$ROOT_DIR/third_party/ghost-local-v5/ghost-local/start.sh"
GHOST_PORT="${GHOST_PORT:-8000}"
GHOST_HEALTH_URL="${GHOST_HEALTH_URL:-http://127.0.0.1:${GHOST_PORT}/health}"
GHOST_LOG_FILE="$ROOT_DIR/third_party/ghost-local-v5/ghost-local/ghost.log"

log() { printf '[GHOSTCTF STACK] %s\n' "$*"; }
warn() { printf '[GHOSTCTF STACK][WARN] %s\n' "$*" >&2; }

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | grep -q ":${port} "
  else
    return 1
  fi
}

# Lê só GHOST_OLLAMA_URL / OLLAMA_HOST do ficheiro (sem source do .env inteiro).
ghost_export_ollama_from_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  local line k v
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line//$'\r'/}"
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    case "$line" in
      GHOSTCTF_AUTO_OLLAMA_SERVE=*)
        k="${line%%=*}"
        v="${line#*=}"
        k="${k//[[:space:]]/}"
        v="${v#\"}"; v="${v%\"}"
        v="${v#\'}"; v="${v%\'}"
        export "$k=$v"
        ;;
      GHOST_OLLAMA_URL=*|OLLAMA_HOST=*)
        k="${line%%=*}"
        v="${line#*=}"
        k="${k//[[:space:]]/}"
        v="${v#\"}"; v="${v%\"}"
        v="${v#\'}"; v="${v%\'}"
        v="${v//http:\/\/localhost:/http:\/\/127.0.0.1:}"
        v="${v//https:\/\/localhost:/https:\/\/127.0.0.1:}"
        v="${v//http:\/\/localhost\//http:\/\/127.0.0.1/}"
        v="${v//https:\/\/localhost\//https:\/\/127.0.0.1/}"
        case "$v" in
          http://localhost|https://localhost) v="${v/localhost/127.0.0.1}" ;;
        esac
        case "$k" in
          OLLAMA_HOST) v="${v//localhost:/127.0.0.1:}" ;;
        esac
        export "$k=$v"
        ;;
    esac
  done <"$f"
}

ghost_export_ollama_from_envfile() {
  ghost_export_ollama_from_file "$ROOT_DIR/.env"
  # Mesmo .env do GHOSTRECON (muitos utilizadores só o preencheram lá).
  if [ -z "${GHOST_OLLAMA_URL:-}" ] && [ -z "${OLLAMA_HOST:-}" ]; then
    ghost_export_ollama_from_file "$ROOT_DIR/GHOSTRECON/.env"
  fi
  # Garantir URL explícita em IPv4 para o subprocesso Python (evita só «localhost» no ambiente).
  if [ -z "${GHOST_OLLAMA_URL:-}" ] && [ -z "${OLLAMA_HOST:-}" ]; then
    export GHOST_OLLAMA_URL="http://127.0.0.1:11434"
  fi
}

# URL /api/tags para testar se o Ollama está a escutar (mesma lógica que o backend GHOST).
ollama_tags_probe_url() {
  local b="${GHOST_OLLAMA_URL:-}"
  if [ -z "$b" ] && [ -n "${OLLAMA_HOST:-}" ]; then
    case "$OLLAMA_HOST" in
      http://*|https://*) b="$OLLAMA_HOST" ;;
      *) b="http://${OLLAMA_HOST}" ;;
    esac
  fi
  [ -n "$b" ] || b="http://127.0.0.1:11434"
  b="${b%/}"
  printf '%s' "${b}/api/tags"
}

ollama_api_reachable() {
  local url
  url="$(ollama_tags_probe_url)"
  command -v curl >/dev/null 2>&1 || return 1
  curl -fsS --connect-timeout 2 --max-time 4 "$url" >/dev/null 2>&1
}

# True se GHOST_OLLAMA_URL / OLLAMA_HOST apontam para esta máquina (não arrancamos ollama serve para hosts remotos).
ollama_configured_host_is_local() {
  local b="${GHOST_OLLAMA_URL:-}"
  if [ -z "$b" ] && [ -n "${OLLAMA_HOST:-}" ]; then
    case "$OLLAMA_HOST" in
      http://*|https://*) b="$OLLAMA_HOST" ;;
      *) b="http://${OLLAMA_HOST}" ;;
    esac
  fi
  [ -z "$b" ] && return 0
  case "$b" in
    *127.0.0.1*|*localhost*|*"[::1]"*) return 0 ;;
    *) return 1 ;;
  esac
}

# Por defeito: tentar ollama serve em background se o alvo for local (127.0.0.1 / localhost).
# GHOSTCTF_AUTO_OLLAMA_SERVE=0 desactiva explicitamente (=1 com URL local equivale ao mesmo que omitir).
should_auto_ollama_serve() {
  case "${GHOSTCTF_AUTO_OLLAMA_SERVE:-}" in
    0|false|no|NO) return 1 ;;
  esac
  ollama_configured_host_is_local
}

# Garante API Ollama antes do Ghost: aviso; por defeito arranca ollama serve se URL local (opt-out: GHOSTCTF_AUTO_OLLAMA_SERVE=0).
ensure_ollama_for_ghost() {
  ghost_export_ollama_from_envfile
  if ollama_api_reachable; then
    log "Ollama OK ($(ollama_tags_probe_url | sed 's,/api/tags$,,'))"
    return 0
  fi
  warn "Ollama não responde em $(ollama_tags_probe_url) — o chat Ghost Intelligence vai falhar até o Ollama estar activo."
  warn "  → Terminal:   ollama serve"
  warn "  → Ou modelo:  ollama pull mistral:7b   (ou outro)"
  if command -v systemctl >/dev/null 2>&1 && systemctl cat ollama.service >/dev/null 2>&1; then
    warn "  → Serviço systemd:  sudo systemctl start ollama    (estado: systemctl status ollama)"
  fi
  if should_auto_ollama_serve && command -v ollama >/dev/null 2>&1; then
    local olog="$ROOT_DIR/third_party/ghost-local-v5/ollama-serve.log"
    log "A tentar \`ollama serve\` em background (log: $olog). Para desactivar: GHOSTCTF_AUTO_OLLAMA_SERVE=0 no .env"
    mkdir -p "$(dirname "$olog")"
    ( nohup ollama serve >>"$olog" 2>&1 & )
    local i
    for i in $(seq 1 25); do
      if ollama_api_reachable; then
        log "Ollama passou a responder após ollama serve."
        return 0
      fi
      sleep 0.6
    done
    warn "ollama serve não ficou pronto a tempo — ver $olog"
  elif should_auto_ollama_serve && ! command -v ollama >/dev/null 2>&1; then
    warn "Comando \`ollama\` não encontrado no PATH — não é possível arrancar o serviço localmente."
  fi
}

start_ghost_if_needed() {
  if [ ! -f "$GHOST_START_SCRIPT" ]; then
    warn "Ghost Intelligence não encontrado em $GHOST_START_SCRIPT — a continuar só com a API Node."
    return 0
  fi

  if port_in_use "$GHOST_PORT"; then
    log "Ghost Intelligence (GHOST v3) já à escuta na porta ${GHOST_PORT}"
    return 0
  fi

  log "A iniciar Ghost Intelligence (Ollama + FastAPI) na porta ${GHOST_PORT}…"
  ensure_ollama_for_ghost
  mkdir -p "$(dirname "$GHOST_LOG_FILE")"
  (
    cd "$ROOT_DIR/third_party/ghost-local-v5/ghost-local"
    GHOST_START_HEXSTRIKE="${GHOST_START_HEXSTRIKE:-0}" PORT="$GHOST_PORT" \
      nohup bash "$GHOST_START_SCRIPT" >>"$GHOST_LOG_FILE" 2>&1 &
  )

  for _ in $(seq 1 25); do
    if curl -fsS "$GHOST_HEALTH_URL" >/dev/null 2>&1; then
      log "Ghost Intelligence online em $GHOST_HEALTH_URL (UI: http://127.0.0.1:${GHOST_PORT}/gui/)"
      return 0
    fi
    sleep 1
  done
  warn "Ghost Intelligence não respondeu a tempo — ver $GHOST_LOG_FILE (API Node arranca na mesma)."
}

start_ghost_if_needed
log "A iniciar API GHOSTCTF (Node)…"
exec node "$ROOT_DIR/server/index.js"
