#!/bin/bash
set -Eeuo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; RED='\033[0;31m'; NC='\033[0m'
echo -e "${GREEN}  ◈ GHOST v3 — IA Local + GHOSTRECON ◈${NC}\n"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODELS=(
  "deepseek-coder-v2:16b"
  "qwen2.5-coder:7b"
  "codellama:13b"
  "mistral:7b"
  "llama3.3:70b"
  "llama3.1:8b"
  "gemma4:31b"
  "qwen3.5:9b"
  "qwen3.5:32b"
  "deepseek-r1:latest"
)

DEPS_ONLY=0
SKIP_OLLAMA=0
SKIP_MODELS=0
SKIP_START=0

usage() {
  cat <<'EOF'
Uso:
  ./setup.sh [opcoes]

Opcoes:
  --deps-only      Instala apenas venv + dependencias Python do backend
  --skip-ollama    Nao instala/inicia Ollama
  --skip-models    Nao puxa nomic-embed-text nem modelos
  --skip-start     Nao inicia o backend uvicorn no final
  -h, --help       Mostra esta ajuda
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --deps-only) DEPS_ONLY=1 ;;
    --skip-ollama) SKIP_OLLAMA=1 ;;
    --skip-models) SKIP_MODELS=1 ;;
    --skip-start) SKIP_START=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo -e "${RED}Opcao invalida: $1${NC}" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

parse_model_choices() {
  local input="$1"
  local -n out_arr=$2
  local clean="${input// /}"
  IFS=',' read -ra idxs <<< "$clean"
  local seen=","
  for idx in "${idxs[@]}"; do
    [[ -z "$idx" ]] && continue
    if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 && idx <= ${#MODELS[@]} )); then
      local model="${MODELS[$((idx-1))]}"
      if [[ "$seen" != *",$model,"* ]]; then
        out_arr+=("$model")
        seen+="$model,"
      fi
    else
      echo -e "${YELLOW}Indice invalido ignorado: ${idx}${NC}"
    fi
  done
}

ensure_python_venv() {
  echo -e "${CYAN}[PY] Dependencias Python...${NC}"
  cd "$SCRIPT_DIR/backend"
  if [ ! -d venv ]; then python3 -m venv venv; fi
  ./venv/bin/pip install -U pip -q
  ./venv/bin/pip install -r requirements.txt -q
  echo -e "${GREEN}✓ Dependencias Python OK${NC}"
}

ensure_ollama_ready() {
  if [ "$SKIP_OLLAMA" -eq 1 ]; then
    echo -e "${YELLOW}~ Ollama ignorado (--skip-ollama)${NC}"
    return
  fi
  echo -e "${CYAN}[1/5] Ollama...${NC}"
  if ! command -v ollama >/dev/null 2>&1; then
    curl -fsSL https://ollama.com/install.sh | sh
  fi
  if ! pgrep -x "ollama" >/dev/null; then
    ollama serve >/dev/null 2>&1 &
    sleep 3
  fi
  echo -e "${GREEN}✓ Ollama OK${NC}"
}

pull_models_if_enabled() {
  if [ "$SKIP_MODELS" -eq 1 ]; then
    echo -e "${YELLOW}~ Pull de modelos ignorado (--skip-models)${NC}"
    PRIMARY_MODEL="${GHOST_PRIMARY_MODEL:-ghost}"
    return
  fi
  if [ "$SKIP_OLLAMA" -eq 1 ]; then
    echo -e "${YELLOW}~ Sem Ollama ativo, sem pull de modelos${NC}"
    PRIMARY_MODEL="${GHOST_PRIMARY_MODEL:-ghost}"
    return
  fi

  echo -e "${CYAN}[2/5] nomic-embed-text (embeddings locais)...${NC}"
  ollama pull nomic-embed-text && echo -e "${GREEN}✓ nomic-embed-text${NC}"

  echo -e "${CYAN}[3/5] Modelos Ollama...${NC}"
  echo "Selecione um ou mais modelos (ex: 1,3,4):"
  for i in "${!MODELS[@]}"; do
    printf "  %2d) %s\n" "$((i+1))" "${MODELS[$i]}"
  done
  local c=""
  if [ -t 0 ]; then
    read -r -p "Escolha [default=1]: " c
  else
    c="${GHOST_MODEL_CHOICES:-1}"
  fi
  [[ -z "$c" ]] && c="1"

  local selected=()
  parse_model_choices "$c" selected
  if [ "${#selected[@]}" -eq 0 ]; then
    selected=("deepseek-coder-v2:16b")
  fi

  echo -e "${CYAN}Instalando ${#selected[@]} modelo(s)...${NC}"
  for m in "${selected[@]}"; do
    echo -e "  -> ${m}"
    if ollama pull "$m"; then
      echo -e "     ${GREEN}✓ ${m}${NC}"
    else
      echo -e "     ${YELLOW}~ falhou ${m} (seguindo com os restantes)${NC}"
    fi
  done
  PRIMARY_MODEL="${selected[0]}"
}

start_backend_if_enabled() {
  if [ "$SKIP_START" -eq 1 ]; then
    echo -e "${YELLOW}~ Backend nao iniciado (--skip-start)${NC}"
    return
  fi

  echo -e "${CYAN}[5/5] Backend GHOST v3...${NC}"
  cd "$SCRIPT_DIR/backend"
  pkill -f "uvicorn main:app" 2>/dev/null || true
  sleep 1
  nohup ./venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000 > "$SCRIPT_DIR/ghost.log" 2>&1 &
  sleep 3
  if curl -s http://localhost:8000/health >/dev/null; then
    echo -e "${GREEN}✓ Backend online${NC}"
  else
    echo -e "${YELLOW}~ Verifique ghost.log${NC}"
  fi
}

if [ "$DEPS_ONLY" -eq 1 ]; then
  ensure_python_venv
  echo -e "${GREEN}✓ Setup deps-only concluido${NC}"
  exit 0
fi

PRIMARY_MODEL="ghost"
ensure_ollama_ready
pull_models_if_enabled
echo -e "${CYAN}[4/5] Preparando backend Python...${NC}"
ensure_python_venv
start_backend_if_enabled

echo -e "\n${GREEN}════════════════════════════════════${NC}"
echo -e "${GREEN}  GHOST v3 OPERACIONAL${NC}"
echo -e "${GREEN}════════════════════════════════════${NC}"
echo -e "  Interface:   ${CYAN}http://localhost:8000/gui/${NC}"
echo -e "  API:         ${CYAN}http://localhost:8000${NC}"
echo -e "  OpenAI:      ${CYAN}http://localhost:8000/v1/chat/completions${NC}"
echo -e "  GHOSTRECON:  ${CYAN}http://localhost:8000/ghostrecon/ingest/run${NC}"
echo -e "  Docs:        ${CYAN}http://localhost:8000/docs${NC}"
echo -e "  Modelo base: ${CYAN}${PRIMARY_MODEL}${NC}\n"

echo -e "${YELLOW}Para integrar ao GHOSTRECON cascade, use no .env:${NC}"
echo -e "  GHOSTRECON_LMSTUDIO_ENABLED=1"
echo -e "  GHOSTRECON_LMSTUDIO_BASE_URL=http://localhost:8000/v1"
echo -e "  GHOSTRECON_LMSTUDIO_MODEL=ghost\n"

command -v xdg-open >/dev/null 2>&1 && xdg-open "http://localhost:8000/gui/" >/dev/null 2>&1 &
