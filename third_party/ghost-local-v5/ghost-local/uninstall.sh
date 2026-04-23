#!/usr/bin/env bash
# Remove ambiente local do GHOST + HexStrike e modelos Ollama.
set -e

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
HEX_DIR="$REPO_ROOT/hexstrike-ai"

echo -e "${RED}⚠ Este script vai remover dados locais e modelos Ollama.${NC}"
echo -e "  - Venvs e dados do projeto (ghost_data, logs)"
echo -e "  - Servidores GHOST/HexStrike em execução"
echo -e "  - Modelos Ollama instalados localmente"
read -r -p "Confirmar desinstalação? [digite SIM]: " CONFIRM
if [[ "$CONFIRM" != "SIM" ]]; then
  echo "Cancelado."
  exit 0
fi

echo -e "${CYAN}[1/4] Parando processos...${NC}"
pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "hexstrike_server.py" 2>/dev/null || true

echo -e "${CYAN}[2/4] Removendo modelos Ollama...${NC}"
if command -v ollama >/dev/null 2>&1; then
  mapfile -t MODELS < <(ollama list 2>/dev/null | awk 'NR>1 {print $1}' | sed '/^$/d')
  if [ "${#MODELS[@]}" -eq 0 ]; then
    echo "  Nenhum modelo encontrado."
  else
    for m in "${MODELS[@]}"; do
      echo "  - removendo ${m}"
      ollama rm "$m" >/dev/null 2>&1 || echo -e "    ${YELLOW}⚠ falhou: ${m}${NC}"
    done
  fi
else
  echo -e "  ${YELLOW}Ollama não encontrado no PATH.${NC}"
fi

echo -e "${CYAN}[3/4] Limpando artefatos do GHOST...${NC}"
rm -rf "$ROOT/backend/venv" \
       "$ROOT/backend/ghost_data" \
       "$ROOT/ghost.log"

echo -e "${CYAN}[4/4] Limpando artefatos do HexStrike...${NC}"
rm -rf "$HEX_DIR/hexstrike-env" \
       "$HEX_DIR/__pycache__" \
       "$HEX_DIR/hexstrike.log"

echo -e "${GREEN}✓ Desinstalação concluída.${NC}"
echo -e "Se quiser remover também o binário Ollama, faça pelo gestor do sistema."
