# GHOST v3 (IA local + Ollama) — cópia embebida no GHOSTCTF

Origem: stack FastAPI + Ollama usada com o GHOSTRECON; **vendida aqui** para o GHOSTCTF não depender da pasta `GHOSTRECON/`.

## Arranque

Na raiz do GHOSTCTF:

```bash
./third_party/ghost-local-v5/start
```

(Equivale ao script `start` que invoca `ghost-local/start.sh`.) Define `PORT=8001` se a porta 8000 estiver ocupada.

## Ollama (obrigatório para chat / embeddings)

O backend GHOST fala com a API do **Ollama** em **`http://127.0.0.1:11434`** por defeito (e normaliza `localhost` → `127.0.0.1` se o `.env` disser `localhost`).

1. Instala o [Ollama](https://ollama.com) para o teu SO.
2. No terminal: `ollama serve` (mantém o serviço à escuta na porta **11434**). Em muitas instalações Linux existe serviço **`ollama`** → `sudo systemctl start ollama`.
3. Puxa um modelo, por exemplo: `ollama pull mistral:7b` ou `ollama pull phi3.5:3.8b`.

No **`npm start`** do GHOSTCTF, o script testa `…/api/tags` antes de subir o Ghost. Se o URL do Ollama for **local** (127.0.0.1 / localhost), tenta **`ollama serve`** em background por defeito (log em `third_party/ghost-local-v5/ollama-serve.log`). Para desactivar: **`GHOSTCTF_AUTO_OLLAMA_SERVE=0`** no `.env` na raiz do GHOSTCTF.

Se o Ollama estiver noutra máquina ou porta, define **`GHOST_OLLAMA_URL`** (ex.: `http://192.168.1.10:11434`) no ambiente **antes** de arrancar o `start.sh` / `npm start` (o processo Python herda a variável).

## Primeira vez

Dentro de `third_party/ghost-local-v5/ghost-local/backend/`:

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

O `start.sh` cria o `venv` automaticamente se não existir.

## Integração GHOSTCTF

- Variáveis: `GHOSTCTF_GHOST_LOCAL_URL` (ex.: `http://127.0.0.1:8000`), `GHOSTCTF_GHOST_LOCAL_MODEL`.
- Relatórios IA: `POST /api/ai-reports` com `"aiPrimaryCloud": "ghost_local"`.
- Health: `GET /api/ai/ghost-local-check`

## HexStrike

Opcional: no `start.sh` original, `GHOST_START_HEXSTRIKE=1` tenta subir HexStrike na pasta irmã `hexstrike-ai` (não incluída nesta cópia mínima). Para só Ollama + API GHOST, ignora.
