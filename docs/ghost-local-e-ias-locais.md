# IA local no GHOSTCTF

## GHOST v3 (`third_party/ghost-local-v5`)

Backend OpenAI-compatível (Ollama) na porta por defeito **8000**. Ver `third_party/ghost-local-v5/README.md`.

## Shannon Lite (white-box)

O código do Shannon **não** está neste repositório. Para usar white-box com repositório clonado:

```bash
mkdir -p IAs && cd IAs
git clone https://github.com/keygraph/shannon.git shannon
```

Variável opcional: `GHOSTCTF_SHANNON_HOME` ou legado `GHOSTRECON_SHANNON_HOME` (path absoluto) se instalares fora de `IAs/shannon`.

## PentestGPT (GreyDGL)

Clone opcional em `IAs/PentestGPT/` (Docker + `make install`). Para só **triagem HTTP** sem o agente, usa o script embebido:

```bash
node server/scripts/pentestgpt-ghost-bridge.mjs
```

E no `.env`: `GHOSTCTF_PENTESTGPT_URL=http://127.0.0.1:8765/validate` (variável legada `GHOSTRECON_PENTESTGPT_URL` ainda lida noutros módulos).

## Variáveis GHOSTCTF (preferidas)

| Uso | Variável |
|-----|----------|
| URL API GHOST local | `GHOSTCTF_GHOST_LOCAL_URL` |
| Modelo Ollama | `GHOSTCTF_GHOST_LOCAL_MODEL` |
| Marcar IA local nas capabilities | `GHOSTCTF_GHOST_LOCAL_ENABLED=1` |
| Ponte PentestGPT / porta | `GHOSTCTF_PENTESTGPT_BRIDGE_PORT`, `GHOSTCTF_PENTESTGPT_BRIDGE_MODEL` |

As variáveis `GHOSTRECON_*` equivalentes continuam a ser lidas como **fallback** onde o código já usava `envGhostctfThenRecon`, até removeres referências antigas no teu `.env`.
