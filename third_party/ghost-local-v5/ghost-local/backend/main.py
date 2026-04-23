"""
GHOST v3 — IA Local Ofensiva + Integração GHOSTRECON
FastAPI + Ollama + ChromaDB + SQLite
- OpenAI-compatible endpoint (cascata GHOSTRECON)
- Ingestão nativa de runs/findings/SQLite do GHOSTRECON
- Streaming real, todos os parâmetros Ollama, sessões, RAG
Samuel Ziger — Uso Privado
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
import httpx, json, sqlite3, os, asyncio, re
from memory import GhostMemory, embedding_strict_enabled
from ghostrecon_parser import GhostreconParser
from code_scanner import scanner as code_scanner
from hexstrike_bridge import (
    HEXSTRIKE_BASE,
    hexstrike_ping,
    hexstrike_post,
    hexstrike_get_health,
)
from datetime import datetime
import uuid

app = FastAPI(title="GHOST v3", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

memory  = GhostMemory()
grecon  = GhostreconParser(memory)


def _ollama_base_url() -> str:
    """Base HTTP do Ollama (API). Env: GHOST_OLLAMA_URL ou OLLAMA_HOST.
    Sempre troca «localhost» por 127.0.0.1: muitos .env usam localhost e o resolver devolve ::1
    enquanto o Ollama escuta só em IPv4 → «All connection attempts failed»."""
    raw = (os.getenv("GHOST_OLLAMA_URL") or os.getenv("OLLAMA_HOST") or "http://127.0.0.1:11434").strip().rstrip("/")
    if raw and not raw.startswith(("http://", "https://")):
        raw = "http://" + raw.lstrip("/")
    raw = re.sub(r"(?i)(https?://)localhost(:\d+)?(?=/|$)", r"\g<1>127.0.0.1\2", raw)
    return raw.rstrip("/")


OLLAMA = _ollama_base_url()
DEFAULT_OPENAI_MODEL = os.getenv("GHOST_OPENAI_DEFAULT_MODEL", os.getenv("GHOST_PRIMARY_MODEL", "mistral:7b"))
FORCE_PORTUGUESE = os.getenv("GHOST_FORCE_PORTUGUESE", "1").strip().lower() in ("1", "true", "yes", "on")
PORTUGUESE_ENFORCER = (
    "Responda sempre em português brasileiro (pt-BR), mantendo termos técnicos em inglês apenas quando necessário."
)


def with_portuguese_enforcer(system_text: str) -> str:
    base = str(system_text or "").strip()
    if not FORCE_PORTUGUESE:
        return base
    if "português" in base.lower() or "pt-br" in base.lower():
        return base
    return f"{base}\n\n{PORTUGUESE_ENFORCER}" if base else PORTUGUESE_ENFORCER

# ─────────────────────────────────────────────────────
#  SYSTEM PROMPT  — consciente do GHOSTRECON
# ─────────────────────────────────────────────────────
BASE_SYSTEM = """Você é GHOST — IA ofensiva local e privada de Samuel Ziger.
Você é parte integrante da plataforma GHOSTRECON — framework de OSINT, reconhecimento e pentest.

## Contexto Operacional
Samuel Ziger · Pentester/Developer · Brasília
- A Divisão (Pentest/Dev) + Photo Now (Vue.js + Java)
- Ex-Cabo Exército Brasileiro (redes/infra, QG Comando)
- Desec Academy + ADS 2º semestre · HackerOne ativo
- Stack: Java, Vue.js, Python, Bash, PHP, JS, C básico

## Plataforma GHOSTRECON
Você tem acesso aos dados produzidos pelo GHOSTRECON:
- **Runs**: varreduras completas com findings, scores, MITRE/OWASP tags
- **Findings**: vulnerabilidades encontradas (HIGH/MEDIUM/LOW/INFO/CRITICAL)
- **Corpus/Intel**: URLs, parâmetros, endpoints descobertos
- **DNS/TLS/Surface**: dados de reconhecimento passivo
- **Subdomínios**: CT logs, VT, subfinder, amass
- **Secrets/JS**: leaks descobertos em JS e repos GitHub
- **SQLi/XSS/SSRF/LFI**: verificações com evidência
- **Kali data**: nmap, nuclei, ffuf, dalfox, wpscan, xss_vibes

## HexStrike AI (bridge GHOST)
O operador pode orquestrar o servidor HexStrike (ferramentas de automação ofensiva) via esta API: `GET /hexstrike/status`, `POST /hexstrike/relay` com corpo `{"path":"/api/...","payload":{...},"timeout":120}`. O GHOST encaminha para `GHOST_HEXSTRIKE_URL` (por defeito http://127.0.0.1:8888). Só caminhos `/api/...` na whitelist. Apenas alvos e testes **autorizados**.

Quando receber dados do GHOSTRECON via contexto, analise-os como um pentester experiente:
- Correlacione findings entre si
- Identifique caminhos de ataque encadeados
- Priorize por impacto real e probabilidade de exploração
- Sugira próximos passos concretos
- Mapeie para MITRE ATT&CK e OWASP Top 10

## Especialidades Técnicas

### Segurança Ofensiva
- **Web**: SQLi, XSS, SSRF, RCE, LFI/RFI, XXE, IDOR, CSRF, SSTI, Deserialização, JWT, OAuth, GraphQL, WebSocket, HTTP Smuggling, CORS, Open Redirect
- **Infra/AD**: Kerberoasting, Pass-the-Hash, DCSync, BloodHound, SMB, LDAP, RDP, MSSQL, Redis, Elasticsearch
- **Red Team**: C2 (Sliver, Havoc), evasão AV/EDR (AMSI, ETW, process hollowing, DLL sideloading), persistence, lateral movement, LOLBins
- **Post-Expl**: pivoting, port forwarding (chisel, ligolo-ng), credential dumping (Mimikatz, secretsdump), privesc
- **OSINT**: Shodan, Censys, theHarvester, recon-ng, dorks, metadata
- **Bug Bounty**: metodologia, CVSS v3/v4, OWASP Testing Guide, HackerOne
- **CTF**: web, pwn (BoF, heap, ROP), reversing, crypto, forensics, stego
- **Malware**: análise estática/dinâmica, YARA, evasão sandbox

### Desenvolvimento
Python, Java, Bash, JavaScript/Vue.js, PHP, C, PowerShell, Go, Assembly, SQL

### Ferramentas
Nmap, Burp, Metasploit, SQLmap, ffuf, Gobuster, Nuclei, Hydra, Hashcat, Mimikatz, BloodHound, Impacket, Chisel, Ligolo, Sliver, msfvenom, CrackMapExec, Responder, Volatility, Ghidra, pwndbg

## Comportamento
- Contexto: profissional / pentest autorizado / bug bounty / educacional
- Idioma padrão: português brasileiro nativo (termos técnicos podem ficar em inglês)
- Sem disclaimers repetitivos — direto ao ponto
- Com dados GHOSTRECON: analisa como operador de campo, não como chatbot

## Método de Resolução de Problemas (upgrade inteligência)
Ao resolver um problema técnico, aplique este ciclo:
1) Diagnóstico: formule hipóteses e descarte causas improváveis com evidências.
2) Priorização: foque primeiro no maior impacto e menor custo de correção.
3) Execução: proponha passos objetivos, comandos e validações mensuráveis.
4) Verificação: confirme resultado esperado e riscos residuais.
5) Próximo passo: indique ação imediata de continuidade (hardening, teste, monitoramento).
"""

# ─────────────────────────────────────────────────────
#  SCHEMAS
# ─────────────────────────────────────────────────────
class ModelParams(BaseModel):
    # Sampling
    temperature:        float = Field(0.7,   ge=0.0,   le=2.0)
    top_p:              float = Field(0.9,   ge=0.0,   le=1.0)
    top_k:              int   = Field(40,    ge=0,     le=200)
    min_p:              float = Field(0.0,   ge=0.0,   le=1.0)
    typical_p:          float = Field(1.0,   ge=0.0,   le=1.0)
    repeat_penalty:     float = Field(1.1,   ge=0.5,   le=2.0)
    repeat_last_n:      int   = Field(64,    ge=-1,    le=2048)
    presence_penalty:   float = Field(0.0,   ge=-2.0,  le=2.0)
    frequency_penalty:  float = Field(0.0,   ge=-2.0,  le=2.0)
    # Context
    num_ctx:            int   = Field(8192,  ge=512,   le=131072)
    num_predict:        int   = Field(2048,  ge=64,    le=32768)
    num_keep:           int   = Field(0,     ge=0,     le=1024)
    # Mirostat
    mirostat:           int   = Field(0,     ge=0,     le=2)
    mirostat_tau:       float = Field(5.0,   ge=0.0,   le=10.0)
    mirostat_eta:       float = Field(0.1,   ge=0.0,   le=1.0)
    # Other
    tfs_z:              float = Field(1.0,   ge=0.0,   le=1.0)
    seed:               int   = Field(-1)
    num_thread:         int   = Field(0,     ge=0)
    num_gpu:            int   = Field(-1)   # -1 = auto
    num_batch:          int   = Field(512,   ge=1,     le=2048)
    penalize_newline:   bool  = Field(False)
    stop:               List[str] = Field([])
    # System behavior
    numa:               bool  = Field(False)
    low_vram:           bool  = Field(False)
    f16_kv:             bool  = Field(True)
    logits_all:         bool  = Field(False)
    vocab_only:         bool  = Field(False)
    use_mmap:           bool  = Field(True)
    use_mlock:          bool  = Field(False)

class Message(BaseModel):
    role:    str
    content: str

class ChatRequest(BaseModel):
    message:         str
    model:           str          = "deepseek-coder-v2:16b"
    history:         List[Message]= []
    params:          ModelParams  = ModelParams()
    session_id:      str          = "default"
    system_override: Optional[str]= None
    memory_k:        int          = Field(6, ge=0, le=30)
    memory_category: Optional[str]= None
    feedback_k:      int          = Field(4, ge=0, le=20)  # RAG só de memória de feedback
    ghostrecon_context: Optional[Dict] = None  # dados diretos do GHOSTRECON

class TeachRequest(BaseModel):
    topic:    str
    content:  str
    category: str       = "general"
    tags:     List[str] = []

class FeedbackRequest(BaseModel):
    question:   str
    answer:     str
    rating:     int     = Field(..., ge=1, le=5)
    correction: Optional[str] = None
    session_id: str     = "default"

class SearchRequest(BaseModel):
    query:     str
    n_results: int           = 10
    category:  Optional[str] = None

class SessionSaveRequest(BaseModel):
    session_id: str
    title:      str
    messages:   List[Message]
    model:      str
    params:     ModelParams = ModelParams()

class HexstrikeRelayBody(BaseModel):
    """Encaminha POST para o servidor HexStrike (path na whitelist)."""
    path:    str
    payload: Dict[str, Any] = Field(default_factory=dict)
    timeout: float = Field(120.0, ge=5.0, le=600.0)

# ─── OpenAI-compat (para cascata GHOSTRECON) ───
class OAIMessage(BaseModel):
    role:    str
    content: str

class OAIRequest(BaseModel):
    model:       str             = "ghost"
    messages:    List[OAIMessage]= []
    max_tokens:  int             = 2048
    temperature: float           = 0.7
    top_p:       float           = 0.9
    stream:      bool            = False
    feedback_k:  int             = Field(4, ge=0, le=20)

class ModelInstallRequest(BaseModel):
    models: List[str] = Field(default_factory=list)

class WorkspaceRootRequest(BaseModel):
    path: str

class WorkspaceWriteRequest(BaseModel):
    path: str
    content: str
    create_dirs: bool = True

# ─────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────
def build_options(p: ModelParams) -> dict:
    opts = {
        "temperature":       p.temperature,
        "top_p":             p.top_p,
        "top_k":             p.top_k,
        "min_p":             p.min_p,
        "typical_p":         p.typical_p,
        "repeat_penalty":    p.repeat_penalty,
        "repeat_last_n":     p.repeat_last_n,
        "presence_penalty":  p.presence_penalty,
        "frequency_penalty": p.frequency_penalty,
        "num_ctx":           p.num_ctx,
        "num_predict":       p.num_predict,
        "num_keep":          p.num_keep,
        "mirostat":          p.mirostat,
        "mirostat_tau":      p.mirostat_tau,
        "mirostat_eta":      p.mirostat_eta,
        "tfs_z":             p.tfs_z,
        "penalize_newline":  p.penalize_newline,
        "num_batch":         p.num_batch,
        "numa":              p.numa,
        "low_vram":          p.low_vram,
        "f16_kv":            p.f16_kv,
        "use_mmap":          p.use_mmap,
        "use_mlock":         p.use_mlock,
    }
    if p.seed >= 0:      opts["seed"]       = p.seed
    if p.num_thread > 0: opts["num_thread"] = p.num_thread
    if p.num_gpu >= 0:   opts["num_gpu"]    = p.num_gpu
    if p.stop:           opts["stop"]       = p.stop
    return opts

def build_context(msg: str, k: int, cat: Optional[str]) -> tuple[str, list]:
    docs = memory.search(msg, n_results=k, category=cat) if k > 0 else []
    if not docs:
        return "", []
    ctx = "\n\n## Memória GHOST (referência primária):\n"
    for d in docs:
        ctx += f"\n### [{d['category'].upper()}] {d['topic']} (rel:{d.get('relevance',0):.3f})\n{d['content']}\n"
    return ctx, docs


def build_feedback_context(msg: str, k: int) -> tuple[str, list]:
    """RAG dedicado a entradas geradas a partir de feedback (preferências / correções)."""
    if k <= 0 or not (msg or "").strip():
        return "", []
    docs = memory.search_feedback(msg, n_results=k)
    if not docs:
        return "", []
    ctx = "\n\n## Preferências e correções do operador (feedback) — aplicar na resposta:\n"
    for d in docs:
        ctx += f"\n### [{d['category'].upper()}] {d['topic']} (rel:{d.get('relevance',0):.3f})\n{d['content']}\n"
    return ctx, docs

# ─────────────────────────────────────────────────────
#  WORKSPACE (leitura/escrita local, estilo "code assistant")
# ─────────────────────────────────────────────────────
WORKSPACE_ROOT = Path(os.getenv("GHOST_WORKSPACE_ROOT", str(Path.cwd()))).resolve()

def _safe_workspace_root(path_raw: str) -> Path:
    p = Path(path_raw).expanduser().resolve()
    if not p.exists():
        raise HTTPException(404, f"Pasta não encontrada: {p}")
    if not p.is_dir():
        raise HTTPException(400, f"Caminho não é diretório: {p}")
    return p

def _resolve_workspace_path(path_raw: str) -> Path:
    rel = str(path_raw or "").strip().lstrip("/\\")
    if not rel:
        return WORKSPACE_ROOT
    p = (WORKSPACE_ROOT / rel).resolve()
    try:
        p.relative_to(WORKSPACE_ROOT)
    except Exception:
        raise HTTPException(400, "Caminho fora da workspace root (bloqueado).")
    return p

def _build_tree(base: Path, depth: int = 2):
    if depth < 0:
        return None
    if base.is_file():
        return {"name": base.name, "path": str(base.relative_to(WORKSPACE_ROOT)), "type": "file"}
    children = []
    try:
        entries = sorted(base.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
    except Exception as e:
        return {
            "name": base.name,
            "path": str(base.relative_to(WORKSPACE_ROOT)) if base != WORKSPACE_ROOT else ".",
            "type": "dir",
            "error": str(e),
            "children": [],
        }
    for ent in entries[:500]:
        rel = str(ent.relative_to(WORKSPACE_ROOT))
        if ent.is_dir():
            children.append(
                {
                    "name": ent.name,
                    "path": rel,
                    "type": "dir",
                    "children": _build_tree(ent, depth - 1)["children"] if depth > 0 else [],
                }
            )
        else:
            children.append({"name": ent.name, "path": rel, "type": "file", "size": ent.stat().st_size})
    return {
        "name": base.name if base != WORKSPACE_ROOT else ".",
        "path": str(base.relative_to(WORKSPACE_ROOT)) if base != WORKSPACE_ROOT else ".",
        "type": "dir",
        "children": children,
    }

def build_ghostrecon_ctx(gr_data: Optional[Dict]) -> str:
    if not gr_data:
        return ""
    lines = ["\n\n## Dados GHOSTRECON (sessão atual):\n"]
    if "domain" in gr_data:
        lines.append(f"**Alvo**: {gr_data['domain']}")
    if "profile" in gr_data:
        lines.append(f"**Perfil**: {gr_data['profile']}")
    if "findings" in gr_data and gr_data["findings"]:
        findings = gr_data["findings"]
        lines.append(f"\n### Findings ({len(findings)} total):")
        for f in findings[:40]:  # max 40 findings no contexto
            sev = f.get("severity", f.get("score","?"))
            lines.append(f"- [{sev}] **{f.get('type','?')}** — {f.get('url', f.get('target','?'))}")
            if f.get("evidence"):
                lines.append(f"  Evidência: {str(f['evidence'])[:200]}")
            if f.get("mitre"):
                lines.append(f"  MITRE: {f['mitre']}")
    if "subdomains" in gr_data:
        subs = gr_data["subdomains"]
        lines.append(f"\n### Subdomínios ({len(subs)}): {', '.join(list(subs)[:20])}")
    if "urls" in gr_data:
        lines.append(f"\n### URLs descobertas: {len(gr_data['urls'])}")
    if "params" in gr_data:
        params_list = gr_data["params"]
        lines.append(f"\n### Parâmetros ({len(params_list)}): {', '.join(list(params_list)[:30])}")
    if "secrets" in gr_data and gr_data["secrets"]:
        lines.append(f"\n### ⚠ Secrets/Leaks detectados: {len(gr_data['secrets'])}")
    if "nmap" in gr_data:
        lines.append(f"\n### Nmap:\n{str(gr_data['nmap'])[:500]}")
    if "nuclei" in gr_data:
        lines.append(f"\n### Nuclei findings: {len(gr_data.get('nuclei',[]))}")
    return "\n".join(lines)

# ─────────────────────────────────────────────────────
#  SISTEMA / HEALTH
# ─────────────────────────────────────────────────────
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

@app.get("/")
async def root():
    return {
        "status": "GHOST v3", "memory": memory.count(),
        "ghostrecon": "integrado", "time": datetime.now().isoformat(),
        "ui": "/gui/",
    }

@app.get("/health")
async def health():
    ollama_ok = False
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{OLLAMA}/api/tags", timeout=3)
            ollama_ok = r.ok
    except: pass
    hz = await hexstrike_ping()
    emb_ok = memory.embeddings_reachable()
    return {
        "ghost": "online", "ollama": "online" if ollama_ok else "offline",
        "embeddings": "online" if emb_ok else "offline",
        "embedding_strict": embedding_strict_enabled(),
        "hexstrike": "online" if hz.get("ok") else "offline",
        "hexstrike_url": HEXSTRIKE_BASE,
        "memory": memory.count(), "feedback": memory.feedback_count(),
        "sessions": memory.sessions_count(), "runs": memory.runs_count(),
        "version": "3.0.0"
    }

@app.get("/models")
async def list_models():
    async with httpx.AsyncClient() as c:
        try:
            r = await c.get(f"{OLLAMA}/api/tags", timeout=5)
            return r.json()
        except Exception as e:
            raise HTTPException(503, f"Ollama offline: {e}")

@app.post("/models/install")
async def install_models(req: ModelInstallRequest):
    """Instala um ou mais modelos Ollama (equivale a `ollama pull`)."""
    picked = []
    for m in req.models:
        mm = (m or "").strip()
        if mm and mm not in picked:
            picked.append(mm)
    if not picked:
        raise HTTPException(400, "Informe ao menos um modelo")
    if len(picked) > 10:
        raise HTTPException(400, "Máximo de 10 modelos por solicitação")

    results = []
    for model in picked:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ollama", "pull", model,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            out, err = await proc.communicate()
            log = (out + err).decode(errors="ignore")
            ok = proc.returncode == 0
            results.append({
                "model": model,
                "ok": ok,
                "exit_code": proc.returncode,
                "log_tail": log[-2000:]
            })
        except FileNotFoundError:
            raise HTTPException(503, "Comando `ollama` não encontrado no sistema")
        except Exception as e:
            results.append({
                "model": model,
                "ok": False,
                "exit_code": -1,
                "log_tail": str(e)
            })

    installed = sum(1 for r in results if r["ok"])
    return {
        "requested": len(picked),
        "installed": installed,
        "failed": len(picked) - installed,
        "results": results
    }

@app.get("/stats")
async def stats():
    return {
        "memory_entries":  memory.count(),
        "categories":      memory.count_by_category(),
        "feedback_count":  memory.feedback_count(),
        "sessions_count":  memory.sessions_count(),
        "runs_count":      memory.runs_count(),
        "top_accessed":    memory.top_accessed(5),
        "version": "3.0.0"
    }

# ─────────────────────────────────────────────────────
#  HEXSTRIKE AI — bridge HTTP (GHOST_HEXSTRIKE_URL)
# ─────────────────────────────────────────────────────
@app.get("/hexstrike/status")
async def hexstrike_status():
    z = await hexstrike_ping()
    return {"base_url": HEXSTRIKE_BASE, "reachable": z.get("ok"), "detail": z}

@app.get("/hexstrike/health")
async def hexstrike_health_proxy():
    """Proxy para GET /health do HexStrike (pode demorar — enumera ferramentas)."""
    code, data = await hexstrike_get_health()
    if code != 200:
        raise HTTPException(status_code=502, detail=data if isinstance(data, (dict, str)) else str(data))
    return data

@app.post("/hexstrike/relay")
async def hexstrike_relay_ep(body: HexstrikeRelayBody):
    code, data = await hexstrike_post(body.path, body.payload, timeout=body.timeout)
    if code == 400:
        raise HTTPException(400, detail=data)
    return JSONResponse(content=data, status_code=code)

@app.get("/quickprompts")
async def quick_prompts():
    return {
        "pentest":   ["Checklist completo pentest web para o alvo", "Payloads SQLi bypass WAF moderno", "Kerberoasting passo-a-passo com impacket", "Report crítico HackerOne — template", "Explorar SSRF neste endpoint", "XXE OOB via DTD externo", "Bypass JWT com algoritmo none"],
        "recon":     ["Recon passivo completo para o domínio", "Google Dorks para arquivos sensíveis", "Script Python enumeração subdomínios + resolução", "Shodan/Censys para ativos vulneráveis", "Automação: nuclei + httpx + subfinder pipeline"],
        "exploit":   ["Exploit BoF com pwntools para binário descrito", "Bypass AMSI PowerShell técnicas atuais", "Privesc SUID Linux — enum + exploração", "Reverse shell Python reconexão automática + cifrado", "Shellcode loader C evasão AV básica", "DCSync secretsdump impacket"],
        "code":      ["Port scanner async Python + banner grabbing", "Script Bash automação recon completo", "Web scraper OSINT com requests + BeautifulSoup", "Parser de findings GHOSTRECON em Python", "Script análise NDJSON do pipeline GHOSTRECON"],
        "ghostrecon":["Analise os findings desta run e priorize por impacto", "Correlacione os subdomínios com os findings HIGH", "Gere relatório executivo dos resultados", "Quais findings têm cadeia de exploração viável?", "Mapeie findings para MITRE ATT&CK", "Próximos passos de pentest baseado nesta superfície"],
        "ctf":       ["Análise RSA com parâmetros fracos (n,e,c)", "Script pwntools para binário vulnerável", "Análise PCAP — encontre credenciais", "Decode esta string — identifique encoding"],
    }

# ─────────────────────────────────────────────────────
#  CHAT — STREAMING
# ─────────────────────────────────────────────────────
@app.post("/chat/stream")
async def chat_stream(req: ChatRequest):
    try:
        ctx_str, ctx_docs = build_context(req.message, req.memory_k, req.memory_category)
        fb_str, fb_docs = build_feedback_context(req.message, req.feedback_k)
    except RuntimeError as e:
        raise HTTPException(503, detail=str(e))
    gr_ctx = build_ghostrecon_ctx(req.ghostrecon_context)
    system = with_portuguese_enforcer(
        (req.system_override or BASE_SYSTEM) + ctx_str + fb_str + gr_ctx
    )

    msgs = [{"role": m.role, "content": m.content} for m in req.history]
    msgs.append({"role": "user", "content": req.message})

    payload = {
        "model": req.model, "system": system,
        "messages": msgs, "stream": True,
        "options": build_options(req.params)
    }

    async def generate():
        """Stream Ollama /api/chat; trata HTTP≠200 e corpo {"error":"..."} (ex.: RAM insuficiente)."""
        full = ""
        got_done = False
        meta_tail = {
            "memory_used": len(ctx_docs),
            "context_topics": [d["topic"] for d in ctx_docs],
            "feedback_used": len(fb_docs),
            "feedback_topics": [d["topic"] for d in fb_docs],
        }

        def pack_done(extra: dict) -> dict:
            extra.update(meta_tail)
            return extra

        async with httpx.AsyncClient(timeout=600) as client:
            try:
                async with client.stream("POST", f"{OLLAMA}/api/chat", json=payload) as r:
                    if r.status_code != 200:
                        raw = (await r.aread()).decode(errors="replace")[:2500]
                        err_txt = raw
                        try:
                            ej = json.loads(raw)
                            if isinstance(ej, dict) and ej.get("error"):
                                err_txt = ej["error"]
                        except json.JSONDecodeError:
                            pass
                        yield json.dumps(pack_done({
                            "token": "", "done": True,
                            "full": f"[Ollama] {err_txt}" if err_txt.strip() else f"[Ollama HTTP {r.status_code}]",
                            "eval_count": 0, "eval_duration": 0, "prompt_eval_count": 0,
                            "total_duration": 0, "load_duration": 0,
                        })) + "\n"
                        return

                    async for line in r.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if chunk.get("error"):
                            yield json.dumps(pack_done({
                                "token": "", "done": True,
                                "full": f"[Ollama] {chunk['error']}",
                                "eval_count": 0, "eval_duration": 0, "prompt_eval_count": 0,
                                "total_duration": 0, "load_duration": 0,
                            })) + "\n"
                            return

                        msg = chunk.get("message")
                        token = (msg.get("content", "") if isinstance(msg, dict) else "") or ""
                        full += token
                        done = chunk.get("done", False)
                        if done:
                            got_done = True
                        out = {"token": token, "done": done}
                        if done:
                            out.update({
                                "full": full,
                                "eval_count":        chunk.get("eval_count", 0),
                                "eval_duration":     chunk.get("eval_duration", 0),
                                "prompt_eval_count": chunk.get("prompt_eval_count", 0),
                                "total_duration":    chunk.get("total_duration", 0),
                                "load_duration":     chunk.get("load_duration", 0),
                                **meta_tail,
                            })
                        yield json.dumps(out) + "\n"

                    if not got_done:
                        hint = (
                            full
                            if full.strip()
                            else "[Ollama] Nenhum token recebido. Causas comuns: modelo inexistente (`ollama list` / `ollama pull ...`), RAM insuficiente para o modelo, ou Ollama parado. Tente um modelo menor (ex.: phi3.5:3.8b, qwen2.5-coder:7b)."
                        )
                        yield json.dumps(pack_done({
                            "token": "", "done": True, "full": hint,
                            "eval_count": 0, "eval_duration": 0, "prompt_eval_count": 0,
                            "total_duration": 0, "load_duration": 0,
                        })) + "\n"
            except httpx.RequestError as e:
                yield json.dumps(pack_done({
                    "token": "", "done": True,
                    "full": (
                        f"[Rede] Não foi possível contactar Ollama em {OLLAMA}: {e}\n\n"
                        "• Instala o Ollama (https://ollama.com) e corre no terminal: `ollama serve` (fica à escuta na porta 11434).\n"
                        "• Garante que tens pelo menos um modelo: `ollama pull mistral:7b` (ou outro).\n"
                        "• Se o Ollama estiver doutro host/porta, define `GHOST_OLLAMA_URL` (ex.: `http://192.168.1.5:11434`) antes de iniciar o GHOST."
                    ),
                    "eval_count": 0, "eval_duration": 0, "prompt_eval_count": 0,
                    "total_duration": 0, "load_duration": 0,
                })) + "\n"

    return StreamingResponse(generate(), media_type="application/x-ndjson",
                             headers={"X-Session-ID": req.session_id})

# ─────────────────────────────────────────────────────
#  OPENAI-COMPATIBLE  (cascata GHOSTRECON)
#  GHOSTRECON usa: Gemini → OpenRouter → Claude → LM Studio
#  GHOST serve como LM Studio / endpoint customizado
# ─────────────────────────────────────────────────────
@app.post("/v1/chat/completions")
async def openai_compat(req: OAIRequest):
    """Endpoint OpenAI-compatible para integração direta com GHOSTRECON cascade"""
    # Extrai system prompt das mensagens se existir
    system_msg = next((m.content for m in req.messages if m.role == "system"), BASE_SYSTEM)
    system_msg = with_portuguese_enforcer(system_msg)
    user_msgs  = [{"role": m.role, "content": m.content} for m in req.messages if m.role != "system"]

    # RAG rápido baseado na última mensagem + camada de feedback
    last_user = next((m.content for m in reversed(req.messages) if m.role == "user"), "")
    try:
        ctx_str, _ = build_context(last_user, 5, None)
        fb_str, _ = build_feedback_context(last_user, req.feedback_k)
    except RuntimeError as e:
        raise HTTPException(503, detail=str(e))
    full_system = system_msg + ctx_str + fb_str

    # Modelo: mapeia "ghost" para um default local configuravel (leve por defeito).
    model = req.model if req.model != "ghost" else DEFAULT_OPENAI_MODEL

    payload = {
        "model": model,
        "system": full_system,
        "messages": user_msgs,
        "stream": req.stream,
        "options": {
            "temperature": req.temperature,
            "top_p": req.top_p,
            "num_predict": req.max_tokens,
            "num_ctx": 8192,
        }
    }

    if req.stream:
        async def generate():
            cid = f"chatcmpl-{uuid.uuid4().hex[:8]}"
            async with httpx.AsyncClient(timeout=600) as client:
                async with client.stream("POST", f"{OLLAMA}/api/chat", json=payload) as r:
                    async for line in r.aiter_lines():
                        if not line.strip(): continue
                        try:
                            chunk = json.loads(line)
                            token = chunk.get("message", {}).get("content", "")
                            done  = chunk.get("done", False)
                            oai   = {
                                "id": cid, "object": "chat.completion.chunk",
                                "created": int(datetime.now().timestamp()),
                                "model": model,
                                "choices": [{"index": 0, "delta": {"content": token} if not done else {}, "finish_reason": "stop" if done else None}]
                            }
                            yield f"data: {json.dumps(oai)}\n\n"
                            if done: yield "data: [DONE]\n\n"
                        except: pass
        return StreamingResponse(generate(), media_type="text/event-stream")
    else:
        async with httpx.AsyncClient(timeout=600) as c:
            r = await c.post(f"{OLLAMA}/api/chat", json=payload)
            d = r.json()
            content = d.get("message", {}).get("content", "")
            return {
                "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
                "object": "chat.completion",
                "created": int(datetime.now().timestamp()),
                "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": d.get("prompt_eval_count", 0), "completion_tokens": d.get("eval_count", 0), "total_tokens": d.get("prompt_eval_count", 0) + d.get("eval_count", 0)}
            }

@app.get("/v1/models")
async def oai_models():
    """OpenAI-compatible model list"""
    data = [{"id": "ghost", "object": "model", "owned_by": "ghost"}]
    seen = {"ghost"}
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{OLLAMA}/api/tags", timeout=5)
            if r.is_success:
                models = (r.json() or {}).get("models", [])
                for m in models:
                    mid = str(m.get("name", "")).strip()
                    if not mid or mid in seen:
                        continue
                    data.append({"id": mid, "object": "model", "owned_by": "ollama"})
                    seen.add(mid)
    except Exception:
        # fallback minimo sem bloquear endpoint
        pass

    if DEFAULT_OPENAI_MODEL not in seen:
        data.append({"id": DEFAULT_OPENAI_MODEL, "object": "model", "owned_by": "ollama"})
    return {"object": "list", "data": data}

# ─────────────────────────────────────────────────────
#  GHOSTRECON — INTEGRAÇÃO
# ─────────────────────────────────────────────────────

@app.post("/ghostrecon/ingest/run")
async def ingest_run(data: dict, background_tasks: BackgroundTasks):
    """
    Ingere um run completo do GHOSTRECON (/api/runs/:id).
    Extrai findings, subdomínios, URLs e aprende automaticamente.
    """
    run_id = grecon.ingest_run(data)
    background_tasks.add_task(grecon.learn_from_run, run_id, data)
    return {"status": "ingerido", "run_id": run_id, "findings": len(data.get("findings", []))}

@app.post("/ghostrecon/ingest/findings")
async def ingest_findings(findings: List[dict]):
    """Ingere apenas a lista de findings de um run"""
    learned = grecon.learn_from_findings(findings)
    return {"status": "aprendido", "learned": learned, "total": len(findings)}

@app.post("/ghostrecon/ingest/sqlite")
async def ingest_sqlite(body: dict):
    """
    Lê o SQLite do GHOSTRECON diretamente.
    body: { "db_path": "/path/to/data/bugbounty.db" }
    """
    db_path = body.get("db_path", "data/bugbounty.db")
    if not os.path.exists(db_path):
        raise HTTPException(404, f"DB não encontrado: {db_path}")
    result = grecon.ingest_sqlite(db_path)
    return {"status": "ingerido", **result}

@app.post("/ghostrecon/ingest/ndjson")
async def ingest_ndjson(request: Request):
    """
    Recebe stream NDJSON diretamente do pipeline GHOSTRECON.
    Pode ser usado como webhook em tempo real durante o scan.
    """
    body = await request.body()
    lines = body.decode().strip().split("\n")
    processed = grecon.process_ndjson(lines)
    return {"status": "processado", **processed}

@app.post("/ghostrecon/analyze")
async def analyze_run(body: dict):
    """
    Análise profunda de um run — streaming.
    body: { "run_id": "...", "mode": "full|quick|report|chain" }
    """
    run_id = body.get("run_id")
    mode   = body.get("mode", "full")
    model  = body.get("model", "deepseek-coder-v2:16b")
    params = ModelParams(**body.get("params", {}))

    run_data = memory.get_run(run_id) if run_id else None

    # Monta prompt de análise
    if mode == "report":
        prompt = _prompt_report(run_data)
    elif mode == "chain":
        prompt = _prompt_chain(run_data)
    elif mode == "quick":
        prompt = _prompt_quick(run_data)
    else:
        prompt = _prompt_full(run_data)

    ctx_str, _ = build_context(f"pentest findings {run_data.get('domain','') if run_data else ''}", 6, None)
    system = BASE_SYSTEM + ctx_str + "\n\nAnalise como pentester sênior. Seja técnico, preciso e acionável."

    payload = {
        "model": model, "system": system,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True, "options": build_options(params)
    }

    async def generate():
        async with httpx.AsyncClient(timeout=600) as client:
            async with client.stream("POST", f"{OLLAMA}/api/chat", json=payload) as r:
                async for line in r.aiter_lines():
                    if not line.strip(): continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        yield json.dumps({"token": token, "done": chunk.get("done", False)}) + "\n"
                    except: pass

    return StreamingResponse(generate(), media_type="application/x-ndjson")

@app.get("/ghostrecon/runs")
async def list_runs():
    return memory.list_runs()

@app.get("/ghostrecon/runs/{run_id}")
async def get_run(run_id: str):
    run = memory.get_run(run_id)
    if not run: raise HTTPException(404, "Run não encontrado")
    return run

@app.get("/ghostrecon/findings/{run_id}")
async def get_findings(run_id: str, severity: Optional[str] = None):
    return grecon.get_findings(run_id, severity)

# ─────────────────────────────────────────────────────
#  MEMÓRIA
# ─────────────────────────────────────────────────────
@app.post("/memory/teach")
async def teach(req: TeachRequest):
    try:
        doc_id = memory.add(topic=req.topic, content=req.content, category=req.category, tags=req.tags)
    except RuntimeError as e:
        raise HTTPException(503, detail=str(e))
    return {"status": "aprendido", "id": doc_id, "topic": req.topic}

@app.post("/memory/teach/bulk")
async def teach_bulk(items: List[TeachRequest]):
    ids = []
    for i in items:
        try:
            ids.append(memory.add(topic=i.topic, content=i.content, category=i.category, tags=i.tags))
        except RuntimeError as e:
            raise HTTPException(503, detail=str(e))
    return {"status": "importado", "count": len(ids)}

@app.post("/memory/feedback")
async def feedback(req: FeedbackRequest):
    fid = memory.save_feedback(req.question, req.answer, req.rating, req.correction, req.session_id)
    return {"status": "salvo", "id": fid, "auto_learned": req.rating >= 4 and bool(req.correction)}

@app.post("/memory/search")
async def search_mem(req: SearchRequest):
    try:
        results = memory.search(req.query, n_results=req.n_results, category=req.category)
    except RuntimeError as e:
        raise HTTPException(503, detail=str(e))
    return {"results": results, "count": len(results)}

@app.get("/memory/all")
async def get_all(category: Optional[str] = None, limit: int = 500):
    return memory.get_all(category=category, limit=limit)

@app.get("/memory/categories")
async def get_cats():
    return memory.count_by_category()

@app.delete("/memory/{doc_id}")
async def del_mem(doc_id: str):
    memory.delete(doc_id)
    return {"status": "removido", "id": doc_id}

@app.get("/memory/export")
async def export_mem():
    return memory.export()

@app.post("/memory/import")
async def import_mem(data: dict):
    try:
        count = memory.import_data(data)
    except RuntimeError as e:
        raise HTTPException(503, detail=str(e))
    return {"status": "importado", "entries": count}

# ─────────────────────────────────────────────────────
#  SESSÕES
# ─────────────────────────────────────────────────────
@app.post("/sessions/save")
async def save_session(req: SessionSaveRequest):
    memory.save_session(req.session_id, req.title,
                        [m.dict() for m in req.messages], req.model, req.params.dict())
    return {"status": "salva", "id": req.session_id}

@app.get("/sessions")
async def list_sessions():
    return memory.list_sessions()

@app.get("/sessions/{sid}")
async def get_session(sid: str):
    s = memory.get_session(sid)
    if not s: raise HTTPException(404, "Sessão não encontrada")
    return s

@app.delete("/sessions/{sid}")
async def del_session(sid: str):
    memory.delete_session(sid)
    return {"status": "removida", "id": sid}

# ─────────────────────────────────────────────────────
#  WORKSPACE API
# ─────────────────────────────────────────────────────
@app.get("/workspace/info")
async def workspace_info():
    return {"root": str(WORKSPACE_ROOT)}

@app.post("/workspace/root")
async def workspace_set_root(req: WorkspaceRootRequest):
    global WORKSPACE_ROOT
    WORKSPACE_ROOT = _safe_workspace_root(req.path)
    return {"status": "ok", "root": str(WORKSPACE_ROOT)}

@app.get("/workspace/tree")
async def workspace_tree(path: str = "", depth: int = 2):
    depth = max(0, min(depth, 5))
    p = _resolve_workspace_path(path)
    if not p.exists():
        raise HTTPException(404, f"Caminho não encontrado: {path}")
    return _build_tree(p, depth)

@app.get("/workspace/read")
async def workspace_read(path: str, max_chars: int = 200000):
    p = _resolve_workspace_path(path)
    if not p.exists():
        raise HTTPException(404, f"Arquivo não encontrado: {path}")
    if not p.is_file():
        raise HTTPException(400, "Caminho não é arquivo.")
    max_chars = max(1000, min(max_chars, 1_000_000))
    try:
        txt = p.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        raise HTTPException(500, f"Falha ao ler arquivo: {e}")
    truncated = len(txt) > max_chars
    if truncated:
        txt = txt[:max_chars]
    return {
        "path": str(p.relative_to(WORKSPACE_ROOT)),
        "content": txt,
        "truncated": truncated,
        "bytes": p.stat().st_size,
    }

@app.post("/workspace/write")
async def workspace_write(req: WorkspaceWriteRequest):
    p = _resolve_workspace_path(req.path)
    parent = p.parent
    if not parent.exists():
        if req.create_dirs:
            parent.mkdir(parents=True, exist_ok=True)
        else:
            raise HTTPException(400, "Diretório pai não existe (create_dirs=false).")
    try:
        p.write_text(req.content, encoding="utf-8")
    except Exception as e:
        raise HTTPException(500, f"Falha ao gravar arquivo: {e}")
    return {"status": "ok", "path": str(p.relative_to(WORKSPACE_ROOT)), "bytes": p.stat().st_size}

# ─────────────────────────────────────────────────────
#  CODESCAN — ANÁLISE DE SEGURANÇA EM REPOSITÓRIO LOCAL
# ─────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    repo_path:     str
    focus:         str              = "all"   # all | sqli | auth | secrets | injection | crypto | logic
    model:         str              = "deepseek-coder-v2:16b"
    params:        ModelParams      = ModelParams()
    include_exts:  List[str]        = []      # ex: [".py",".java"] — vazio = todas
    exclude_paths: List[str]        = []      # dirs/arquivos a ignorar
    target_file:   Optional[str]    = None    # analisa só este arquivo
    llm_review:    bool             = True    # roda análise LLM além do estático
    learn:         bool             = True    # aprende findings na memória

class ScanFileRequest(BaseModel):
    file_path: str
    focus:     str         = "all"
    model:     str         = "deepseek-coder-v2:16b"
    params:    ModelParams = ModelParams()

@app.post("/codescan/repo")
async def scan_repo(req: ScanRequest, bg: BackgroundTasks):
    """
    Escaneia repositório local:
    1. Análise estática com regras (Python, Java, JS, PHP, Bash, Go, etc.)
    2. Análise LLM profunda em streaming (opcional)
    3. Aprende findings na memória vetorial (opcional)
    """
    import asyncio

    # 1. Scan estático (rápido, síncrono)
    try:
        inc = set(req.include_exts) if req.include_exts else None
        result = code_scanner.walk_repo(
            root=req.repo_path,
            include_exts=inc,
            exclude_paths=req.exclude_paths
        )
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"Erro no scan: {e}")

    # 2. Aprende findings em background
    if req.learn and result["static_findings"]:
        bg.add_task(_learn_code_findings, result, req.repo_path)

    # 3. Se não quer LLM, retorna só estático
    if not req.llm_review:
        result.pop("file_contents", None)
        return result

    # 4. Análise LLM — streaming
    prompt  = code_scanner.build_llm_prompt(result, focus=req.focus, target_file=req.target_file)
    ctx_str, _ = build_context(f"code security {req.focus} vulnerabilities", 4, "pentest")
    system  = BASE_SYSTEM + ctx_str + "\n\nVocê é um especialista em code review de segurança (SAST). Identifique vulnerabilidades reais, não falsos positivos óbvios. Seja técnico e preciso."

    # Remove conteúdo de arquivo da resposta (fica no prompt)
    result.pop("file_contents", None)

    payload = {
        "model": req.model,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
        "options": build_options(req.params)
    }

    async def generate():
        # Envia primeiro o resultado estático como metadados
        yield json.dumps({"type": "static", "data": result}) + "\n"

        async with httpx.AsyncClient(timeout=600) as client:
            async with client.stream("POST", f"{OLLAMA}/api/chat", json=payload) as r:
                async for line in r.aiter_lines():
                    if not line.strip(): continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("message", {}).get("content", "")
                        done  = chunk.get("done", False)
                        yield json.dumps({
                            "type": "llm",
                            "token": token,
                            "done": done,
                            **({"eval_count": chunk.get("eval_count", 0)} if done else {})
                        }) + "\n"
                    except: pass

    return StreamingResponse(generate(), media_type="application/x-ndjson")

@app.post("/codescan/file")
async def scan_file(req: ScanFileRequest):
    """Analisa um arquivo específico — estático + LLM"""
    from pathlib import Path

    fpath = Path(req.file_path)
    if not fpath.exists():
        raise HTTPException(404, f"Arquivo não encontrado: {req.file_path}")

    # Estático
    findings = code_scanner.scan_file(str(fpath))

    # Conteúdo para LLM
    try:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
    except:
        raise HTTPException(500, "Não foi possível ler o arquivo")

    from code_scanner import LANG_MAP
    lang = LANG_MAP.get(fpath.suffix.lower(), "code")

    prompt = f"""Analise este arquivo em busca de vulnerabilidades de segurança.

**Arquivo**: {fpath.name} ({lang})
**Findings estáticos já detectados**: {len(findings)}

```{lang}
{content[:8000]}
```

Findings automáticos:
{json.dumps([{"line":f.line,"severity":f.severity,"title":f.title,"snippet":f.snippet} for f in findings], indent=2, ensure_ascii=False)}

Foco: {req.focus}
Analise profundamente. Para cada vuln: arquivo/linha, tipo, severidade, snippet, como explorar, como corrigir."""

    system = BASE_SYSTEM + "\n\nEspecialista SAST. Analise apenas o código fornecido. Seja preciso, direto, sem falsos positivos desnecessários."

    payload = {
        "model": req.model, "system": system,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True, "options": build_options(req.params)
    }

    async def generate():
        yield json.dumps({"type": "static", "findings": [{"line":f.line,"severity":f.severity,"title":f.title,"snippet":f.snippet,"cwe":f.cwe} for f in findings]}) + "\n"
        async with httpx.AsyncClient(timeout=300) as client:
            async with client.stream("POST", f"{OLLAMA}/api/chat", json=payload) as r:
                async for line in r.aiter_lines():
                    if not line.strip(): continue
                    try:
                        chunk = json.loads(line)
                        yield json.dumps({"type":"llm","token":chunk.get("message",{}).get("content",""),"done":chunk.get("done",False)}) + "\n"
                    except: pass

    return StreamingResponse(generate(), media_type="application/x-ndjson")

@app.post("/codescan/snippet")
async def scan_snippet(body: dict):
    """Analisa snippet de código inline — sem arquivo"""
    code    = body.get("code", "")
    lang    = body.get("lang", "python")
    focus   = body.get("focus", "all")
    model   = body.get("model", "deepseek-coder-v2:16b")
    p       = ModelParams(**body.get("params", {}))

    if not code.strip():
        raise HTTPException(400, "Código vazio")

    prompt = f"""Analise este snippet de {lang} em busca de vulnerabilidades:

```{lang}
{code[:6000]}
```

Foco: {focus}
Identifique: vulns, inputs não validados, lógica insegura, uso de funções perigosas.
Para cada issue: linha aproximada, tipo, severidade, PoC de exploração, fix."""

    ctx_str, _ = build_context(f"{lang} security vulnerability {focus}", 3, "pentest")
    system = BASE_SYSTEM + ctx_str + "\n\nEspecialista em code review de segurança."

    payload = {"model": model, "system": system,
               "messages": [{"role": "user", "content": prompt}],
               "stream": True, "options": build_options(p)}

    async def generate():
        async with httpx.AsyncClient(timeout=300) as client:
            async with client.stream("POST", f"{OLLAMA}/api/chat", json=payload) as r:
                async for line in r.aiter_lines():
                    if not line.strip(): continue
                    try:
                        chunk = json.loads(line)
                        yield json.dumps({"token":chunk.get("message",{}).get("content",""),"done":chunk.get("done",False)}) + "\n"
                    except: pass

    return StreamingResponse(generate(), media_type="application/x-ndjson")

@app.get("/codescan/rules")
async def list_rules():
    """Lista todas as regras estáticas disponíveis"""
    from code_scanner import RULES_GLOBAL, RULES_BY_LANG, LANG_MAP
    rules = []
    for pattern, sev, title, cwe, owasp in RULES_GLOBAL:
        rules.append({"scope":"global","severity":sev,"title":title,"cwe":cwe,"owasp":owasp})
    for lang, lang_rules in RULES_BY_LANG.items():
        for pattern, sev, title, cwe, owasp in lang_rules:
            rules.append({"scope":lang,"severity":sev,"title":title,"cwe":cwe,"owasp":owasp})
    return {"rules": rules, "total": len(rules), "languages": list(set(LANG_MAP.values()))}


@app.post("/codescan/disasm")
async def analyze_disasm(body: dict):
    """
    Análise profunda de disassembly / dump de Assembly.
    Aceita:
      - texto de disassembly (output de objdump, gdb, radare2, IDA, Ghidra)
      - código .asm/.s direto
    Detecta: gadgets ROP, shellcode, padrões de exploração, ofuscação,
             syscalls, stack pivots, NOP sleds, técnicas de evasão.
    """
    disasm    = body.get("disasm", "")
    focus     = body.get("focus", "rop")   # rop | shellcode | all | priv | race
    arch      = body.get("arch", "x86_64") # x86_64 | x86 | arm | arm64 | mips
    context   = body.get("context", "")    # contexto extra (nome binário, origem, etc.)
    model     = body.get("model", "deepseek-coder-v2:16b")
    p         = ModelParams(**body.get("params", {}))

    if not disasm.strip():
        raise HTTPException(400, "Disassembly vazio")

    # Scan estático nas linhas de assembly
    lines = disasm.split("\n")
    static_hits = []
    from code_scanner import RULES_BY_LANG
    asm_rules = RULES_BY_LANG.get("assembly", [])
    for i, line in enumerate(lines, 1):
        for pattern, sev, title, cwe, owasp in asm_rules:
            if re.search(pattern, line, re.IGNORECASE):
                static_hits.append({
                    "line": i, "severity": sev, "title": title,
                    "snippet": line.strip()[:120], "cwe": cwe
                })

    focus_map = {
        "rop":      "Identifique todos os gadgets ROP/JOP úteis: stack pivots (pop rsp, xchg rsp, leave+ret, add rsp+ret), write-what-where (mov [reg],reg), call/jmp indiretos, gadgets de syscall. Para cada gadget: offset se disponível, instrução exata, utilidade em chain.",
        "shellcode":"Analise se este é shellcode. Identifique: técnica de obtenção de IP (CALL $+5, FNSTENV, FPU), syscalls invocadas (execve, read, connect), encoding/ofuscação (XOR, rotações), NOP sled, estágio (stager vs full). Reconstitua o objetivo provável.",
        "all":      "Análise completa: gadgets ROP, padrões de shellcode, syscalls, operações privilegiadas, ofuscação, anti-debug, técnicas de evasão, lógica do código.",
        "priv":     "Identifique operações privilegiadas: ring0 (lgdt/lidt/wrmsr), syscalls de escalonamento (setuid, ptrace), operações I/O (in/out), modificação de registradores de controle (CR0/CR3).",
        "race":     "Identifique windows de race condition, acessos concorrentes a memória compartilhada, padrões TOCTOU em nível de Assembly.",
    }

    prompt = f"""## Análise de Assembly / Disassembly
Arquitetura: {arch}
Foco: {focus}
{f'Contexto: {context}' if context else ''}

### Findings Estáticos Automáticos ({len(static_hits)}):
{json.dumps(static_hits[:30], indent=2, ensure_ascii=False) if static_hits else "Nenhum"}

### Disassembly:
```asm
{disasm[:8000]}
```

### Instrução:
{focus_map.get(focus, focus_map['all'])}

Seja técnico e preciso. Indique offset/endereço quando visível. Para ROP: classifique o tipo de gadget. Para shellcode: descreva o payload completo reconstituído."""

    ctx_str, _ = build_context(f"assembly {focus} {arch}", 4, "pentest")
    system = BASE_SYSTEM + ctx_str + "\n\nVocê é especialista em análise de baixo nível: engenharia reversa, exploração binária, análise de Assembly."

    payload = {
        "model": model, "system": system,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True, "options": build_options(p)
    }

    async def generate():
        yield json.dumps({"type": "static", "findings": static_hits, "arch": arch, "focus": focus}) + "\n"
        async with httpx.AsyncClient(timeout=300) as client:
            async with client.stream("POST", f"{OLLAMA}/api/chat", json=payload) as r:
                async for line in r.aiter_lines():
                    if not line.strip(): continue
                    try:
                        chunk = json.loads(line)
                        yield json.dumps({
                            "type": "llm",
                            "token": chunk.get("message", {}).get("content", ""),
                            "done": chunk.get("done", False)
                        }) + "\n"
                    except: pass

    return StreamingResponse(generate(), media_type="application/x-ndjson")


def _learn_code_findings(result: dict, repo_path: str):
    """Background: aprende findings de código na memória"""
    repo_name = os.path.basename(repo_path)
    for f in result.get("static_findings", []):
        if f["severity"] in ("CRITICAL","HIGH","MEDIUM"):
            memory.add(
                topic    = f"[{f['severity']}] {f['title']} — {repo_name}",
                content  = f"Arquivo: {f['file']}\nLinha: {f['line']}\nLang: {f['lang']}\nCWE: {f['cwe']}\nOWASP: {f['owasp']}\nSnippet: {f['snippet']}",
                category = "pentest",
                tags     = ["codescan", repo_name, f["lang"], f["severity"].lower(), f["cwe"]],
                source   = "codescan"
            )

# ─────────────────────────────────────────────────────
#  HELPERS DE PROMPT GHOSTRECON
# ─────────────────────────────────────────────────────
def _prompt_quick(run: Optional[dict]) -> str:
    if not run: return "Nenhum dado de run disponível. Descreva o alvo para análise."
    domain   = run.get("domain", "?")
    findings = run.get("findings", [])
    high     = [f for f in findings if str(f.get("severity","")).upper() in ["HIGH","CRITICAL"]]
    return f"""Run GHOSTRECON — {domain}
Total findings: {len(findings)} | HIGH/CRITICAL: {len(high)}

Findings HIGH/CRITICAL:
{json.dumps(high[:15], indent=2, ensure_ascii=False)}

Faça análise rápida: principais riscos, exploração imediata, prioridade de remediação."""

def _prompt_full(run: Optional[dict]) -> str:
    if not run: return "Nenhum dado de run disponível."
    domain   = run.get("domain", "?")
    findings = run.get("findings", [])
    subs     = run.get("subdomains", [])
    return f"""Run GHOSTRECON completo — {domain}
Subdomínios: {len(subs)} | Findings: {len(findings)}

{json.dumps(findings[:30], indent=2, ensure_ascii=False)}

Análise completa:
1. Superfície de ataque identificada
2. Findings priorizados por impacto real
3. Cadeias de ataque possíveis (encadeamento de vulnerabilidades)
4. Mapeamento MITRE ATT&CK
5. Próximos passos operacionais
6. Recomendações de remediação"""

def _prompt_chain(run: Optional[dict]) -> str:
    if not run: return "Nenhum dado."
    findings = run.get("findings", [])
    return f"""Dados GHOSTRECON — {run.get('domain','?')}
Findings: {json.dumps(findings[:25], indent=2, ensure_ascii=False)}

Identifique e descreva todos os caminhos de ataque encadeados possíveis.
Para cada cadeia: steps específicos, condições, probabilidade de sucesso, impacto final.
Pense como um red teamer tentando comprometer o alvo."""

def _prompt_report(run: Optional[dict]) -> str:
    if not run: return "Nenhum dado."
    return f"""Gere um relatório executivo de pentest para:
Alvo: {run.get('domain','?')}
Data: {run.get('created_at', datetime.now().isoformat())}

Dados:
{json.dumps(run, indent=2, ensure_ascii=False)[:4000]}

Formato: relatório profissional em Markdown com:
# Sumário Executivo
# Superfície Analisada  
# Vulnerabilidades Identificadas (tabela por severidade)
# Análise Técnica Detalhada (top 5 findings)
# Cadeias de Ataque
# Recomendações
# Conclusão"""


@app.get("/gui", include_in_schema=False)
@app.get("/gui/", include_in_schema=False)
async def ghost_web_ui():
    """Interface web — abrir no browser (mesma origem que a API, evita NetworkError com file://)."""
    index = FRONTEND_DIR / "index.html"
    if not index.is_file():
        raise HTTPException(404, "frontend/index.html não encontrado")
    return FileResponse(index, media_type="text/html; charset=utf-8")
