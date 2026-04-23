"""
GHOST — GHOSTRECON Parser
Ingere e aprende com os dados produzidos pelo GHOSTRECON:
- Runs completos (JSON)
- Findings individuais
- SQLite data/bugbounty.db
- NDJSON em tempo real do pipeline
"""

import sqlite3, json, uuid, os
from datetime import datetime
from typing import Optional


class GhostreconParser:
    def __init__(self, memory):
        self.memory = memory

    # ─────────────────────────────────────────
    #  INGEST RUN COMPLETO
    # ─────────────────────────────────────────
    def ingest_run(self, data: dict) -> str:
        """Salva run no banco e retorna run_id"""
        run_id = data.get("id") or data.get("run_id") or str(uuid.uuid4())
        domain = data.get("domain", "unknown")

        self.memory.save_run(
            run_id   = run_id,
            domain   = domain,
            data     = data,
            findings_count = len(data.get("findings", [])),
            profile  = data.get("profile", "standard"),
        )
        return run_id

    def learn_from_run(self, run_id: str, data: dict):
        """Background: aprende com findings e superfície do run"""
        domain   = data.get("domain", "unknown")
        findings = data.get("findings", [])
        self.learn_from_findings(findings, domain=domain, run_id=run_id)

        # Aprende subdomínios
        subs = data.get("subdomains", [])
        if subs:
            self.memory.add(
                topic    = f"Subdomínios — {domain}",
                content  = f"Alvo: {domain}\nSubdomínios descobertos ({len(subs)}):\n" + "\n".join(list(subs)[:50]),
                category = "recon",
                tags     = [domain, "subdomains", run_id[:8]]
            )

        # Aprende parâmetros interessantes
        params = data.get("params", [])
        if params:
            self.memory.add(
                topic    = f"Parâmetros HTTP — {domain}",
                content  = f"Parâmetros descobertos em {domain}:\n" + "\n".join(list(params)[:80]),
                category = "recon",
                tags     = [domain, "params", "fuzz"]
            )

        # Aprende secrets encontrados
        secrets = data.get("secrets", [])
        for s in secrets[:20]:
            self.memory.add(
                topic    = f"Secret/Leak — {domain}",
                content  = f"Tipo: {s.get('type','?')}\nURL: {s.get('url','?')}\nValor: {str(s.get('value',''))[:100]}",
                category = "pentest",
                tags     = [domain, "leak", "secret", s.get("type","")]
            )

    # ─────────────────────────────────────────
    #  INGEST FINDINGS
    # ─────────────────────────────────────────
    def learn_from_findings(self, findings: list, domain: str = "", run_id: str = "") -> int:
        """Aprende com cada finding — adiciona à memória vetorial"""
        learned = 0
        severity_map = {"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}

        for f in findings:
            sev   = str(f.get("severity", f.get("score", "INFO"))).upper()
            ftype = f.get("type", f.get("vuln_type", "unknown"))
            url   = f.get("url", f.get("target", ""))
            ev    = f.get("evidence", f.get("payload", ""))
            mitre = f.get("mitre", f.get("mitre_id", ""))
            owasp = f.get("owasp", "")
            desc  = f.get("description", f.get("detail", ""))

            # Só persiste findings relevantes (INFO é muito genérico)
            if severity_map.get(sev, 1) < 2:
                continue

            content = (
                f"Severidade: {sev}\n"
                f"Tipo: {ftype}\n"
                f"Alvo: {domain or url}\n"
                f"URL: {url}\n"
                f"Evidência: {str(ev)[:300]}\n"
            )
            if desc:  content += f"Descrição: {str(desc)[:200]}\n"
            if mitre: content += f"MITRE: {mitre}\n"
            if owasp: content += f"OWASP: {owasp}\n"

            tags = [domain, sev.lower(), ftype.lower().replace(" ","_")]
            if run_id: tags.append(run_id[:8])
            if mitre:  tags.append(mitre.lower())

            self.memory.add(
                topic    = f"[{sev}] {ftype} — {domain or url[:50]}",
                content  = content,
                category = "pentest",
                tags     = tags,
                source   = "ghostrecon"
            )
            learned += 1

        return learned

    # ─────────────────────────────────────────
    #  INGEST SQLITE
    # ─────────────────────────────────────────
    def ingest_sqlite(self, db_path: str) -> dict:
        """Lê o SQLite do GHOSTRECON e ingere os dados"""
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        stats = {"runs": 0, "findings": 0, "manual_validations": 0}

        # Tabela de runs
        try:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY created_at DESC LIMIT 50"
            ).fetchall()
            for row in rows:
                r = dict(row)
                run_data = {}
                # Tenta parsear campo data/findings se for JSON
                for field in ["data", "findings", "result", "output"]:
                    if r.get(field) and isinstance(r[field], str):
                        try:
                            run_data = json.loads(r[field])
                            break
                        except: pass
                if not run_data:
                    run_data = r

                domain = r.get("domain") or run_data.get("domain", "unknown")
                findings = run_data.get("findings", [])

                self.memory.save_run(
                    run_id         = str(r.get("id", uuid.uuid4())),
                    domain         = domain,
                    data           = run_data,
                    findings_count = len(findings),
                    profile        = run_data.get("profile", r.get("profile", "standard"))
                )
                if findings:
                    self.learn_from_findings(findings, domain=domain)
                stats["runs"] += 1
                stats["findings"] += len(findings)
        except sqlite3.OperationalError:
            pass  # tabela não existe

        # Tabela de findings direta
        try:
            rows = conn.execute("SELECT * FROM findings ORDER BY created_at DESC LIMIT 200").fetchall()
            all_findings = [dict(r) for r in rows]
            self.learn_from_findings(all_findings)
            stats["findings"] += len(all_findings)
        except sqlite3.OperationalError:
            pass

        # Manual validations (Reporte)
        try:
            rows = conn.execute("SELECT * FROM manual_validations LIMIT 100").fetchall()
            for row in rows:
                r = dict(row)
                self.memory.add(
                    topic    = f"Validação Manual — {r.get('type','?')}",
                    content  = f"URL: {r.get('url','?')}\nSeveridade: {r.get('severity','?')}\nNota: {r.get('notes','')}\nStatus: {r.get('status','?')}",
                    category = "pentest",
                    tags     = ["manual_validation", r.get("type","").lower()],
                    source   = "ghostrecon_manual"
                )
            stats["manual_validations"] = len(rows)
        except sqlite3.OperationalError:
            pass

        # Brain/Cortex categories
        try:
            rows = conn.execute("SELECT * FROM categories LIMIT 100").fetchall()
            for row in rows:
                r = dict(row)
                self.memory.add(
                    topic    = f"Cortex Category — {r.get('name','?')}",
                    content  = f"Categoria: {r.get('name','?')}\nFindings: {r.get('count',0)}\nLinks: {r.get('links','')}",
                    category = "recon",
                    tags     = ["cortex", "category"],
                    source   = "ghostrecon_cortex"
                )
        except sqlite3.OperationalError:
            pass

        conn.close()
        return stats

    # ─────────────────────────────────────────
    #  INGEST NDJSON (pipeline em tempo real)
    # ─────────────────────────────────────────
    def process_ndjson(self, lines: list) -> dict:
        """Processa eventos NDJSON do pipeline GHOSTRECON"""
        stats = {"findings": 0, "logs": 0, "intel": 0, "errors": 0}

        for line in lines:
            line = line.strip()
            if not line: continue
            try:
                evt = json.loads(line)
            except:
                continue

            etype = evt.get("type", "")

            if etype == "finding":
                data = evt.get("data", evt)
                self.learn_from_findings([data])
                stats["findings"] += 1

            elif etype == "intel":
                data = evt.get("data", {})
                domain = data.get("domain", "")
                if data.get("urls"):
                    self.memory.add(
                        topic    = f"Intel URLs — {domain}",
                        content  = f"URLs do corpus para {domain}:\n" + "\n".join(list(data["urls"])[:30]),
                        category = "recon",
                        tags     = [domain, "intel", "urls"],
                        source   = "ghostrecon_ndjson"
                    )
                stats["intel"] += 1

            elif etype == "done":
                # Run completo — persiste sumário
                data = evt.get("data", {})
                if data.get("findings"):
                    self.learn_from_findings(data["findings"])
                    stats["findings"] += len(data["findings"])

            elif etype == "error":
                stats["errors"] += 1

            elif etype in ("log", "progress", "pipe"):
                stats["logs"] += 1

        return stats

    # ─────────────────────────────────────────
    #  QUERY
    # ─────────────────────────────────────────
    def get_findings(self, run_id: str, severity: Optional[str] = None) -> dict:
        run = self.memory.get_run(run_id)
        if not run:
            return {"findings": [], "total": 0}
        findings = run.get("findings", [])
        if severity:
            findings = [f for f in findings
                       if str(f.get("severity","")).upper() == severity.upper()]
        return {"findings": findings, "total": len(findings), "run_id": run_id}
