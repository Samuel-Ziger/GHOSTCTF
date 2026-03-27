# GHOSTCTF / GhostRecon

**Console web para recon em CTF por IPv4** com pipeline servidor em Node.js, e **API de recon passivo por domínio** voltada a bug bounty / OSINT (no mesmo backend).

O `package.json` chama o projeto de **ghostrecon**; a UI marca **GHOSTCTF**. São duas faces do mesmo serviço: automação agressiva opcional no alvo do lab e, via HTTP, enumeração passiva quando trabalhas com domínios.

---

## O que isto faz

| Modo | Entrada | Destaque |
|------|---------|----------|
| **GHOSTCTF** (UI) | IPv4 | `nmap`, enumeração web, diretórios, deteção de flags (Solyd, HTB, Google CTF), playbooks, provas opcionais (LFI, SQLMap, WPScan, FTP anónimo, SSH, MySQL, Exploit-DB, …). Stream **NDJSON** para o terminal da página. |
| **GhostRecon** (API) | Domínio válido | Subdomínios (crt.sh, VirusTotal opcional), DNS, RDAP, cabeçalhos de segurança, `robots.txt` / sitemaps, Wayback, Common Crawl, análise de JS, segredos heurísticos, dorks, Google CSE / GitHub opcionais, modo **Kali** opcional (ffuf, nuclei, …). |

Os runs podem ser **gravados** (SQLite local por omissão, ou **Supabase/Postgres** via `DATABASE_URL` ou chaves da API).

---

## Requisitos

- **Node.js** ≥ 18  
- Ferramentas **opcionais**:
  - **Kali** (ou ambiente com as mesmas ferramentas no `PATH`) para scans agressivos no modo domínio ou capacidades extra detetadas em `/api/capabilities`.
  - **John the Ripper** / wordlists para os endpoints de cracking usados pela UI.
  - **`nmap`** obrigatório para a parte GhostCTF baseada em IP (o pipeline chama o binário).

---

## Arranque rápido

```bash
npm install
cp .env.example .env
# Edita .env: PORT (default 3847), DATABASE_URL ou Supabase, chaves opcionais
npm start
```

Abre **`http://127.0.0.1:3847`** (ou a porta definida em `PORT`). O servidor serve o `index.html` e a API na mesma origem.

Desenvolvimento com reload:

```bash
npm run dev
```

---

## Docker

```bash
docker build -t ghostctf .
docker run --rm -p 3847:3847 --env-file .env ghostctf
```

A imagem copia `server/` e `index.html`. Configura variáveis de ambiente como no `.env.example`.

---

## Configuração (.env)

Copia **`.env.example`** para **`.env`**. Entre outras:

| Variável | Função |
|----------|--------|
| `PORT` | Porta HTTP (default `3847`) |
| `DATABASE_URL` | Postgres direto (recomendado com Supabase Session Pooler em IPv4) |
| `SUPABASE_*` | Alternativa à URL directa |
| `VIRUSTOTAL_API_KEY` | Módulo `virustotal` no pipeline de domínio |
| `GOOGLE_CSE_KEY` / `GOOGLE_CSE_CX` | Google Programmable Search no pipeline passivo |
| `GITHUB_TOKEN` | Code Search no pipeline passivo |
| `GHOSTRECON_WEBHOOK_URL` | Webhook JSON após run gravado (ex.: Discord) |
| `GHOSTRECON_RL_MAX` / `GHOSTRECON_RL_WINDOW_MS` | Rate limit dos POST de stream |
| `GHOSTRECON_CC_CDX_API` | Índice Common Crawl personalizado |
| `GHOSTCTF_RL_MAX` / `GHOSTCTF_RL_WINDOW_MS` | Alias aceites pelo código |
| `GHOSTCTF_FORCE_KALI` | Forçar deteção de ambiente tipo Kali fora do Kali |
| `GHOSTCTF_NMAP_ARGS` | Args extra para `nmap` no recon por domínio (quando aplicável) |

Nunca commits o ficheiro `.env`.

---

## API (resumo)

Todas as rotas abaixo estão no `server/index.js`. Respostas de stream usam **NDJSON** (uma linha JSON por evento).

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET` | `/api/health` | Saúde do serviço |
| `GET` | `/api/capabilities` | Ferramentas Kali disponíveis no host |
| `POST` | `/api/recon/stream` | Pipeline **passivo por domínio** — body: `{ domain, modules[], exactMatch?, kaliMode? }` |
| `POST` | `/api/ghostctf/stream` | Pipeline **CTF por IP** — body: `{ ip, platform, modules[], udpScan?, tcpAllPorts? }` |
| `POST` | `/api/ghostctf/decode` | Base64/Base32 + extração de flags por plataforma |
| `POST` | `/api/ghostctf/hash` | Operações de hash (ver corpo em `index.js`) |
| `POST` | `/api/ghostctf/hash-crack` | Crack MD5 com ferramentas do sistema |
| `POST` | `/api/ghostctf/john-crack` | John integrado |
| `GET` | `/api/runs` | Lista de runs guardados |
| `GET` | `/api/runs/:id` | Detalhe de um run |
| `GET` | `/api/runs/:newerId/diff/:baselineId` | Diff entre runs |
| `GET` | `/api/intel/:target` | Corpus deduplicado por alvo |
| `GET` | `/api/knowledge` | Biblioteca de padrões (SQLite; vazio em Supabase-only) |

### Módulos úteis do `POST /api/recon/stream`

Inclui, entre outros (passa os IDs exactamente como o backend espera):  
`subdomains`, `virustotal`, `dns_enrichment`, `rdap`, `security_headers`, `robots_sitemap`, `wellknown_security_txt`, `wellknown_openid`, `wayback`, `common_crawl`, `google_cse`, `github`, `pastebin`, e com `kaliMode: true` também `subfinder`, `amass` quando disponíveis.

Os **dorks** são construídos conforme o array `modules` (ver `buildDorks` / categorias no código).

---

## Interface (index.html)

- **Alvo:** apenas **IPv4** no fluxo principal (validação no cliente); chama `/api/ghostctf/stream`.
- **Plataforma de flag:** Solyd, HackTheBox, Google CTF.
- **Módulos GhostCTF:** UDP scan, todas as portas TCP, Exploit-DB, LFI, SQLMap, VHost/sitemap, disclosure, reutilização de credenciais, foco WordPress, WPScan.
- **Crack mode:** MD5 e John com formatos comuns.
- **Decode rápido:** Base64/Base32 na sidebar.
- Exportação dos achados: **JSON**, **Markdown**, **TXT**.

Se abrires o HTML em `file://`, define a base da API em `localStorage`:

`ghostctf_api_base` → `http://127.0.0.1:3847` (ou a tua porta).

---

## Base de dados (Supabase)

- Migrações em `supabase/migrations/` (tabelas `runs`, `findings`, `bounty_intel`).
- Scripts npm: `db:link`, `db:push`, `db:migration:new` (CLI Supabase como devDependency).

RLS está definido nas migrações; ajusta políticas se expuseres a BD publicamente.

---

## Testes

```bash
npm test
```

Executa `node --test` sobre os testes em `server/tests/`.

---

## Estrutura do repositório (núcleo)

```
server/
  index.js          # Express, rotas, orquestração
  config.js         # Limites, UA, rate limit
  modules/          # DNS, probe, DB, integrações externas, …
  ghostctf/         # Pipeline CTF (nmap, dir-enum, flags, …)
index.html          # SPA estática
supabase/           # Migrações e config CLI
 Dockerfile
 .env.example
```

---

## Ética e uso legítimo

Usa isto só em **alvos que te autorizem** (labs de CTF, programas de bug bounty, ambientes próprios). Scans agressivos, SQLMap, enumeração de passwords e ferramentas tipo nuclei podem ser **ilegais ou violar ToS** se apontados para sistemas sem permissão. A responsabilidade é sempre tua.

---

## Créditos

Feito para acelerar recon em CTF e consolidar truques de **OSINT / recon passivo** num único serviço Node, com opção de Postgres partilhado via Supabase.
