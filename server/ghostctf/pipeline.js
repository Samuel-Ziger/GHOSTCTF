import { scanIpPorts } from './nmap-scan.js';
import { curlWebFromNmap, rowPrefersHttps, webOriginUrl } from './web-curl.js';
import { dirEnumAllTools } from './dir-enum.js';
import { detectFlagsWithDecoding } from './flag-detector.js';
import { buildCtfPlaybookSuggestions } from './playbook.js';
import { searchExploitDbFromNmap } from './exploitdb.js';
import { expandWebResponsesWithLinkCrawl } from './html-links.js';
import { appendRobotsTxtResponses } from './robots-probe.js';
import { ftpPortsFromNmap, probeFtpAnonymous } from './ftp-anonymous-probe.js';
import { probeSshService, sshPortsFromNmap } from './ssh-probe.js';
import { mysqlPortsFromNmap, probeMysqlService } from './mysql-probe.js';
import { runLfiPasswdProbe } from './lfi-probe.js';

export async function runGhostCtfPipeline({
  ip,
  platformId,
  modules = [],
  udpScan = false,
  tcpAllPorts = false,
  emit,
  saveRun,
}) {
  const findings = [];
  const stats = { endpoints: 0, params: 0, flags: 0, secrets: 0, high: 0 };
  const foundFlagSet = new Set();

  const addFinding = (f, statKey) => {
    if (statKey) stats[statKey] = (stats[statKey] || 0) + 1;
    findings.push(f);
    if (f.prio === 'high') stats.high += 1;
    emit({ type: 'finding', finding: f });
    emit({ type: 'stats', stats: { ...stats } });
  };

  const log = (msg, level = 'info') => emit({ type: 'log', msg, level });
  const pipe = (name, state) => emit({ type: 'pipe', name, state });
  const progress = (p) => emit({ type: 'progress', pct: p });
  const intel = (line) => emit({ type: 'intel', line });

  // 1) INPUT
  pipe('input', 'active');
  progress(5);
  pipe('input', 'done');

  // 2) RECON - Ports and services (mapeia para "subdomains" no UI)
  pipe('subdomains', 'active');
  progress(12);
  log(`GhostCTF Recon por IP: ${ip}`, 'section');

  let nmapRows = [];
  try {
    nmapRows = await scanIpPorts({ ip, tcpAllPorts, udpScan, log });
  } catch (e) {
    emit({ type: 'error', message: e?.message || String(e) });
    return { runId: null, findings, stats, intelMerge: null, correlation: { ip, platformId } };
  }

  const openPorts = (nmapRows || []).length;
  log(`nmap: ${openPorts} porta(s)/serviço(s) com registro no XML`, openPorts ? 'success' : 'warn');
  emit({ type: 'stats', stats: { ...stats } });

  // cria findings por serviço/porta
  const seenPorts = new Set();
  for (const r of nmapRows) {
    const port = Number(r.port);
    const proto = String(r.proto || 'tcp');
    const key = `${proto}:${port}`;
    if (seenPorts.has(key)) continue;
    seenPorts.add(key);

    const name = r.name || '';
    const product = r.product || '';
    const extra = r.extrainfo || '';
    const line = `${proto}/${port} ${name} ${product} ${r.version || ''}`.trim();
    const https = rowPrefersHttps(port, name, product, extra);
    addFinding(
      {
        type: 'nmap',
        prio: 'med',
        score: 55,
        value: line,
        meta: `${r.extrainfo || 'nmap'} (host=${r.host || ip})`,
        url: webOriginUrl(ip, port, https),
      },
      'endpoints',
    );
  }

  // Exploit-DB lookup (searchsploit) — opcional
  if (Array.isArray(modules) && modules.includes('exploitdb')) {
    try {
      const ex = await searchExploitDbFromNmap({ ip, nmapRows, log, limitQueries: 10 });
      if (ex.ok && Array.isArray(ex.findings) && ex.findings.length) {
        for (const f of ex.findings) addFinding(f, null);
      }
    } catch (e) {
      log(`Exploit-DB lookup: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('Exploit-DB lookup: OFF (ative em Modules)', 'info');
  }

  /** @type {{ tried: number; successPorts: number[]; errors: string[] }} */
  const ftpAnonymousSummary = { tried: 0, successPorts: [], errors: [] };
  const ftpPorts = ftpPortsFromNmap(nmapRows);
  if (ftpPorts.length) {
    log(`FTP detetado (porta(s) ${ftpPorts.join(', ')}) — a testar USER anonymous / PASS anonymous@...`, 'info');
    for (const ftpPort of ftpPorts) {
      ftpAnonymousSummary.tried += 1;
      try {
        const fr = await probeFtpAnonymous({ host: ip, port: ftpPort, timeoutMs: 12000 });
        if (fr.anonymousOk) {
          ftpAnonymousSummary.successPorts.push(ftpPort);
          const listPreview = Array.isArray(fr.listPreview) ? fr.listPreview.slice(0, 6) : [];
          const listMeta = listPreview.length ? ` · LIST=${listPreview.join(' | ').slice(0, 240)}` : '';
          addFinding(
            {
              type: 'endpoint',
              prio: 'high',
              score: 72,
              value: `FTP anonymous permitido @ ${ip}:${ftpPort}`,
              meta: `USER anonymous · PASS anonymous@ · ${fr.summary || '230'}${listMeta}`,
              url: `ftp://${ip}:${ftpPort}/`,
            },
            'endpoints',
          );
          log(`FTP anonymous: SUCESSO em ${ip}:${ftpPort} — ${fr.summary || '230'}`, 'success');
          if (listPreview.length) {
            log(`FTP LIST ${ip}:${ftpPort}: ${listPreview.join(' | ')}`, 'info');
          } else {
            log(`FTP LIST ${ip}:${ftpPort}: sem listagem (permissão/servidor)`, 'info');
          }
          intel(`FTP ANONYMOUS OK @ ${ip}:${ftpPort} — listar: ftp ${ip} ${ftpPort} (user anonymous, pass anonymous@)`);
        } else {
          const hint = fr.summary || fr.error || `código ${fr.code ?? '—'}`;
          log(`FTP anonymous: sem acesso em ${ip}:${ftpPort} — ${hint}`, 'info');
          if (fr.error) ftpAnonymousSummary.errors.push(`${ftpPort}:${fr.error}`);
        }
      } catch (e) {
        const msg = e?.message || String(e);
        ftpAnonymousSummary.errors.push(`${ftpPort}:${msg}`);
        log(`FTP probe ${ip}:${ftpPort}: ${msg}`, 'warn');
      }
    }
  }

  /** @type {{ tried: number; okPorts: number[]; errors: string[] }} */
  const sshSummary = { tried: 0, okPorts: [], errors: [] };
  const sshPorts = sshPortsFromNmap(nmapRows);
  if (sshPorts.length) {
    log(`SSH detetado (porta(s) ${sshPorts.join(', ')}) — a recolher banner + hostkeys...`, 'info');
    for (const sshPort of sshPorts) {
      sshSummary.tried += 1;
      try {
        const sr = await probeSshService({ host: ip, port: sshPort, timeoutMs: 12000 });
        const keyHint = Array.isArray(sr.hostKeys) ? sr.hostKeys.slice(0, 2).join(' | ').slice(0, 220) : '';
        if (sr.ok) {
          sshSummary.okPorts.push(sshPort);
          const meta = [
            sr.banner ? `banner=${sr.banner}` : null,
            keyHint ? `keyscan=${keyHint}` : null,
          ]
            .filter(Boolean)
            .join(' · ');
          addFinding(
            {
              type: 'endpoint',
              prio: 'med',
              score: 64,
              value: `SSH ativo @ ${ip}:${sshPort}`,
              meta: meta || 'SSH respondeu (banner/keyscan)',
              url: null,
            },
            'endpoints',
          );
          log(`SSH probe ${ip}:${sshPort}: ${sr.banner || 'banner ausente'}${keyHint ? ' · hostkey recolhida' : ''}`, 'success');
          intel(`SSH ${ip}:${sshPort} — ${sr.banner || 'banner não exposto'}${keyHint ? ' · keyscan OK' : ''}`);
        } else {
          const err = sr.bannerError || sr.keyscanError || 'sem resposta';
          sshSummary.errors.push(`${sshPort}:${err}`);
          log(`SSH probe ${ip}:${sshPort}: ${err}`, 'info');
        }
      } catch (e) {
        const msg = e?.message || String(e);
        sshSummary.errors.push(`${sshPort}:${msg}`);
        log(`SSH probe ${ip}:${sshPort}: ${msg}`, 'warn');
      }
    }
  }

  /** @type {{ tried: number; okPorts: number[]; errors: string[] }} */
  const mysqlSummary = { tried: 0, okPorts: [], errors: [] };
  const mysqlPorts = mysqlPortsFromNmap(nmapRows);
  if (mysqlPorts.length) {
    log(`MySQL detetado (porta(s) ${mysqlPorts.join(', ')}) — a recolher handshake/version...`, 'info');
    for (const mysqlPort of mysqlPorts) {
      mysqlSummary.tried += 1;
      try {
        const mr = await probeMysqlService({ host: ip, port: mysqlPort, timeoutMs: 12000 });
        if (mr.ok) {
          mysqlSummary.okPorts.push(mysqlPort);
          const meta = [
            mr.serverVersion ? `version=${mr.serverVersion}` : null,
            Number.isFinite(mr.protocolVersion) ? `proto=${mr.protocolVersion}` : null,
            Number.isFinite(mr.connectionId) ? `connId=${mr.connectionId}` : null,
          ]
            .filter(Boolean)
            .join(' · ');
          addFinding(
            {
              type: 'endpoint',
              prio: 'med',
              score: 66,
              value: `MySQL ativo @ ${ip}:${mysqlPort}`,
              meta: meta || 'handshake MySQL recebido',
              url: null,
            },
            'endpoints',
          );
          log(`MySQL probe ${ip}:${mysqlPort}: ${mr.serverVersion || 'handshake OK'}`, 'success');
          intel(`MySQL ${ip}:${mysqlPort} — ${mr.serverVersion || 'versão não exposta'}`);
        } else {
          mysqlSummary.errors.push(`${mysqlPort}:${mr.error || 'sem handshake'}`);
          log(`MySQL probe ${ip}:${mysqlPort}: ${mr.error || 'sem handshake'}`, 'info');
        }
      } catch (e) {
        const msg = e?.message || String(e);
        mysqlSummary.errors.push(`${mysqlPort}:${msg}`);
        log(`MySQL probe ${ip}:${mysqlPort}: ${msg}`, 'warn');
      }
    }
  }

  // Playbook inicial (pós-nmap)
  try {
    const sug = buildCtfPlaybookSuggestions({ ip, findings });
    for (const s of sug.slice(0, 6)) {
      intel(`PLAYBOOK (${String(s.prio).toUpperCase()}): ${s.title}`);
      for (const step of s.steps.slice(0, 6)) intel(`  - ${step}`);
    }
  } catch (e) {
    log(`playbook: ${e?.message || String(e)}`, 'warn');
  }

  pipe('subdomains', 'done');
  progress(28);

  // 3) UDP stage label (mapa para "rdap")
  pipe('rdap', 'active');
  if (udpScan) log('UDP scan ON: já incluído no nmap.', 'info');
  else log('UDP scan OFF: apenas TCP (top ports).', 'info');
  pipe('rdap', 'done');

  // 4) WEB PROBE (mapa para "alive")
  pipe('alive', 'active');
  progress(35);
  log('Probe HTTP/HTTPS com curl nas portas web candidatas...', 'info');
  const webResponses = await curlWebFromNmap({ ip, nmapRows, timeoutMs: 12000, maxBodyBytes: 250000, log });

  let robotsFetched = 0;
  try {
    const rb = await appendRobotsTxtResponses(webResponses, {
      ip,
      log,
      timeoutMs: 10000,
      maxBodyBytes: 128000,
    });
    robotsFetched = rb.fetched || 0;
  } catch (e) {
    log(`robots.txt: ${e?.message || String(e)}`, 'warn');
  }

  const countAfterInitialCurl = webResponses.length;

  for (const r of webResponses) {
    if (!r.status) continue;
    if (!r.bodyText && r.__via !== 'robots.txt') continue;
    const via = r.__via === 'robots.txt' ? ' · via=robots.txt' : '';
    addFinding(
      {
        type: 'tech',
        prio: 'low',
        score: 20,
        value: `HTTP ${r.status} @ ${r.url}`,
        meta: `tech=${(r.tech || []).slice(0, 5).join(' · ') || '—'}${via}`,
        url: r.url,
      },
      'endpoints',
    );
  }

  // Segue links no HTML (mesmo host que o IP), p.ex. index → noticias.php (flags em comentários / outras páginas)
  let linkPagesFetched = 0;
  try {
    log('Rastreio de links no HTML (href → curl no mesmo IP/host que resolve para o alvo)...', 'info');
    const linkRes = await expandWebResponsesWithLinkCrawl(webResponses, {
      ip,
      log,
      timeoutMs: 15000,
      maxBodyBytes: 350000,
    });
    linkPagesFetched = linkRes.fetched || 0;
    if (linkPagesFetched) log(`HTML links: ${linkPagesFetched} página(s) extra com curl`, 'success');
    else log('HTML links: nenhum URL novo. Ver logs “[http] link do HTML”.', 'info');
  } catch (e) {
    log(`HTML link crawl: ${e?.message || String(e)}`, 'warn');
  }

  for (let i = countAfterInitialCurl; i < webResponses.length; i += 1) {
    const r = webResponses[i];
    if (!r || !r.status || !r.bodyText) continue;
    addFinding(
      {
        type: 'tech',
        prio: 'low',
        score: 20,
        value: `HTTP ${r.status} @ ${r.url}`,
        meta: `tech=${(r.tech || []).slice(0, 5).join(' · ') || '—'} · via=html-link`,
        url: r.url,
      },
      'endpoints',
    );
  }

  // Playbook atualizado (pós-web probe)
  try {
    const sug = buildCtfPlaybookSuggestions({ ip, findings });
    for (const s of sug.slice(0, 8)) {
      intel(`PLAYBOOK (${String(s.prio).toUpperCase()}): ${s.title}`);
      for (const step of s.steps.slice(0, 6)) intel(`  - ${step}`);
    }
  } catch (e) {
    log(`playbook: ${e?.message || String(e)}`, 'warn');
  }

  // Se a flag já aparecer em headers/body do primeiro probe,
  // emitimos imediatamente e continuamos o pipeline.
  ingestFlagFindingsFromWebResponses({
    webResponses,
    platformId,
    foundFlagSet,
    addFinding,
    log,
    maxTextLen: 500_000,
  });
  pipe('alive', 'done');
  progress(52);

  // 5) SURFACE / DIR ENUM (mapa para "surface")
  pipe('surface', 'active');
  progress(58);
  log('Enumeração de diretórios (ffuf + gobuster + dirb, em paralelo) nas seeds web…', 'info');

  const urlsSeedUniq = [];
  const seedSeen = new Set();
  for (const r of webResponses) {
    if (!r || !r.status || !r.url) continue;
    const k = String(r.url).split('#')[0];
    if (seedSeen.has(k)) continue;
    seedSeen.add(k);
    urlsSeedUniq.push(k);
    if (urlsSeedUniq.length >= 4) break;
  }

  const discoveredUrls = new Set();
  /** @type {Record<string, { n: number; err?: string }>} */
  const dirEnumToolsAgg = {};
  for (const baseUrl of urlsSeedUniq) {
    const u = String(baseUrl || '');
    if (!u) continue;
    const enumRes = await dirEnumAllTools({ baseUrl: u, log, timeoutMs: 240000, maxMergedUrls: 120 });
    if (enumRes?.tools && typeof enumRes.tools === 'object') {
      for (const [k, v] of Object.entries(enumRes.tools)) {
        if (!dirEnumToolsAgg[k]) dirEnumToolsAgg[k] = { n: 0 };
        dirEnumToolsAgg[k].n += Number(v?.n) || 0;
        if (v?.err) dirEnumToolsAgg[k].err = v.err;
      }
    }
    if (!Array.isArray(enumRes.urls)) continue;
    for (const d of enumRes.urls) discoveredUrls.add(d);
  }

  // curl nas URLs descobertas
  let pagesFetched = 0;
  for (const u of [...discoveredUrls].slice(0, 50)) {
    try {
      // reaproveita curlWebFromNmap? aqui só precisamos de um curl simples.
      // import local pra evitar overhead:
      const { curlWebSingle } = await import('./web-curl-single.js');
      const r = await curlWebSingle({ url: u, timeoutMs: 12000, maxBodyBytes: 250000 });
      pagesFetched++;
      // salva findings “endpoint-like” (não é essencial pro flag scan)
      if (r.status) {
        addFinding(
          {
            type: 'endpoint',
            prio: 'low',
            score: 44,
            value: u,
            meta: `curl status=${r.status}`,
            url: u,
          },
          'endpoints',
        );
      }
      // guarda evidência agregada pra scan de flags
      r.__evidence = { headersText: r.headersText, bodyText: r.bodyText };
      webResponses.push(r);
    } catch {
      // ignore
    }
  }

  log(`Páginas extra (curl das dirs): ${pagesFetched}`, pagesFetched ? 'success' : 'info');
  pipe('surface', 'done');
  progress(70);

  // 6) URLS / DISCOVERY — links HTML já cobertos em “alive”; robots/sitemap podem ser acrescentados depois
  pipe('urls', 'active');
  log('Discovery URLs: robots.txt + links HTML + ffuf/gobuster/dirb.', 'info');
  pipe('urls', 'done');

  // 7) PARAM DISCOVERY / FLAG SCAN (mapa para "params")
  pipe('params', 'active');
  progress(78);

  /** @type {{ attempts: number; hits: number }} */
  const lfiSummary = { attempts: 0, hits: 0 };
  if (Array.isArray(modules) && modules.includes('lfiProbe')) {
    try {
      const lfiSeedUrls = [];
      for (const r of webResponses || []) {
        if (!r?.url) continue;
        lfiSeedUrls.push(String(r.url));
        if (r.finalUrl) lfiSeedUrls.push(String(r.finalUrl));
      }
      const lfi = await runLfiPasswdProbe({
        urls: lfiSeedUrls,
        log,
        maxAttempts: 24,
        timeoutMs: 12000,
        maxBodyBytes: 180000,
      });
      lfiSummary.attempts = Number(lfi?.attempts || 0);
      const hits = Array.isArray(lfi?.hits) ? lfi.hits : [];
      lfiSummary.hits = hits.length;
      for (const h of hits) {
        addFinding(
          {
            type: 'param',
            prio: 'high',
            score: 94,
            value: `Possível LFI via ${h.param} em ${h.baseUrl}`,
            meta: `payload=${h.payload} · status=${h.status} · evidência=${h.evidence}`,
            url: h.testUrl || h.baseUrl,
          },
          'params',
        );
        log(`LFI provável: ${h.testUrl} (${h.evidence})`, 'success');
        if (h.snippet) intel(`LFI snippet: ${h.snippet}`);
      }
      if (!hits.length) {
        log(`LFI probe: sem evidência de /etc/passwd (tentativas=${lfiSummary.attempts})`, 'info');
      }
    } catch (e) {
      log(`LFI probe: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('LFI probe: OFF (ative em Modules)', 'info');
  }

  log('Scan de flags Solyd{...} e validação do formato (com base64/base32 decoding)...', 'info');

  ingestFlagFindingsFromWebResponses({
    webResponses,
    platformId,
    foundFlagSet,
    addFinding,
    log,
    maxTextLen: 900_000,
  });

  // stats “params” conta flags novas (deduplicadas)
  pipe('params', 'done');

  progress(92);

  // 8) JS / DECODER STAGE (mapa para "js") - já fizemos decoding; mantém visual coerente
  pipe('js', 'active');
  pipe('js', 'done');

  // 9) DORKS / FLAGS VALIDATION (mapa para "dorks")
  pipe('dorks', 'active');
  pipe('dorks', 'done');

  // 10) SECRETS / VECTORS (mapa para "secrets") - MVP sem exploração ativa automática
  pipe('secrets', 'active');
  log('Módulos de exploração (SQLi/LFI/XSS/PrivEsc) ainda não estão no MVP — foco em Recon + Flags.', 'warn');
  pipe('secrets', 'done');

  // 11) KALI / EXPLOIT (skip)
  pipe('kali', 'skip');

  // 12) SCORE (final)
  pipe('score', 'active');
  progress(100);
  pipe('score', 'done');

  const modulesForDb = [
    '__ghostctf__',
    `platform:${platformId}`,
    udpScan ? 'udpScan' : 'udpScan:off',
    tcpAllPorts ? 'tcpAllPorts' : 'tcpAllPorts:off',
    ...modules,
  ];

  const corr = {
    ip,
    platformId,
    udpScan,
    tcpAllPorts,
    pagesFetched: (pagesFetched || 0) + (linkPagesFetched || 0) + (robotsFetched || 0),
    linkPagesFetched: linkPagesFetched || 0,
    robotsFetched: robotsFetched || 0,
    flagsFound: foundFlagSet.size,
    dirEnumTools: dirEnumToolsAgg,
    ftpAnonymous: {
      tried: ftpAnonymousSummary.tried,
      okPorts: ftpAnonymousSummary.successPorts,
      errors: ftpAnonymousSummary.errors,
    },
    sshProbe: {
      tried: sshSummary.tried,
      okPorts: sshSummary.okPorts,
      errors: sshSummary.errors,
    },
    mysqlProbe: {
      tried: mysqlSummary.tried,
      okPorts: mysqlSummary.okPorts,
      errors: mysqlSummary.errors,
    },
    lfiProbe: {
      attempts: lfiSummary.attempts,
      hits: lfiSummary.hits,
    },
  };

  let saved = null;
  let runId = null;
  let intelMerge = null;
  try {
    saved = await saveRun({
      target: ip,
      exactMatch: false,
      modules: modulesForDb,
      stats: { ...stats },
      findings,
      correlation: corr,
    });
    if (saved != null) {
      runId = saved.runId;
      intelMerge = saved.intelMerge;
      log(`GhostCTF salvo — run #${runId}`, 'success');
    }
  } catch (e) {
    log(`Erro ao salvar no DB: ${e?.message || String(e)}`, 'warn');
  }

  emit({
    type: 'done',
    target: ip,
    platform: platformId,
    findings,
    stats,
    correlation: corr,
    runId,
    intelMerge,
    storage: null,
  });

  return { runId, findings, stats, intelMerge, correlation: corr };
}

function safeToString(v) {
  return v == null ? '' : String(v);
}

/**
 * Agrega headers/bodies das respostas web e extrai flags (com decoding).
 * Usa array garantido — evita ReferenceError se detectFlagsWithDecoding falhar.
 */
function ingestFlagFindingsFromWebResponses({
  webResponses,
  platformId,
  foundFlagSet,
  addFinding,
  log,
  maxTextLen = 900_000,
}) {
  const evidenceChunks = [];
  for (const r of webResponses || []) {
    if (!r) continue;
    const ht = safeToString(r.headersText || '');
    const bt = safeToString(r.bodyText || '');
    if (ht) evidenceChunks.push(ht);
    if (bt) evidenceChunks.push(bt);
  }
  const rawText = evidenceChunks.join('\n').slice(0, maxTextLen);
  let flagHits = [];
  try {
    const hits = detectFlagsWithDecoding({ rawText, platformId });
    flagHits = Array.isArray(hits) ? hits : [];
  } catch (e) {
    if (typeof log === 'function') log(`scan de flags: ${e?.message || String(e)}`, 'warn');
    flagHits = [];
  }
  for (const hit of flagHits) {
    if (!hit || !hit.flag) continue;
    if (foundFlagSet.has(hit.flag)) continue;
    foundFlagSet.add(hit.flag);
    addFinding(
      {
        type: 'flag',
        prio: 'high',
        score: 99,
        value: hit.flag,
        meta: `platform=${platformId}; evidence=${hit.evidence || 'unknown'}; decodedFrom=${hit.decodedFrom || ''}`,
        url: null,
      },
      'flags',
    );
  }
}

