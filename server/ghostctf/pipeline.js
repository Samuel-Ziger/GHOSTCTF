import { scanIpPorts } from './nmap-scan.js';
import { curlWebFromNmap } from './web-curl.js';
import { ffufDirEnum } from './dir-enum.js';
import { detectFlagsWithDecoding } from './flag-detector.js';
import { buildCtfPlaybookSuggestions } from './playbook.js';
import { searchExploitDbFromNmap } from './exploitdb.js';
import { expandWebResponsesWithLinkCrawl } from './html-links.js';
import { appendRobotsTxtResponses } from './robots-probe.js';

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

    const line = `${proto}/${port} ${r.name || ''} ${r.product || ''} ${r.version || ''}`.trim();
    addFinding(
      {
        type: 'nmap',
        prio: 'med',
        score: 55,
        value: line,
        meta: `${r.extrainfo || 'nmap'} (host=${r.host || ip})`,
        url: `http://${ip}:${port}/`,
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
    const linkRes = await expandWebResponsesWithLinkCrawl(webResponses, {
      ip,
      log,
      maxDepth: 2,
      maxNewFetches: 40,
      timeoutMs: 12000,
      maxBodyBytes: 250000,
    });
    linkPagesFetched = linkRes.fetched || 0;
    if (linkPagesFetched) log(`HTML links: ${linkPagesFetched} página(s) extra com curl`, 'success');
    else log('HTML links: nenhum link novo no mesmo host (ou limite 0)', 'info');
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
  {
    const evidenceChunks = [];
    for (const r of webResponses || []) {
      if (!r) continue;
      const ht = safeToString(r.headersText || '');
      const bt = safeToString(r.bodyText || '');
      if (ht) evidenceChunks.push(ht);
      if (bt) evidenceChunks.push(bt);
    }
    const rawText = evidenceChunks.join('\n').slice(0, 500000);
    const flagHits = detectFlagsWithDecoding({ rawText, platformId });
    for (const hit of flagHits) {
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
  pipe('alive', 'done');
  progress(52);

  // 5) SURFACE / DIR ENUM (mapa para "surface")
  pipe('surface', 'active');
  progress(58);
  log('Enumeração de diretórios (ffuf) em URLs web encontradas...', 'info');

  const urlsSeed = webResponses
    .filter((r) => r && r.status && r.url)
    .map((r) => r.url)
    .slice(0, 3);

  const discoveredUrls = new Set();
  for (const baseUrl of urlsSeed) {
    const u = String(baseUrl || '');
    if (!u) continue;
    const enumRes = await ffufDirEnum({ baseUrl: u, log, timeoutMs: 90000 });
    if (!enumRes?.ok || !Array.isArray(enumRes.urls)) continue;
    for (const d of enumRes.urls) discoveredUrls.add(d);
  }

  // curl nas URLs descobertas
  let pagesFetched = 0;
  for (const u of [...discoveredUrls].slice(0, 25)) {
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
  log('Discovery URLs: robots.txt (probe inicial) + links HTML + ffuf.', 'info');
  pipe('urls', 'done');

  // 7) PARAM DISCOVERY / FLAG SCAN (mapa para "params")
  pipe('params', 'active');
  progress(78);
  log('Scan de flags Solyd{...} e validação do formato (com base64/base32 decoding)...', 'info');

  {
    const evidenceChunks = [];
    for (const r of webResponses || []) {
      if (!r) continue;
      const ht = safeToString(r.headersText || '');
      const bt = safeToString(r.bodyText || '');
      if (ht) evidenceChunks.push(ht);
      if (bt) evidenceChunks.push(bt);
    }

    const rawText = evidenceChunks.join('\n').slice(0, 900000);
    const flagHits = detectFlagsWithDecoding({ rawText, platformId });
    for (const hit of flagHits) {
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

