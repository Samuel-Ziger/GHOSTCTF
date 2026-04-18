import 'dotenv/config';
import express from 'express';
import { createServer } from 'node:http';
import path from 'path';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'url';
import { fetchCrtShSubdomains } from './modules/subdomains.js';
import { resolves } from './modules/dns.js';
import { probeHttp, mapPool } from './modules/probe.js';
import { analyzeSecurityHeaders } from './modules/security-headers.js';
import { peekTlsCertificate } from './modules/tls-cert.js';
import { crawlRobotsAndSitemapsForOrigin, hostnameInScope } from './modules/robots-sitemap.js';
import { fetchCommonCrawlUrls } from './modules/commoncrawl.js';
import { fetchRdapSummary } from './modules/rdap.js';
import { fetchVirustotalSubdomains } from './modules/virustotal.js';
import { compareRuns } from './modules/db-compare.js';
import { postReconWebhook, postAiReportWebhook } from './modules/webhook-notify.js';
import {
  runDualAiReports,
  pickAiReportForWebhook,
  probeLmStudioConnection,
  normalizeOpenrouterOnlyFlag,
  aiKeysConfigured,
  ghostctfAiPolicyDisableGemini,
} from './modules/ai-dual-report.js';
import { fetchWaybackUrls, filterInterestingUrls, extractJsUrls } from './modules/wayback.js';
import { extractParamsFromUrls } from './modules/params.js';
import { analyzeJsUrl } from './modules/js-analyzer.js';
import { scanSecrets } from './modules/secrets.js';
import { githubCodeSearch } from './modules/github.js';
import { buildDorks } from './modules/dorks.js';
import { scoreEndpointPath, scoreParamName } from './modules/scoring.js';
import { correlate } from './modules/correlation.js';
import { suggestVectors, buildExploitChecklist } from './modules/intelligence.js';
import { applyPrioritizationV2, topHighProbability } from './modules/prioritization.js';
import { extractCveHintsFromTechStrings } from './modules/cve-hints.js';
import { fetchDnsEnrichment } from './modules/dns-enrichment.js';
import { fetchWellKnownSecurityTxt, fetchWellKnownOpenIdConfiguration } from './modules/wellknown.js';
import { limits, reconRateLimitConfig } from './config.js';
import {
  saveRun,
  listRuns,
  getRunById,
  listIntelForTarget,
  intelCountForTarget,
  listKnowledge,
  storageLabel,
  listManualValidationsForTarget,
  upsertManualValidation,
  deleteManualValidation,
  listBrainCategories,
  createBrainCategory,
  deleteBrainCategory,
  syncBrainHistoricoFalhas,
  updateBrainCategoryDescription,
  upsertBrainLink,
  getBrainCategoryById,
  listBrainLinksForCategory,
  listBrainLinksForFinding,
  deleteBrainLink,
} from './modules/db.js';
import { googleCseSearch, urlMatchesTarget } from './modules/google-cse.js';
import { getKaliCapabilities, runKaliAggressiveScan } from './modules/kali-scan.js';
import { enumerateSubdomainsWithSubfinder, enumerateSubdomainsWithAmass } from './modules/kali-subdomain-tools.js';
import { runGhostCtfPipeline } from './ghostctf/pipeline.js';
import { ghostctfHttpCookieAls } from './ghostctf/http-cookie-context.js';
import { getPlatform } from './ghostctf/platforms.js';
import { attachShellWebSocket } from './ghostctf/shell-ws.js';
import { makeGhostctfPayload, saveGhostctfPayloadToProject } from './ghostctf/payload-kit.js';
import { runMsfvenomWandenreichBuild } from './ghostctf/msfvenom-wandenreich.js';
import { saveHistoricoGhostMarkdown } from './ghostctf/historico-ghost-save.js';
import { resolveNgrokTcpForLocalPort, startNgrokTcpAndResolve } from './ghostctf/ngrok-local.js';
import { runPipeline } from './recon-pipeline.js';
import { prependExtraPathToEnvPath } from './modules/tool-path.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const reconRlHits = new Map();

function allowReconRequest(req) {
  const { max, windowMs } = reconRateLimitConfig();
  if (max <= 0) return true;
  const ip = String(
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '_',
  );
  const now = Date.now();
  const arr = (reconRlHits.get(ip) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) return false;
  arr.push(now);
  reconRlHits.set(ip, arr);
  return true;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

const app = express();

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  next();
});

app.use(express.json({ limit: '5mb' }));

function isValidDomain(d) {
  return /^[a-zA-Z0-9][a-zA-Z0-9-.]+\.[a-zA-Z]{2,}$/.test(d);
}

function normDomain(d) {
  return d.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
}

function isValidIpv4(ip) {
  return /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(
    String(ip || '').trim(),
  );
}

function normIp(ip) {
  return String(ip || '').trim();
}

app.post('/api/recon/stream', async (req, res) => {
  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('X-Accel-Buffering', 'no');

  const send = (obj) => {
    res.write(`${JSON.stringify(obj)}\n`);
  };

  if (!allowReconRequest(req)) {
    send({ type: 'error', message: 'Rate limit — aguarde antes de novo recon' });
    res.end();
    return;
  }

  const domainRaw = req.body?.domain;
  const modules = Array.isArray(req.body?.modules) ? req.body.modules : [];
  const exactMatch = Boolean(req.body?.exactMatch);
  const kaliMode = Boolean(req.body?.kaliMode);
  const profile = String(req.body?.profile || 'standard')
    .trim()
    .toLowerCase();
  const auth =
    req.body?.auth && typeof req.body.auth === 'object'
      ? {
          headers: req.body.auth.headers && typeof req.body.auth.headers === 'object' ? req.body.auth.headers : {},
          cookie: req.body.auth.cookie ? String(req.body.auth.cookie) : '',
        }
      : null;

  if (!domainRaw || !isValidDomain(normDomain(domainRaw))) {
    send({ type: 'error', message: 'Domínio inválido' });
    res.end();
    return;
  }

  const domain = normDomain(domainRaw);

  const extraPathRaw = typeof req.body?.extraPath === 'string' ? req.body.extraPath : '';
  let savedEnvPath = null;
  if (extraPathRaw.trim()) {
    savedEnvPath = process.env.PATH;
    process.env.PATH = prependExtraPathToEnvPath(extraPathRaw, savedEnvPath);
  }

  try {
    await runPipeline({
      domain,
      exactMatch,
      modules,
      emit: send,
      kaliMode,
      auth,
      profile,
      outOfScope: req.body?.outOfScope,
      projectName: req.body?.projectName,
      autoAiReports: Boolean(req.body?.autoAiReports),
      aiProviderMode: String(req.body?.aiProviderMode || 'auto'),
      aiUseOpenrouter: req.body?.aiUseOpenrouter !== false,
      aiOpenrouterOnly: normalizeOpenrouterOnlyFlag(req.body?.aiOpenrouterOnly),
      aiPrimaryCloud:
        typeof req.body?.aiPrimaryCloud === 'string'
          ? req.body.aiPrimaryCloud
          : typeof req.body?.aiPrimaryReport === 'string'
            ? req.body.aiPrimaryReport
            : null,
      manualGithubReposRaw: req.body?.manualGithubRepos ?? req.body?.shannonGithubRepos ?? null,
      bountyContext:
        req.body?.bountyContext && typeof req.body.bountyContext === 'object' ? req.body.bountyContext : null,
    });
  } catch (e) {
    send({ type: 'error', message: e?.message || String(e) });
  } finally {
    if (savedEnvPath !== null) process.env.PATH = savedEnvPath;
  }
  res.end();
});

app.post('/api/ghostctf/stream', async (req, res) => {
  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('X-Accel-Buffering', 'no');

  const send = (obj) => {
    res.write(`${JSON.stringify(obj)}\n`);
  };

  if (!allowReconRequest(req)) {
    send({ type: 'error', message: 'Rate limit — aguarde antes de novo run GhostCTF' });
    res.end();
    return;
  }

  const ipRaw = req.body?.ip;
  const platform = req.body?.platform || 'solyd';
  const modules = Array.isArray(req.body?.modules) ? req.body.modules : [];
  const extraHostsRaw = req.body?.extraHosts;
  const extraHosts = Array.isArray(extraHostsRaw)
    ? extraHostsRaw.map((s) => String(s).trim()).filter(Boolean)
    : typeof extraHostsRaw === 'string'
      ? extraHostsRaw.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
      : [];
  const udpScan = Boolean(req.body?.udpScan);
  const tcpAllPorts = Boolean(req.body?.tcpAllPorts);
  const hostsOnlyWeb = Boolean(req.body?.hostsOnlyWeb);

  const smRaw = req.body?.secondaryMysqlHosts;
  const secondaryMysqlHosts = (
    Array.isArray(smRaw)
      ? smRaw.map((s) => normIp(s))
      : typeof smRaw === 'string'
        ? smRaw.split(/[\n,]+/).map((s) => normIp(s))
        : []
  )
    .filter((h) => isValidIpv4(h))
    .slice(0, 8);

  const vhostBaseDomain = String(req.body?.vhostBaseDomain || '')
    .trim()
    .replace(/^https?:\/\//i, '')
    .split('/')[0];
  const vhostFuzzExtraPrefixes = String(req.body?.vhostFuzzExtraPrefixes || '').trim();

  const sshBruteUsers = String(req.body?.sshBruteUsers || '').trim();
  const sshBruteWordlistPath = String(req.body?.sshBruteWordlistPath || '').trim();
  const sshBruteMaxPasswords = Math.min(500, Math.max(20, Number(req.body?.sshBruteMaxPasswords) || 150));
  const sshBruteAutoHydra = Boolean(req.body?.sshBruteAutoHydra);
  const sshBruteAutoTimeoutMs = Math.min(
    7_200_000,
    Math.max(300_000, Number(req.body?.sshBruteAutoTimeoutMs) || 1_800_000),
  );
  const sshBruteSolydWordlists = Boolean(req.body?.sshBruteSolydWordlists);

  const hydraWpBruteUsers = String(req.body?.hydraWpBruteUsers || '').trim();
  const hydraWpBruteWordlistPath = String(req.body?.hydraWpBruteWordlistPath || '').trim();
  const hydraWpBruteMaxPasswords = Math.min(500, Math.max(20, Number(req.body?.hydraWpBruteMaxPasswords) || 150));

  const langflowHostHeader = String(req.body?.langflowHostHeader || '').trim();
  const langflowTryAllOrigins = Boolean(req.body?.langflowTryAllOrigins);
  const langflowVerticesShell = Boolean(req.body?.langflowVerticesShell);
  const langflowNgrokHost = String(req.body?.langflowNgrokHost || '').trim();
  const langflowNgrokPort = Number(req.body?.langflowNgrokPort) || 0;
  const langflowBuildFlowId = String(req.body?.langflowBuildFlowId || '').trim();
  const langflowAlsoTryFlagPath = Boolean(req.body?.langflowAlsoTryFlagPath);

  if (!ipRaw || !isValidIpv4(normIp(ipRaw))) {
    send({ type: 'error', message: 'IP inválido (use IPv4)' });
    res.end();
    return;
  }

  const ip = normIp(ipRaw);
  const httpSessionCookie = String(req.body?.httpSessionCookie || '').trim();

  try {
    await ghostctfHttpCookieAls.run(httpSessionCookie ? { cookie: httpSessionCookie } : {}, () =>
      runGhostCtfPipeline({
        ip,
        platformId: platform,
        modules,
        extraHosts,
        hostsOnlyWeb,
        udpScan,
        tcpAllPorts,
        secondaryMysqlHosts,
        vhostBaseDomain,
        vhostFuzzExtraPrefixes,
        sshBruteUsers,
        sshBruteWordlistPath,
        sshBruteMaxPasswords,
        sshBruteAutoHydra,
        sshBruteAutoTimeoutMs,
        sshBruteSolydWordlists,
        hydraWpBruteUsers,
        hydraWpBruteWordlistPath,
        hydraWpBruteMaxPasswords,
        langflowHostHeader,
        langflowTryAllOrigins,
        langflowVerticesShell,
        langflowNgrokHost,
        langflowNgrokPort,
        langflowBuildFlowId,
        langflowAlsoTryFlagPath,
        emit: send,
        saveRun,
      }),
    );
  } catch (e) {
    send({ type: 'error', message: e?.message || String(e) });
  }

  res.end();
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'ghostctf' });
});

app.get('/api/capabilities', async (_req, res) => {
  try {
    const cap = await getKaliCapabilities();
    const keys = aiKeysConfigured();
    const disableGemini = ghostctfAiPolicyDisableGemini();
    res.json({
      ...cap,
      ai: {
        gemini: keys.gemini,
        openrouter: keys.openrouter,
        claude: keys.claude,
        lmstudio: keys.lmstudio,
        any: keys.any,
        /** Relatórios por IA no servidor GHOSTCTF não chamam Gemini quando `true`. */
        openrouter_only_cloud: disableGemini,
      },
    });
  } catch (e) {
    res.status(500).json({ kali: false, message: e.message, tools: {} });
  }
});

app.get('/api/csrf-token', (_req, res) => {
  res.json({ ok: true, token: 'ghostctf-local' });
});

function decodeBase64Maybe(s) {
  let x = String(s ?? '').trim();
  if (!x) return null;
  x = x.replace(/-/g, '+').replace(/_/g, '/');
  const mod = x.length % 4;
  if (mod === 2) x += '==';
  else if (mod === 3) x += '=';
  else if (mod === 1) return null;
  try {
    const out = Buffer.from(x, 'base64').toString('utf8');
    return out && out.length >= 1 ? out : null;
  } catch {
    return null;
  }
}

function decodeBase32Maybe(s) {
  let x = String(s ?? '').trim().replace(/=+$/g, '');
  if (!x) return null;
  x = x.toUpperCase();
  if (!/^[A-Z2-7]+$/.test(x)) return null;
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of x) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) return null;
    bits += idx.toString(2).padStart(5, '0');
  }
  let out = '';
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    out += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
  }
  if (!out) return null;
  try {
    return decodeURIComponent(escape(out));
  } catch {
    return out;
  }
}

function extractFlagsByPlatform(text, platformId) {
  const platform = getPlatform(platformId);
  if (!platform) return [];
  const t = String(text ?? '');
  const re = new RegExp(platform.flagRegex.source, platform.flagRegex.flags);
  const out = [];
  let m;
  while ((m = re.exec(t)) !== null) {
    const f = m[0];
    if (platform.validateFlag(f)) out.push(f);
    if (out.length >= 25) break;
  }
  return [...new Set(out)];
}

app.post('/api/ghostctf/decode', async (req, res) => {
  const input = String(req.body?.input ?? '').trim();
  const platformId = String(req.body?.platform || 'solyd').trim().toLowerCase();
  if (!input) {
    res.status(400).json({ ok: false, error: 'input vazio' });
    return;
  }

  const b64 = decodeBase64Maybe(input);
  const b32 = decodeBase32Maybe(input);
  const candidates = [];
  if (b64 != null) candidates.push({ kind: 'base64', decoded: b64 });
  if (b32 != null) candidates.push({ kind: 'base32', decoded: b32 });

  let detected = 'unknown';
  if (b64 != null && b32 == null) detected = 'base64';
  else if (b32 != null && b64 == null) detected = 'base32';
  else if (b64 != null && b32 != null) detected = 'ambiguous';

  const flags = [];
  for (const c of candidates) {
    const hits = extractFlagsByPlatform(c.decoded, platformId);
    for (const h of hits) flags.push({ flag: h, source: c.kind });
  }
  const uniq = [];
  const seen = new Set();
  for (const f of flags) {
    if (seen.has(f.flag)) continue;
    seen.add(f.flag);
    uniq.push(f);
  }

  res.json({
    ok: true,
    detected,
    candidates: candidates.map((c) => ({
      kind: c.kind,
      decoded: c.decoded.slice(0, 4000),
    })),
    flags: uniq,
  });
});

app.post('/api/ghostctf/hash', async (req, res) => {
  const input = String(req.body?.input ?? '');
  if (!input.trim()) {
    res.status(400).json({ ok: false, error: 'input vazio' });
    return;
  }
  const text = input;
  const trimmed = text.trim();
  const lower = trimmed.toLowerCase();

  const md5 = crypto.createHash('md5').update(text, 'utf8').digest('hex');
  const sha1 = crypto.createHash('sha1').update(text, 'utf8').digest('hex');
  const sha256 = crypto.createHash('sha256').update(text, 'utf8').digest('hex');

  let detected = 'texto';
  if (/^[a-f0-9]{32}$/.test(lower)) detected = 'hash-md5';
  else if (/^[a-f0-9]{40}$/.test(lower)) detected = 'hash-sha1';
  else if (/^[a-f0-9]{64}$/.test(lower)) detected = 'hash-sha256';

  res.json({
    ok: true,
    detected,
    inputLength: text.length,
    hashes: { md5, sha1, sha256 },
  });
});

/** Payloads mínimos para CTF (vários formatos) — upload manual no alvo; só em ambiente autorizado. */
app.post('/api/ghostctf/payload-file', (req, res) => {
  const kind = String(req.body?.kind || '').trim();
  const lhostRaw = String(req.body?.lhost || '').trim();
  const lportNum = Number(req.body?.lport);
  const r = makeGhostctfPayload(kind, lhostRaw, lportNum);
  if (!r.ok) {
    res.status(r.status).json({ ok: false, error: r.error });
    return;
  }
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${r.filename}"`);
  res.send(r.body);
});

/** Grava o mesmo payload em <raiz do projeto>/payloads/ (pasta criada automaticamente). */
app.post('/api/ghostctf/payload-save', async (req, res) => {
  try {
    const kind = String(req.body?.kind || '').trim();
    const lhostRaw = String(req.body?.lhost || '').trim();
    const lportNum = Number(req.body?.lport);
    const out = await saveGhostctfPayloadToProject(kind, lhostRaw, lportNum);
    if (!out.ok) {
      res.status(out.status).json({ ok: false, error: out.error });
      return;
    }
    res.json({
      ok: true,
      relativePath: out.relativePath,
      absolutePath: out.absolutePath,
      filename: out.filename,
      lport: out.lport,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

/** Grava relatório Markdown do recon em historicos/historicosGhost/<nome>/recon_<iso>.md */
app.post('/api/ghostctf/historico-ghost-md', async (req, res) => {
  try {
    const folderName = req.body?.folderName;
    const markdown = req.body?.markdown;
    const out = await saveHistoricoGhostMarkdown(folderName, markdown);
    if (!out.ok) {
      res.status(out.status).json({ ok: false, error: out.error });
      return;
    }
    res.json({ ok: true, relativePath: out.relativePath, filename: out.filename });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

/** Wandenreich: gera payload com msfvenom no host (Kali) e grava em payloads/. */
app.post('/api/ghostctf/msfvenom-build', async (req, res) => {
  try {
    const preset = String(req.body?.preset || '').trim();
    const lhost = String(req.body?.lhost || '').trim();
    const lport = Number(req.body?.lport);
    const encoder = String(req.body?.encoder || '').trim();
    const iterations = Number(req.body?.iterations);
    const out = await runMsfvenomWandenreichBuild({
      preset,
      lhost,
      lport,
      encoder: encoder || undefined,
      iterations,
    });
    if (!out.ok) {
      res.status(out.status).json({ ok: false, error: out.error });
      return;
    }
    res.json({
      ok: true,
      relativePath: out.relativePath,
      filename: out.filename,
      preset: out.preset,
      encoder: out.encoder,
      iterations: out.iterations,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

/**
 * Ngrok: sempre HTTP 200 + JSON { ok, error? } para o browser não confundir com “rota em falta”.
 * Lê http://127.0.0.1:4040/api/tunnels — preenche LHOST/LPORT do payload com o endpoint público TCP.
 */
app.post('/api/ghostctf/ngrok-resolve', async (req, res) => {
  try {
    const localPort = Number(req.body?.localPort);
    const out = await resolveNgrokTcpForLocalPort(localPort);
    if (!out.ok) {
      res.json({ ok: false, error: out.error });
      return;
    }
    res.json({
      ok: true,
      ngrokHost: out.ngrokHost,
      ngrokPort: out.ngrokPort,
      publicUrl: out.publicUrl,
      localPort: out.localPort,
    });
  } catch (e) {
    res.json({ ok: false, error: e?.message || String(e) });
  }
});

/** Tenta `ngrok tcp <localPort>` em background e faz poll até o túnel aparecer na API local. */
app.post('/api/ghostctf/ngrok-tcp-start', async (req, res) => {
  try {
    const localPort = Number(req.body?.localPort);
    const out = await startNgrokTcpAndResolve(localPort);
    if (!out.ok) {
      res.json({ ok: false, error: out.error });
      return;
    }
    res.json({
      ok: true,
      ngrokHost: out.ngrokHost,
      ngrokPort: out.ngrokPort,
      publicUrl: out.publicUrl,
      localPort: out.localPort,
      started: Boolean(out.started),
    });
  } catch (e) {
    res.json({ ok: false, error: e?.message || String(e) });
  }
});

async function crackMd5WithWordlist({ targetHash, wordlistPath, maxLines = 300000 }) {
  return await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(wordlistPath, { encoding: 'utf8' });
    stream.on('error', (e) => reject(e));
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    let tried = 0;
    let found = null;

    rl.on('line', (line) => {
      if (found) return;
      tried += 1;
      const candidate = String(line ?? '');
      const digest = crypto.createHash('md5').update(candidate, 'utf8').digest('hex');
      if (digest === targetHash) {
        found = candidate;
        rl.close();
      } else if (tried >= maxLines) {
        rl.close();
      }
    });
    rl.on('close', () => resolve({ tried, found }));
  });
}

function runProc(cmd, args, timeoutMs = 90000) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let killed = false;
    const t = setTimeout(() => {
      killed = true;
      try {
        child.kill('SIGKILL');
      } catch {
        // ignore
      }
      reject(new Error(`${cmd} timeout (${timeoutMs}ms)`));
    }, timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => {
      clearTimeout(t);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(t);
      if (killed) return;
      resolve({
        code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      });
    });
  });
}

async function hasCommand(cmd) {
  const finder = process.platform === 'win32' ? 'where' : 'which';
  try {
    const r = await runProc(finder, [cmd], 4000);
    return r.code === 0;
  } catch {
    return false;
  }
}

async function crackMd5WithJohn({ targetHash, wordlistPath, maxRunSec = 45 }) {
  const johnOk = await hasCommand('john');
  if (!johnOk) return { ok: false, found: false, reason: 'john_missing' };
  if (!wordlistPath || !fs.existsSync(wordlistPath)) return { ok: false, found: false, reason: 'wordlist_missing' };

  const dir = await mkdtemp(path.join(tmpdir(), 'ghjohn-'));
  const hashFile = path.join(dir, 'hashes.txt');
  const potFile = path.join(dir, 'john.pot');
  try {
    await writeFile(hashFile, `${targetHash}\n`, 'utf8');
    const runArgs = [
      '--format=raw-md5',
      '--wordlist',
      wordlistPath,
      `--pot=${potFile}`,
      `--max-run-time=${Math.max(5, Math.min(180, Number(maxRunSec) || 45))}`,
      hashFile,
    ];
    await runProc('john', runArgs, 120000);

    const showArgs = ['--show', '--format=raw-md5', `--pot=${potFile}`, hashFile];
    const shown = await runProc('john', showArgs, 15000);
    const lines = String(shown.stdout || '')
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter(Boolean);
    const crackLine = lines.find((x) => x.includes(':') && !/^\d+\s+password hash/i.test(x));
    if (!crackLine) return { ok: true, found: false };

    const parts = crackLine.split(':');
    const plaintext = parts.length >= 2 ? parts[1] : '';
    if (!plaintext) return { ok: true, found: false };
    return { ok: true, found: true, plaintext };
  } catch (e) {
    return { ok: false, found: false, reason: e?.message || String(e) };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function crackHashWithJohn({
  hashLine,
  format,
  wordlistPath,
  maxRunSec = 60,
  useRules = false,
  incrementalMode = '',
} = {}) {
  const johnOk = await hasCommand('john');
  if (!johnOk) return { ok: false, found: false, reason: 'john_missing' };
  const hasWordlist = wordlistPath && fs.existsSync(wordlistPath);
  if (!hasWordlist && !incrementalMode) return { ok: false, found: false, reason: 'wordlist_missing' };

  const fmt = String(format || '').trim() || 'raw-md5';
  const dir = await mkdtemp(path.join(tmpdir(), 'ghjohnx-'));
  const hashFile = path.join(dir, 'hashes.txt');
  const potFile = path.join(dir, 'john.pot');
  try {
    await writeFile(hashFile, `${String(hashLine || '').trim()}\n`, 'utf8');
    const runArgs = [`--format=${fmt}`, `--pot=${potFile}`, `--max-run-time=${Math.max(5, Math.min(300, Number(maxRunSec) || 60))}`];
    if (incrementalMode) {
      runArgs.push(`--incremental=${incrementalMode}`);
    } else {
      runArgs.push('--wordlist', wordlistPath);
      if (useRules) runArgs.push('--rules');
    }
    runArgs.push(hashFile);
    const run = await runProc('john', runArgs, 180000);
    const showArgs = ['--show', `--format=${fmt}`, `--pot=${potFile}`, hashFile];
    const shown = await runProc('john', showArgs, 20000);
    const lines = String(shown.stdout || '')
      .split(/\r?\n/)
      .map((x) => x.trim())
      .filter(Boolean);
    const crackLine = lines.find((x) => x.includes(':') && !/^\d+\s+password hash/i.test(x));
    if (!crackLine) return { ok: true, found: false, runCode: run.code };
    const parts = crackLine.split(':');
    const plaintext = parts.length >= 2 ? parts[1] : '';
    if (!plaintext) return { ok: true, found: false, runCode: run.code };
    return { ok: true, found: true, plaintext, runCode: run.code };
  } catch (e) {
    return { ok: false, found: false, reason: e?.message || String(e) };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

app.post('/api/ghostctf/hash-crack', async (req, res) => {
  const inputRaw = String(req.body?.input ?? '').trim().toLowerCase();
  const isMd5 = /^[a-f0-9]{32}$/.test(inputRaw);
  if (!isMd5) {
    res.status(400).json({ ok: false, error: 'informe um hash MD5 (32 hex)' });
    return;
  }

  const customWordlist = String(req.body?.wordlist ?? '').trim();
  const maxLines = Math.max(1000, Math.min(2000000, Number(req.body?.maxLines) || 300000));
  const wordlists = [
    customWordlist || null,
    '/usr/share/wordlists/rockyou.txt',
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt',
  ].filter(Boolean);

  for (const wl of wordlists) {
    if (!fs.existsSync(wl)) continue;
    try {
      const j = await crackMd5WithJohn({ targetHash: inputRaw, wordlistPath: wl, maxRunSec: 45 });
      if (j.found) {
        res.json({
          ok: true,
          found: true,
          plaintext: j.plaintext,
          tried: null,
          engine: 'john',
          wordlist: wl,
        });
        return;
      }
      const r = await crackMd5WithWordlist({ targetHash: inputRaw, wordlistPath: wl, maxLines });
      if (r.found != null) {
        res.json({
          ok: true,
          found: true,
          plaintext: r.found,
          tried: r.tried,
          engine: 'local-wordlist',
          wordlist: wl,
        });
        return;
      }
    } catch {
      // tenta próxima
    }
  }

  res.json({
    ok: true,
    found: false,
    plaintext: null,
    triedApprox: maxLines,
    message: 'não encontrado nas wordlists disponíveis dentro do limite',
  });
});

app.post('/api/ghostctf/john-crack', async (req, res) => {
  const hashLine = String(req.body?.hash ?? '').trim();
  if (!hashLine) {
    res.status(400).json({ ok: false, error: 'hash vazio' });
    return;
  }
  const format = String(req.body?.format ?? 'raw-md5').trim() || 'raw-md5';
  const customWordlist = String(req.body?.wordlist ?? '').trim();
  const maxRunSec = Math.max(5, Math.min(300, Number(req.body?.maxRunSec) || 60));
  const enableRules = Boolean(req.body?.enableRules ?? true);
  const enableIncremental = Boolean(req.body?.enableIncremental ?? false);
  const incrementalMode = String(req.body?.incrementalMode ?? 'Digits').trim() || 'Digits';

  const wordlists = [
    customWordlist || null,
    '/usr/share/wordlists/rockyou.txt',
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/500-worst-passwords.txt',
  ].filter(Boolean);

  let triedWordlists = 0;
  let phasesTried = [];
  for (const wl of wordlists) {
    if (!fs.existsSync(wl)) continue;
    triedWordlists += 1;
    // Fase 1: wordlist direta
    let r = await crackHashWithJohn({
      hashLine,
      format,
      wordlistPath: wl,
      maxRunSec,
      useRules: false,
      incrementalMode: '',
    });
    phasesTried.push(`wordlist:${wl}`);
    if (r.found) {
      res.json({
        ok: true,
        found: true,
        engine: 'john',
        plaintext: r.plaintext,
        format,
        wordlist: wl,
        phase: 'wordlist',
      });
      return;
    }
    // Fase 2: wordlist + rules
    if (enableRules) {
      r = await crackHashWithJohn({
        hashLine,
        format,
        wordlistPath: wl,
        maxRunSec,
        useRules: true,
        incrementalMode: '',
      });
      phasesTried.push(`wordlist+rules:${wl}`);
      if (r.found) {
        res.json({
          ok: true,
          found: true,
          engine: 'john',
          plaintext: r.plaintext,
          format,
          wordlist: wl,
          phase: 'wordlist+rules',
        });
        return;
      }
    }
    if (!r.ok && r.reason === 'john_missing') {
      res.status(400).json({ ok: false, error: 'john não encontrado no PATH' });
      return;
    }
  }

  // Fase 3: incremental curto (opcional, sem wordlist)
  if (enableIncremental) {
    phasesTried.push(`incremental:${incrementalMode}`);
    const r = await crackHashWithJohn({
      hashLine,
      format,
      wordlistPath: '',
      maxRunSec: Math.min(maxRunSec, 45),
      useRules: false,
      incrementalMode,
    });
    if (r.found) {
      res.json({
        ok: true,
        found: true,
        engine: 'john',
        plaintext: r.plaintext,
        format,
        wordlist: null,
        phase: `incremental:${incrementalMode}`,
      });
      return;
    }
  }

  res.json({
    ok: true,
    found: false,
    engine: 'john',
    format,
    triedWordlists,
    phasesTried,
    message: 'não encontrado nas wordlists disponíveis',
  });
});

app.get('/api/runs', async (req, res) => {
  const lim = Number(req.query.limit) || 50;
  try {
    const runs = await listRuns(lim);
    res.json({ runs });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

app.get('/api/runs/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) {
    res.status(400).json({ error: 'id inválido' });
    return;
  }
  try {
    const run = await getRunById(id);
    if (!run) {
      res.status(404).json({ error: 'run não encontrado' });
      return;
    }
    res.json(run);
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

/** Diff entre dois runs do mesmo alvo (fingerprints como `bounty_intel`). */
app.get('/api/runs/:newerId/diff/:baselineId', async (req, res) => {
  const newerId = Number(req.params.newerId);
  const baselineId = Number(req.params.baselineId);
  if (!Number.isFinite(newerId) || !Number.isFinite(baselineId)) {
    res.status(400).json({ error: 'ids inválidos' });
    return;
  }
  try {
    const result = await compareRuns(baselineId, newerId);
    if (result.error) {
      res.status(result.error === 'run não encontrado' ? 404 : 400).json(result);
      return;
    }
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

/** Corpus deduplicado por alvo (`bounty_intel` — SQLite ou Supabase). */
app.get('/api/intel/:target', async (req, res) => {
  const raw = String(req.params.target || '').trim();
  const isIp = isValidIpv4(raw);
  const t = isIp ? normIp(raw) : raw.toLowerCase();
  if (!t) {
    res.status(400).json({ error: 'target inválido' });
    return;
  }
  if (!isIp && !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(t)) {
    res.status(400).json({ error: 'target inválido (use domínio ou IPv4)' });
    return;
  }
  try {
    const [totalUnique, items] = await Promise.all([
      intelCountForTarget(t),
      listIntelForTarget(t, 500),
    ]);
    res.json({
      target: t,
      kind: isIp ? 'ip' : 'domain',
      totalUnique,
      items,
    });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

/** Biblioteca global de falhas (independente de alvo/IP). */
app.get('/api/knowledge', async (req, res) => {
  const lim = Number(req.query.limit) || 80;
  try {
    const items = await listKnowledge(lim);
    res.json({ ok: true, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

function isValidHubTargetParam(t) {
  const s = String(t || '').trim().toLowerCase();
  if (!s) return false;
  if (
    /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s)
  ) {
    return true;
  }
  return /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(s);
}

function isSha256FingerprintHexApi(fp) {
  return /^[a-f0-9]{64}$/.test(String(fp || '').trim().toLowerCase());
}

app.get('/api/ai/keys', (_req, res) => {
  res.json(aiKeysConfigured());
});

app.post('/api/ai-reports', async (req, res) => {
  const payload = req.body?.payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    res.status(400).json({ ok: false, error: 'Corpo inválido: falta object "payload" (export JSON do pipeline).' });
    return;
  }
  const projectName = String(req.body?.projectName ?? payload.projectName ?? '').trim();
  const targetDomain = String(req.body?.targetDomain ?? payload.target ?? '').trim();
  if (!targetDomain) {
    res.status(400).json({ ok: false, error: 'Define Target ou inclui "target" no payload.' });
    return;
  }
  try {
    const out = await runDualAiReports(payload, {
      projectName,
      targetDomain,
      aiProviderMode: String(req.body?.aiProviderMode || 'auto'),
      aiUseOpenrouter: req.body?.aiUseOpenrouter !== false,
      aiOpenrouterOnly: normalizeOpenrouterOnlyFlag(req.body?.aiOpenrouterOnly),
      aiPrimaryCloud:
        typeof req.body?.aiPrimaryCloud === 'string'
          ? req.body.aiPrimaryCloud
          : typeof req.body?.aiPrimaryReport === 'string'
            ? req.body.aiPrimaryReport
            : null,
      aiDisableGemini: ghostctfAiPolicyDisableGemini(),
    });
    const whUrl = (process.env.GHOSTCTF_WEBHOOK_URL || process.env.GHOSTRECON_WEBHOOK_URL)?.trim();
    if (whUrl) {
      const picked = pickAiReportForWebhook(out);
      if (picked) {
        void postAiReportWebhook(whUrl, {
          target: targetDomain,
          runId: payload.runId ?? null,
          provider: picked.provider,
          relatorio: picked.relatorio,
          proximos_passos: picked.proximos_passos,
        });
      }
    }
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/api/ai/lmstudio-check', async (_req, res) => {
  try {
    const out = await probeLmStudioConnection();
    res.json(out);
  } catch (e) {
    res.status(503).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/api/brain/categories', async (_req, res) => {
  try {
    const items = await listBrainCategories();
    res.json({ items });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

app.post('/api/brain/categories', async (req, res) => {
  const title = req.body?.title;
  const description = req.body?.description;
  try {
    const out = await createBrainCategory(title, description);
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

/** Apaga categoria (e `brain_links` em cascata). Categorias semente (XSS, SQLi, …) são bloqueadas. */
app.post('/api/brain/categories/:id/delete', async (req, res) => {
  const id = Number(req.params.id);
  try {
    const out = await deleteBrainCategory(id);
    if (!out.deleted) {
      res.status(404).json({ ok: false, error: 'Categoria não encontrada.' });
      return;
    }
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

/** Remove categorias antigas ligadas a `historicos/CTFsSolyd/falhas em ordem` (não cria biblioteca; SQLite). */
app.post('/api/brain/sync-historico-falhas', async (_req, res) => {
  try {
    const out = await syncBrainHistoricoFalhas();
    if (!out.ok) {
      res.status(out.error && String(out.error).includes('não encontrado') ? 404 : 400).json(out);
      return;
    }
    res.json(out);
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e), count: 0 });
  }
});

app.post('/api/brain/categories/:id/description', async (req, res) => {
  const id = Number(req.params.id);
  const description = req.body?.description;
  try {
    const out = await updateBrainCategoryDescription(id, description);
    res.json({ ok: true, category: out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/api/brain/link', async (req, res) => {
  const target = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  const fp = String(req.body?.fingerprint || '').trim().toLowerCase();
  const categoryId = req.body?.categoryId;
  try {
    const out = await upsertBrainLink({ target, fingerprint: fp, categoryId });
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/api/brain/finding-links', async (req, res) => {
  const target = String(req.query?.target || '')
    .trim()
    .toLowerCase();
  const fp = String(req.query?.fingerprint || '').trim().toLowerCase();
  if (!isValidHubTargetParam(target)) {
    res.status(400).json({ error: 'alvo inválido' });
    return;
  }
  if (!/^[a-f0-9]{64}$/.test(fp)) {
    res.status(400).json({ error: 'fingerprint inválido' });
    return;
  }
  try {
    const links = await listBrainLinksForFinding(target, fp);
    res.json({ target, fingerprint: fp, links });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

app.post('/api/brain/unlink', async (req, res) => {
  const target = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  const fp = String(req.body?.fingerprint || '').trim().toLowerCase();
  const categoryId = req.body?.categoryId;
  try {
    const out = await deleteBrainLink({ target, fingerprint: fp, categoryId });
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

app.get('/api/brain/category/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id) || id < 1) {
    res.status(400).json({ error: 'id inválido' });
    return;
  }
  try {
    const category = await getBrainCategoryById(id);
    if (!category) {
      res.status(404).json({ error: 'categoria não encontrada' });
      return;
    }
    const links = await listBrainLinksForCategory(id);
    res.json({ category, links });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

app.get('/api/manual-validations/:target', async (req, res) => {
  const t = String(req.params.target || '')
    .trim()
    .toLowerCase();
  if (!isValidHubTargetParam(t)) {
    res.status(400).json({ error: 'alvo inválido' });
    return;
  }
  try {
    const items = await listManualValidationsForTarget(t);
    res.json({ target: t, items });
  } catch (e) {
    res.status(500).json({ error: e?.message || String(e) });
  }
});

app.post('/api/manual-validations', async (req, res) => {
  const target = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  const fp = String(req.body?.fingerprint || '').trim().toLowerCase();
  const validated = req.body?.validated !== false && req.body?.validated !== 0 && req.body?.validated !== 'false';
  if (!isValidHubTargetParam(target)) {
    res.status(400).json({ ok: false, error: 'alvo inválido' });
    return;
  }
  if (!isSha256FingerprintHexApi(fp)) {
    res.status(400).json({ ok: false, error: 'fingerprint inválido' });
    return;
  }
  try {
    if (validated) {
      const snap = req.body?.snapshot && typeof req.body.snapshot === 'object' ? req.body.snapshot : null;
      const notes = req.body?.notes != null ? String(req.body.notes) : '';
      await upsertManualValidation({ target, fingerprint: fp, snapshot: snap, notes });
      res.json({ ok: true, target, fingerprint: fp, validated: true });
    } else {
      await deleteManualValidation(target, fp);
      res.json({ ok: true, target, fingerprint: fp, validated: false });
    }
  } catch (e) {
    res.status(400).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post('/api/manual-validations/ai-report', async (req, res) => {
  const target = String(req.body?.target || '')
    .trim()
    .toLowerCase();
  const findingsIn = Array.isArray(req.body?.findings) ? req.body.findings : null;
  if (!isValidHubTargetParam(target)) {
    res.status(400).json({ ok: false, error: 'alvo inválido' });
    return;
  }
  if (!findingsIn || !findingsIn.length) {
    res.status(400).json({ ok: false, error: 'Indica pelo menos um achado validado (array findings).' });
    return;
  }
  const known = new Set(
    (await listManualValidationsForTarget(target)).map((x) => String(x.fingerprint || '').toLowerCase()),
  );
  const findings = [];
  for (const f of findingsIn) {
    if (!f || typeof f !== 'object') continue;
    const fp = String(f.fingerprint || '').trim().toLowerCase();
    if (!isSha256FingerprintHexApi(fp) || !known.has(fp)) continue;
    const row = {
      type: f.type,
      prio: f.prio,
      score: f.score,
      value: f.value,
      meta: f.meta,
      url: f.url,
      fingerprint: fp,
    };
    if (Array.isArray(f.flags)) {
      const fa = f.flags
        .map((x) => String(x ?? '').trim())
        .filter(Boolean)
        .slice(0, 12)
        .map((x) => x.slice(0, 220));
      if (fa.length) row.flags = fa;
    }
    findings.push(row);
  }
  if (!findings.length) {
    res.status(400).json({
      ok: false,
      error: 'Nenhum achado coincide com validações manuais gravadas na base para este alvo.',
    });
    return;
  }
  const projectName = String(req.body?.projectName ?? '').trim();
  const stats =
    req.body?.stats && typeof req.body.stats === 'object'
      ? req.body.stats
      : { subs: 0, endpoints: 0, params: 0, secrets: 0, dorks: 0, high: 0, flags: 0 };
  const payload = {
    schemaVersion: 1,
    source: 'ghostctf-manual-validation-report',
    exportedAt: new Date().toISOString(),
    target,
    projectName: projectName || undefined,
    stats,
    findings,
    correlation: null,
    reportTemplates: {},
    runId: null,
    storage: storageLabel(),
    modules: ['manual_validation'],
    bountyContext: {
      note: 'Relatório pedido a partir de achados já confirmados manualmente no checklist Reporte.',
    },
  };
  const aiPrimaryRaw =
    typeof req.body?.aiPrimaryCloud === 'string'
      ? req.body.aiPrimaryCloud
      : typeof req.body?.aiPrimaryReport === 'string'
        ? req.body.aiPrimaryReport
        : null;
  try {
    const allowGemini = !ghostctfAiPolicyDisableGemini();
    const out = await runDualAiReports(payload, {
      projectName,
      targetDomain: target,
      aiProviderMode: 'auto',
      aiUseOpenrouter: req.body?.aiUseOpenrouter !== false,
      aiOpenrouterOnly: normalizeOpenrouterOnlyFlag(req.body?.aiOpenrouterOnly),
      aiPrimaryCloud: aiPrimaryRaw,
      onStatus: () => {},
      aiOpenrouterThenGeminiBeforeLm: allowGemini,
      aiDisableGemini: !allowGemini,
    });
    const whUrl = (process.env.GHOSTCTF_WEBHOOK_URL || process.env.GHOSTRECON_WEBHOOK_URL)?.trim();
    if (whUrl) {
      const picked = pickAiReportForWebhook(out);
      if (picked) {
        void postAiReportWebhook(whUrl, {
          target,
          runId: null,
          provider: picked.provider,
          relatorio: picked.relatorio,
          proximos_passos: picked.proximos_passos,
        });
      }
    }
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.use(express.static(ROOT, { index: false }));
app.get('/', (_req, res) => {
  res.sendFile(path.join(ROOT, 'index.html'));
});

const PORT = Number(process.env.PORT) || 3847;
const server = createServer(app);
attachShellWebSocket(server);
server.listen(PORT, async () => {
  console.log(`GHOSTCTF → http://127.0.0.1:${PORT}`);
  try {
    const r = await syncBrainHistoricoFalhas();
    const rm = Array.isArray(r.removed) ? r.removed.length : 0;
    if (rm > 0) {
      console.log(`[GHOSTCTF] Cérebro: limpeza «falhas em ordem» (${rm} categorias removidas).`);
    } else if (!r.ok && r.error && !String(r.error).includes('não encontrado')) {
      console.warn('[GHOSTCTF] Sync falhas → cérebro:', r.error);
    }
  } catch (e) {
    console.warn('[GHOSTCTF] Sync falhas → cérebro:', e?.message || String(e));
  }
});
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(
      `[GHOSTCTF] Porta ${PORT} em uso. Encerre a instância anterior (ex.: netstat -ano | findstr :${PORT}) ou defina PORT=3850 antes de npm start.`,
    );
  } else {
    console.error('[GHOSTCTF]', err.message);
  }
  process.exit(1);
});
