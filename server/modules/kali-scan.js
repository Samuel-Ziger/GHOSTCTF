import fs from 'fs';
import { readFile, writeFile, mkdtemp, rm } from 'fs/promises';
import { join, delimiter } from 'path';
import { tmpdir } from 'os';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { limits } from '../config.js';
import {
  runWpscanJson,
  extractWpscanFindings,
  isWpscanApiTokenConfigured,
  isWpscanApiRequired,
  countWpvulndbFindings,
} from './wpscan.js';

const WORDLISTS = [
  '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt',
  '/usr/share/seclists/Discovery/Web-Content/common.txt',
  '/usr/share/wordlists/dirb/common.txt',
];

const XSS_VIBES_DIR = join(process.cwd(), 'Xss', 'xss_vibes');
const XSS_VIBES_MAIN = join(XSS_VIBES_DIR, 'main.py');
const XSS_VIBES_PAYLOADS = join(XSS_VIBES_DIR, 'payloads.json');

function sanitizeHost(h) {
  if (typeof h !== 'string' || h.length > 253 || h.length < 3) return null;
  const s = h.trim().toLowerCase();
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(s)) return null;
  return s;
}

async function pathWhich(cmd) {
  return new Promise((resolve) => {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const p = spawn(finder, [cmd], { stdio: ['ignore', 'pipe', 'pipe'] });
    // No Windows (e ambientes sem PATH completo), spawn pode falhar (ex.: "which" não existe).
    // A detecção de ferramentas é opcional; não pode derrubar o servidor.
    p.on('error', () => resolve(false));
    p.on('close', (c) => resolve(c === 0));
  });
}

/** `which` + caminhos absolutos (IDE/systemd por vezes não herdam PATH completo com ~/go/bin). */
function fileExecutableExists(absPath) {
  if (!absPath || typeof absPath !== 'string') return false;
  try {
    const st = fs.statSync(absPath);
    return st.isFile() || st.isSymbolicLink();
  } catch {
    return false;
  }
}

async function pathWhichOrPaths(cmd, absoluteCandidates = []) {
  if (await pathWhich(cmd)) return true;
  for (const p of absoluteCandidates) {
    if (fileExecutableExists(p)) return true;
  }
  return false;
}

/** Onde o dalfox costuma estar (PATH incomum no processo Node). */
function dalfoxCandidatePaths() {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const set = new Set();
  const push = (p) => {
    if (p && typeof p === 'string') set.add(p);
  };
  push('/usr/local/bin/dalfox');
  push('/usr/bin/dalfox');
  push('/snap/bin/dalfox');
  if (home) {
    push(join(home, 'go', 'bin', 'dalfox'));
    push(join(home, '.local', 'bin', 'dalfox'));
    push(join(home, 'bin', 'dalfox'));
  }
  const goPath = process.env.GOPATH || '';
  for (const root of goPath.split(delimiter)) {
    const t = root?.trim();
    if (t) push(join(t, 'bin', 'dalfox'));
  }
  return [...set];
}

/** Caminho absoluto quando o ficheiro existe; senão `dalfox` no PATH. */
function resolveDalfoxExecutableForSpawn() {
  for (const p of dalfoxCandidatePaths()) {
    if (fileExecutableExists(p)) return p;
  }
  return 'dalfox';
}

export async function getKaliCapabilities() {
  const force = process.env.GHOSTRECON_FORCE_KALI === '1';
  let distroKali = false;
  try {
    const rel = fs.readFileSync('/etc/os-release', 'utf8');
    if (/\bID=kali\b/i.test(rel)) distroKali = true;
    else if (/PRETTY_NAME=.*[Kk]ali/i.test(rel)) distroKali = true;
  } catch {
    /* não-Linux ou sem os-release */
  }

  const qualifyDistro = distroKali || force;
  const python3 = await pathWhich('python3');
  const python = python3 ? false : await pathWhich('python');
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const sqlmapAbs = ['/usr/bin/sqlmap', '/usr/local/bin/sqlmap', ...(home ? [join(home, '.local/bin/sqlmap')] : [])];
  const tools = {
    nmap: await pathWhich('nmap'),
    nuclei: await pathWhich('nuclei'),
    ffuf: await pathWhich('ffuf'),
    searchsploit: await pathWhich('searchsploit'),
    wpscan: await pathWhich('wpscan'),
    whois: await pathWhich('whois'),
    dalfox: await pathWhichOrPaths('dalfox', dalfoxCandidatePaths()),
    sqlmap: await pathWhichOrPaths('sqlmap', sqlmapAbs),
    python3,
    python,
    xss_vibes: (python3 || python) && fs.existsSync(XSS_VIBES_MAIN) && fs.existsSync(XSS_VIBES_PAYLOADS),
  };

  const ready = qualifyDistro && tools.nmap;
  let message = 'Modo agressivo disponível.';
  if (!qualifyDistro) {
    message = 'Não é Kali Linux. Usa Kali ou define GHOSTRECON_FORCE_KALI=1 (apenas testes).';
  } else if (!tools.nmap) {
    message = 'nmap não encontrado no PATH.';
  }

  return {
    kali: ready,
    kaliDistro: distroKali,
    forced: force,
    qualifyDistro,
    tools,
    message,
  };
}

function runProc(cmd, args, timeoutMs, spawnOpts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      ...spawnOpts,
    });
    const out = [];
    const err = [];
    let killed = false;
    const t = setTimeout(() => {
      killed = true;
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
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

function getAttr(attrStr, key) {
  const m = attrStr.match(new RegExp(`${key}="([^"]*)"`));
  return m ? m[1] : '';
}

function decodeXmlAttrLite(s) {
  return String(s || '')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&amp;/g, '&');
}

/**
 * Extrai portas abertas + serviço (self-close ou `<service>…</service>`) + resumo de scripts NSE no bloco.
 */
export function parseNmapXml(xml) {
  const rows = [];
  const parts = xml.split(/<host[\s>]/);
  const portBlockRe = /<port protocol="(\w+)" portid="(\d+)">([\s\S]*?)<\/port>/gi;
  const scriptOutRe = /<script[^>]*\bid="([^"]*)"[^>]*output="([^"]*)"/gi;
  /** Legado: só `<service …/>` imediatamente após state open (alguns XML truncados). */
  const legacyPortRe =
    /<port protocol="(\w+)" portid="(\d+)">\s*<state\b[^>]*\bstate="open"[^>]*\/>\s*<service([^/]*)\/>/gi;

  for (let i = 1; i < parts.length; i++) {
    const hc = parts[i];
    const hostLabel =
      (hc.match(/<hostname name="([^"]+)"/) || [])[1] ||
      (hc.match(/<address addr="([^"]+)" addrtype="ipv4"/) || [])[1] ||
      (hc.match(/<address addr="([^"]+)" addrtype="ipv6"/) || [])[1] ||
      'unknown';

    const seenKeys = new Set();
    const pushRow = (proto, port, name, product, version, extrainfo, innerForScripts) => {
      const key = `${proto}/${port}`;
      if (seenKeys.has(key)) return;
      seenKeys.add(key);
      const scriptBits = [];
      if (innerForScripts) {
        scriptOutRe.lastIndex = 0;
        let sm;
        while ((sm = scriptOutRe.exec(innerForScripts)) !== null) {
          scriptBits.push(`${sm[1]}: ${decodeXmlAttrLite(sm[2])}`);
          if (scriptBits.length > 48) break;
        }
      }
      let ex = extrainfo;
      if (scriptBits.length) {
        const blob = scriptBits.join(' | ');
        ex = ex ? `${ex} | scripts: ${blob}` : `scripts: ${blob}`;
      }
      const searchBlob = [product, version, name, ex].filter(Boolean).join(' ').trim();
      rows.push({
        host: hostLabel,
        port,
        proto,
        name,
        product,
        version,
        extrainfo: ex,
        searchBlob,
      });
    };

    portBlockRe.lastIndex = 0;
    let m;
    let foundBlocks = false;
    while ((m = portBlockRe.exec(hc)) !== null) {
      const inner = m[3];
      if (!/<state\b[^>]*\bstate="open"/i.test(inner)) continue;
      foundBlocks = true;
      let attrs = '';
      const svcSelf = inner.match(/<service\b([^>]*)\/>/i);
      const svcFull = inner.match(/<service\b([^>]*)>([\s\S]*?)<\/service>/i);
      if (svcSelf) attrs = svcSelf[1];
      else if (svcFull) attrs = svcFull[1];
      else continue;

      const name = getAttr(attrs, 'name');
      const product = getAttr(attrs, 'product');
      const version = getAttr(attrs, 'version');
      const extrainfo = getAttr(attrs, 'extrainfo');
      pushRow(m[1], m[2], name, product, version, extrainfo, inner);
    }

    if (!foundBlocks) {
      legacyPortRe.lastIndex = 0;
      let lm;
      while ((lm = legacyPortRe.exec(hc)) !== null) {
        const attrs = lm[3];
        const name = getAttr(attrs, 'name');
        const product = getAttr(attrs, 'product');
        const version = getAttr(attrs, 'version');
        const extrainfo = getAttr(attrs, 'extrainfo');
        pushRow(lm[1], lm[2], name, product, version, extrainfo, null);
      }
    }
  }
  return rows;
}

async function runNmapOnHosts(hosts, log) {
  const dir = await mkdtemp(join(tmpdir(), 'ghnr-'));
  const xmlPath = join(dir, 'nmap.xml');
  const extra = (process.env.GHOSTRECON_NMAP_ARGS || '-sV -Pn -T4 --host-timeout 180s')
    .split(/\s+/)
    .filter(Boolean);
  const args = [...extra, '-oX', xmlPath, ...hosts];
  log(`nmap ${args.slice(0, -hosts.length).join(' ')} [${hosts.length} hosts]`, 'info');
  try {
    const proc = await runProc('nmap', args, 660000);
    if (proc.code !== 0) {
      log(`nmap terminou com código ${proc.code}`, 'warn');
    }
    const xml = await readFile(xmlPath, 'utf8');
    return parseNmapXml(xml);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function searchExploitDbOne(query, log) {
  const q = query.slice(0, 100).trim();
  if (q.length < 2) return [];
  const tryJson = async (args) => {
    const r = await runProc('searchsploit', args, 40000);
    if (!r.stdout.trim()) return [];
    try {
      const j = JSON.parse(r.stdout);
      if (Array.isArray(j)) return j.slice(0, 8);
      if (j.RESULTS_EXPLOIT && Array.isArray(j.RESULTS_EXPLOIT)) return j.RESULTS_EXPLOIT.slice(0, 8);
      if (j.RESULTS_SHELLCODE && Array.isArray(j.RESULTS_SHELLCODE)) return j.RESULTS_SHELLCODE.slice(0, 8);
      if (j.results && Array.isArray(j.results)) return j.results.slice(0, 8);
    } catch {
      /* texto */
    }
    return [];
  };
  try {
    let rows = await tryJson(['--json', q]);
    if (rows.length) return rows;
    rows = await tryJson(['-j', q]);
    return rows;
  } catch (e) {
    log(`searchsploit "${q.slice(0, 40)}…": ${e.message}`, 'warn');
    return [];
  }
}

function exploitTitle(row) {
  if (typeof row === 'string') return row;
  return row.Title || row.title || row.Path || row['EDB-ID'] || row.EDB_ID || JSON.stringify(row).slice(0, 120);
}

function exploitUrl(row) {
  const id = row['EDB-ID'] || row.EDB_ID || row.id || row['edb-id'];
  if (id) return `https://www.exploit-db.com/exploits/${id}`;
  return row.url || '';
}

/**
 * Query Google sugerida após versão nmap (contexto Exploit-DB), ex.: «exploit pra ssh 9.1».
 * @param {{ name?: string, product?: string, version?: string }} row
 * @returns {string|null}
 */
export function buildExploitVersionGoogleQuery(row) {
  const ver = String(row?.version || '').trim();
  if (!ver || !/\d/.test(ver)) return null;
  const name = String(row?.name || '').trim().toLowerCase();
  const product = String(row?.product || '').trim();
  let short = name.replace(/[^a-z0-9._-]/gi, '');
  if (!short && product) {
    short = product
      .split(/\s+/)[0]
      .toLowerCase()
      .replace(/[^a-z0-9._-]/gi, '');
  }
  if (!short || short.length > 48) return null;
  const m = ver.match(/^([\d.]+(?:p\d+)?(?:[a-z]+\d*)?)/i);
  const verNorm = (m && m[1]) || ver.split(/\s+/)[0].slice(0, 20);
  if (!verNorm) return null;
  return `exploit pra ${short} ${verNorm}`.replace(/\s+/g, ' ').trim();
}

async function runFfuf200(baseUrl, log) {
  const wl = WORDLISTS.find((p) => fs.existsSync(p));
  if (!wl) {
    log('ffuf: nenhuma wordlist em /usr/share/seclists ou dirb', 'warn');
    return [];
  }
  const dir = await mkdtemp(join(tmpdir(), 'ghff-'));
  const out = join(dir, 'out.json');
  const base = baseUrl.replace(/\/$/, '');
  const threads = Math.min(64, Math.max(1, Number(process.env.GHOSTRECON_FFUF_THREADS || 32)));
  try {
    const args = [
      '-u',
      `${base}/FUZZ`,
      '-w',
      wl,
      '-mc',
      '200',
      '-t',
      String(threads),
      '-timeout',
      '8',
      '-maxtime',
      '120',
      '-of',
      'json',
      '-o',
      out,
      '-s',
    ];
    await runProc('ffuf', args, 135000);
    const raw = await readFile(out, 'utf8');
    const j = JSON.parse(raw);
    return (j.results || []).map((r) => r.url).filter(Boolean);
  } catch (e) {
    log(`ffuf ${base}: ${e.message}`, 'warn');
    return [];
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function runNucleiList(urls, log) {
  if (!urls.length) return [];
  const dir = await mkdtemp(join(tmpdir(), 'ghnu-'));
  const listFile = join(dir, 'targets.txt');
  const outFile = join(dir, 'out.jsonl');
  await writeFile(listFile, [...new Set(urls)].slice(0, 18).join('\n'), 'utf8');
  const profile = String(process.env.GHOSTRECON_NUCLEI_PROFILE || 'bb-passive').toLowerCase();
  const profileArgs =
    profile === 'safe'
      ? ['-severity', 'medium,high,critical']
      : profile === 'bb-active'
        ? ['-severity', 'low,medium,high,critical']
        : profile === 'high-impact'
          ? ['-severity', 'high,critical', '-tags', 'rce,sqli,lfi,ssrf,xss,auth-bypass']
          : ['-severity', 'medium,high,critical'];
  try {
    await runProc(
      'nuclei',
      ['-l', listFile, '-jsonl', '-o', outFile, '-silent', '-rate-limit', '35', '-timeout', '8', ...profileArgs],
      320000,
    );
    let text = '';
    try {
      text = await readFile(outFile, 'utf8');
    } catch {
      return [];
    }
    return text
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch (e) {
    log(`nuclei: ${e.message}`, 'warn');
    return [];
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function runNucleiTags(urls, tagsCsv, log) {
  if (!urls.length) return [];
  const dir = await mkdtemp(join(tmpdir(), 'ghnu-'));
  const listFile = join(dir, 'targets.txt');
  const outFile = join(dir, 'out.jsonl');
  await writeFile(listFile, [...new Set(urls)].slice(0, 30).join('\n'), 'utf8');
  const profile = String(process.env.GHOSTRECON_NUCLEI_PROFILE || 'bb-passive').toLowerCase();
  const sevArgs = profile === 'safe' ? ['-severity', 'medium,high,critical'] : ['-severity', 'low,medium,high,critical'];
  try {
    await runProc(
      'nuclei',
      [
        '-l',
        listFile,
        '-jsonl',
        '-o',
        outFile,
        '-silent',
        '-rate-limit',
        '25',
        '-timeout',
        '8',
        '-tags',
        tagsCsv,
        ...sevArgs,
      ],
      360000,
    );
    let text = '';
    try {
      text = await readFile(outFile, 'utf8');
    } catch {
      return [];
    }
    return text
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch (e) {
    log(`nuclei(${tagsCsv}): ${e.message}`, 'warn');
    return [];
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function parseDalfoxLines(text, limit = 6) {
  const lines = String(text || '')
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
  const hits = [];
  for (const line of lines) {
    if (/\[(POC|VULN|WEAK)\]/i.test(line) || /\bvulnerab/i.test(line)) {
      hits.push(line.slice(0, 260));
    }
    if (hits.length >= limit) break;
  }
  return hits;
}

/** Tenta extrair achados estruturados do stdout JSON / JSONL do dalfox. */
function extractDalfoxJsonHits(text, limit = 10) {
  const hits = [];
  const walk = (obj) => {
    if (hits.length >= limit) return;
    if (!obj) return;
    if (typeof obj === 'string') return;
    if (Array.isArray(obj)) {
      for (const x of obj) {
        walk(x);
        if (hits.length >= limit) return;
      }
      return;
    }
    if (typeof obj !== 'object') return;
    const msg = String(obj.message || obj.msg || obj.data || '');
    const typ = String(obj.type || obj.Type || '');
    const hasUrl = Boolean(obj.url || obj.URL || obj.host);
    if (
      hasUrl ||
      /\bvulnerab/i.test(msg) ||
      /\b(POC|VULN|WEAK)\b/i.test(typ) ||
      (obj.param && (obj.payload || obj.poc))
    ) {
      hits.push(JSON.stringify(obj).slice(0, 400));
    }
    for (const v of Object.values(obj)) {
      if (hits.length >= limit) return;
      if (v && (typeof v === 'object' || Array.isArray(v))) walk(v);
    }
  };
  const s = String(text || '').trim();
  if (!s) return hits;
  try {
    walk(JSON.parse(s));
  } catch {
    for (const line of s.split('\n')) {
      const t = line.trim();
      if (!t.startsWith('{')) continue;
      try {
        walk(JSON.parse(t));
      } catch {
        /* ignore */
      }
      if (hits.length >= limit) break;
    }
  }
  return hits.slice(0, limit);
}

async function runDalfoxUrl(url, log, auth = null) {
  const timeoutMs = Number(process.env.GHOSTRECON_DALFOX_TIMEOUT_MS || 120000);
  const tail = ['--silence', '--skip-bav', '--skip-mining-all', '--worker', '40'];
  const authArgs = [];
  if (auth?.cookie) authArgs.push('--cookie', String(auth.cookie));
  const ua = auth?.headers?.['User-Agent'] || auth?.headers?.['user-agent'];
  if (ua) authArgs.push('--user-agent', String(ua));

  const dalfoxBin = resolveDalfoxExecutableForSpawn();
  const runOnce = async (withJson) => {
    const args = ['url', url, ...(withJson ? ['--format', 'json'] : []), ...tail, ...authArgs];
    const proc = await runProc(dalfoxBin, args, timeoutMs);
    const text = [proc.stdout, proc.stderr].filter(Boolean).join('\n');
    return { proc, text };
  };

  try {
    let { proc, text } = await runOnce(true);
    let hits = extractDalfoxJsonHits(proc.stdout || text);
    const looksLikeBadFlag =
      !hits.length && /unknown flag|invalid option|unrecognized.*--format/i.test(text);
    if (looksLikeBadFlag) {
      ({ proc, text } = await runOnce(false));
      hits = extractDalfoxJsonHits(proc.stdout || text);
    }
    if (!hits.length) hits = parseDalfoxLines(text);
    if (proc.code !== 0 && typeof log === 'function') {
      log(`dalfox ${url}: código ${proc.code}`, 'warn');
    }
    return { ok: true, hits, stdoutFormat: hits.length && /^\s*\{/.test(String(proc.stdout || '').trim()) ? 'json' : 'mixed' };
  } catch (e) {
    return { ok: false, error: String(e?.message || e), hits: [] };
  }
}

function stripAnsi(text) {
  return String(text || '').replace(/\x1b\[[0-9;]*m/g, '');
}

function parseXssVibesTextForHits(text, limit = 20) {
  const clean = stripAnsi(text);
  const lines = clean
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!/VULNERABLE:/i.test(line)) continue;
    const fromMsg = line.match(/VULNERABLE:\s*(https?:\/\/\S+)/i)?.[1];
    const nextUrl = lines
      .slice(i + 1, i + 6)
      .find((x) => /^https?:\/\/\S+/i.test(x))
      ?.match(/^(https?:\/\/\S+)/i)?.[1];
    const finalUrl = fromMsg || nextUrl || null;
    if (finalUrl && !hits.includes(finalUrl)) hits.push(finalUrl);
    if (hits.length >= limit) break;
  }
  return hits;
}

async function runXssVibesBatch({ urls, cap, log, auth = null }) {
  const uniq = [...new Set((urls || []).filter((u) => /^https?:\/\//i.test(String(u))))];
  if (!uniq.length) return { ok: true, hits: [], message: 'sem URLs válidas' };
  const maxUrls = Math.max(1, Number(process.env.GHOSTRECON_XSS_VIBES_MAX_URLS || 25));
  const selected = uniq.slice(0, maxUrls);
  const threads = Math.min(10, Math.max(1, Number(process.env.GHOSTRECON_XSS_VIBES_THREADS || 6)));
  const timeoutMs = Math.max(30_000, Number(process.env.GHOSTRECON_XSS_VIBES_TIMEOUT_MS || 300_000));
  const pyCmd = cap?.tools?.python3 ? 'python3' : cap?.tools?.python ? 'python' : null;
  if (!pyCmd) return { ok: false, hits: [], error: 'python3/python não encontrado no PATH' };
  if (!fs.existsSync(XSS_VIBES_MAIN)) return { ok: false, hits: [], error: `xss_vibes não encontrado: ${XSS_VIBES_MAIN}` };

  const dir = await mkdtemp(join(tmpdir(), 'ghxv-'));
  const inFile = join(dir, 'targets.txt');
  const outFile = join(dir, 'xss_vibes_hits.txt');
  await writeFile(inFile, selected.join('\n'), 'utf8');
  const args = [XSS_VIBES_MAIN, '-f', inFile, '-o', outFile, '-t', String(threads)];
  const headerParts = [];
  if (auth?.cookie) headerParts.push(`Cookie: ${String(auth.cookie).replace(/,/g, ';')}`);
  const ua = auth?.headers?.['User-Agent'] || auth?.headers?.['user-agent'];
  if (ua) headerParts.push(`User-Agent: ${String(ua).replace(/,/g, ' ')}`);
  if (headerParts.length) args.push('-H', headerParts.join(','));

  if (typeof log === 'function') {
    log(`[xss_vibes] Executando ferramenta: ${pyCmd} main.py -f targets.txt -o xss_vibes_hits.txt -t ${threads}`, 'info');
    log(`[xss_vibes] Alvos com query: ${selected.length} (limite=${maxUrls})`, 'info');
  }

  try {
    const proc = await runProc(pyCmd, args, timeoutMs, { cwd: XSS_VIBES_DIR });
    const mixed = [proc.stdout, proc.stderr].filter(Boolean).join('\n');
    let hits = [];
    try {
      const rawOut = await readFile(outFile, 'utf8');
      hits = rawOut
        .split('\n')
        .map((s) => s.trim())
        .filter((s) => /^https?:\/\//i.test(s));
    } catch {
      /* output opcional */
    }
    if (!hits.length) hits = parseXssVibesTextForHits(mixed);
    hits = [...new Set(hits)];
    if (proc.code !== 0 && typeof log === 'function') {
      log(`[xss_vibes] terminou com código ${proc.code}`, 'warn');
    }
    if (typeof log === 'function') {
      log(`[xss_vibes] conclusão: ${hits.length} possível(is) XSS`, hits.length ? 'warn' : 'info');
    }
    return { ok: true, hits, stdout: mixed.slice(0, 6000) };
  } catch (e) {
    return { ok: false, hits: [], error: String(e?.message || e) };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function pickFirstMatch(re, text) {
  const m = String(text || '').match(re);
  return m?.[1] ? String(m[1]).trim() : null;
}

function pickAllMatches(re, text, limit = 8) {
  const out = [];
  const s = String(text || '');
  let m;
  // eslint-disable-next-line no-constant-condition
  while ((m = re.exec(s)) !== null) {
    if (m[1]) out.push(String(m[1]).trim());
    if (out.length >= limit) break;
  }
  return out;
}

function isFtpServiceRow(row) {
  if (!row) return false;
  const name = String(row.name || '').toLowerCase();
  const product = String(row.product || '').toLowerCase();
  return row.proto === 'tcp' && (String(row.port) === '21' || name.includes('ftp') || product.includes('ftp'));
}

async function tryFtpAnonymousLogin({
  host,
  port = 21,
  timeoutMs = 12_000,
  passCandidates = ['', 'anonymous@ghostrecon.local'],
}) {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port: Number(port) || 21 });
    sock.setEncoding('utf8');
    sock.setTimeout(timeoutMs);

    let buf = '';
    let done = false;
    let sentUser = false;
    let sentPass = false;
    let passIndex = -1;
    const triedPasses = [];
    let banner = '';
    let userReply = '';
    let passReply = '';

    const nextPass = () => {
      const idx = passIndex + 1;
      if (idx >= passCandidates.length) return false;
      passIndex = idx;
      const candidate = String(passCandidates[passIndex] ?? '');
      triedPasses.push(candidate);
      sock.write(`PASS ${candidate}\r\n`);
      sentPass = true;
      return true;
    };

    const finish = (result) => {
      if (done) return;
      done = true;
      try {
        sock.end();
      } catch {
        /* ignore */
      }
      resolve(result);
    };

    const onLine = (line) => {
      const m = String(line).match(/^(\d{3})([\s-])(.*)$/);
      if (!m) return;
      const code = Number(m[1]);
      const sep = m[2];
      const msg = m[3] || '';
      if (!banner && code === 220 && sep === ' ') banner = msg;

      // Resposta multiline usa "123-"; só tratamos a linha final "123 ".
      if (sep !== ' ') return;

      if (!sentUser && code === 220) {
        sock.write('USER anonymous\r\n');
        sentUser = true;
        return;
      }

      if (sentUser && !sentPass) {
        userReply = `${code} ${msg}`.trim();
        if (code === 230) {
          sock.write('QUIT\r\n');
          finish({
            ok: true,
            host,
            port,
            banner,
            userReply,
            passReply: '',
            passUsed: '(none-required)',
            triedPasses,
          });
          return;
        }
        if (code === 331) {
          if (!nextPass()) {
            finish({ ok: false, host, port, banner, userReply, passReply: '', triedPasses });
          }
          return;
        }
        if (code >= 500) {
          finish({ ok: false, host, port, banner, userReply, passReply: '', triedPasses });
        }
        return;
      }

      if (sentPass) {
        passReply = `${code} ${msg}`.trim();
        if (code === 230) {
          sock.write('QUIT\r\n');
          finish({
            ok: true,
            host,
            port,
            banner,
            userReply,
            passReply,
            passUsed: String(passCandidates[passIndex] ?? ''),
            triedPasses,
          });
          return;
        }
        if (code >= 500 || code === 530) {
          if (nextPass()) return;
          finish({ ok: false, host, port, banner, userReply, passReply, triedPasses });
        }
      }
    };

    sock.on('data', (chunk) => {
      buf += chunk;
      const lines = buf.split(/\r?\n/);
      buf = lines.pop() || '';
      for (const line of lines) onLine(line);
    });

    sock.on('timeout', () => finish({ ok: false, host, port, error: `timeout ${timeoutMs}ms` }));
    sock.on('error', (e) => finish({ ok: false, host, port, error: e?.message || String(e) }));
    sock.on('close', () => {
      if (!done) finish({ ok: false, host, port, error: 'connection closed' });
    });
  });
}

function parseWhoisText(domainOrHost, whoisText) {
  // Formatos variam por registrar; usamos regexes comuns.
  const registrar = pickFirstMatch(/Registrar:\s*(.+)$/im, whoisText) || pickFirstMatch(/registrar:\s*(.+)$/im, whoisText);
  const registrantCountry =
    pickFirstMatch(/Registrant Country:\s*(.+)$/im, whoisText) || pickFirstMatch(/country:\s*(.+)$/im, whoisText);
  const created =
    pickFirstMatch(/Creation Date:\s*(.+)$/im, whoisText) ||
    pickFirstMatch(/created on:\s*(.+)$/im, whoisText) ||
    pickFirstMatch(/Created:\s*(.+)$/im, whoisText);
  const updated =
    pickFirstMatch(/Updated Date:\s*(.+)$/im, whoisText) || pickFirstMatch(/updated on:\s*(.+)$/im, whoisText);
  const expires =
    pickFirstMatch(/Registry Expiry Date:\s*(.+)$/im, whoisText) ||
    pickFirstMatch(/Expiry Date:\s*(.+)$/im, whoisText) ||
    pickFirstMatch(/expires on:\s*(.+)$/im, whoisText);

  // Alguns whois usam "Name Server:" e outros "nserver:".
  const nameServers =
    pickAllMatches(/Name Server:\s*(.+)$/gim, whoisText, 10).length
      ? pickAllMatches(/Name Server:\s*(.+)$/gim, whoisText, 10)
      : pickAllMatches(/nserver:\s*(.+)$/gim, whoisText, 10);

  // Se quase nada vier, não cria achado “vazio”.
  const hasSomething = Boolean(registrar || created || expires || nameServers.length);
  return {
    hasSomething,
    registrar,
    registrantCountry,
    created,
    updated,
    expires,
    nameServers,
    domainOrHost,
  };
}

async function runWhoisJsonLike({ target, timeoutMs, log }) {
  // quem usa whois no Kali geralmente tem o CLI "whois".
  // Não normalizamos em JSON: apenas parseamos texto com regexes.
  const proc = await runProc('whois', [target], timeoutMs);
  const text = [proc.stdout, proc.stderr].filter(Boolean).join('\n').slice(0, 220_000);
  if (typeof log === 'function' && text.includes('No match')) log(`whois: sem match para ${target}`, 'info');
  return { ok: proc.code === 0, text };
}

/**
 * Scan ativo: nmap → searchsploit (heurístico) → ffuf (só HTTP 200) → nuclei (se `runNuclei`).
 */
function nucleiEvidenceMeta({ tid, sev, extra }) {
  const parts = [
    `scanner=nuclei`,
    `severity=${sev}`,
    tid && `template=${tid}`,
    `confidence=active_scan`,
  ];
  if (extra) parts.push(extra);
  return parts.filter(Boolean).join(' • ');
}

export async function runKaliAggressiveScan({
  domain,
  subdomainsAlive,
  cap,
  log,
  addFinding,
  wordpressTargets,
  paramUrls,
  xssSignals = true,
  sqliSignals = true,
  /** Só corre scans nuclei se o módulo UI `kali_nuclei` estiver activo (e modo Kali no servidor). */
  runNuclei = false,
  /** Só corre ffuf se o módulo UI `kali_ffuf` estiver activo (e modo Kali no servidor). */
  runFfuf = false,
  /** Cookie / headers do recon (dalfox `--cookie`, xss_vibes `-H`). */
  auth = null,
  /** NDJSON: eventos `dork` para fila de Google (pesquisas «exploit pra …» por versão nmap). */
  emit = null,
}) {
  const pipeTool = (name, state) => {
    if (typeof emit !== 'function') return;
    emit({ type: 'pipe', name, state });
  };

  const rawHosts = [domain, ...(subdomainsAlive || [])].map(sanitizeHost).filter(Boolean);
  const hosts = [...new Set(rawHosts)].slice(0, 22);

  log('═══ MODO KALI / SCAN ATIVO ═══', 'section');
  log('Apenas em alvos com autorização explícita (bug bounty / pentest autorizado).', 'warn');
  log(`Alvos nmap (${hosts.length}): ${hosts.join(', ')}`, 'info');

  const baseUrlsForFfuf = [
    `https://${domain}/`,
    `http://${domain}/`,
  ];
  const seenQueries = new Set();
  const seenExploitGoogle = new Set();
  const exploitGoogleMax = Math.max(
    1,
    Math.min(60, Number(process.env.GHOSTRECON_EXPLOIT_GOOGLE_MAX_QUERIES || 25)),
  );
  const ftpChecked = new Set();

  if (cap.tools.nmap) {
    pipeTool('nmap', 'active');
    try {
      const rows = await runNmapOnHosts(hosts, log);
      log(`nmap: ${rows.length} serviço(s) em portas abertas`, 'success');
      for (const row of rows) {
        const line = `${row.proto}/${row.port} ${row.host} — ${row.name || '?'} ${row.product || ''} ${row.version || ''}`.trim();
        let url = null;
        if (row.port === '443') url = `https://${row.host}/`;
        else if (row.port === '80') url = `http://${row.host}/`;
        addFinding({
          type: 'nmap',
          prio: 'med',
          score: 56,
          value: line,
          meta: row.searchBlob || row.name || 'nmap',
          url,
        });

        const exploitGq = buildExploitVersionGoogleQuery(row);
        if (exploitGq && typeof emit === 'function' && seenExploitGoogle.size < exploitGoogleMax) {
          const gk = exploitGq.toLowerCase();
          if (!seenExploitGoogle.has(gk)) {
            seenExploitGoogle.add(gk);
            const googleUrl = `https://www.google.com/search?q=${encodeURIComponent(exploitGq)}`;
            emit({
              type: 'dork',
              googleUrl,
              query: exploitGq,
              mod: 'nmap_version_exploit_google',
              prio: 'med',
              /** UI: abre mesmo com «Abrir dorks» desligado */
              forceOpen: true,
            });
            addFinding(
              {
                type: 'dork',
                prio: 'med',
                score: 50,
                value: exploitGq,
                meta: 'Categoria: nmap_version_exploit_google • sugestão Google (versão nmap / Exploit-DB contexto)',
                url: googleUrl,
              },
              'dorks',
            );
            log(`Google (versão nmap): ${exploitGq}`, 'info');
          }
        }

        if (isFtpServiceRow(row)) {
          const k = `${row.host}:${row.port}`;
          if (!ftpChecked.has(k)) {
            ftpChecked.add(k);
            const ftpTimeout = Math.max(4000, Number(process.env.GHOSTRECON_FTP_ANON_TIMEOUT_MS || 12000));
            log(`[FTP] Teste de login anônimo em ${k} (PASS vazio, depois e-mail)`, 'info');
            try {
              const r = await tryFtpAnonymousLogin({
                host: row.host,
                port: Number(row.port) || 21,
                timeoutMs: ftpTimeout,
              });
              if (r.ok) {
                addFinding({
                  type: 'security',
                  prio: 'high',
                  score: 91,
                  value: `FTP anonymous login enabled @ ${k}`,
                  meta: [
                    'service=ftp',
                    r.banner ? `banner=${String(r.banner).slice(0, 90)}` : null,
                    r.userReply ? `user=${r.userReply}` : null,
                    r.passReply ? `pass=${r.passReply}` : null,
                    r.passUsed === '' ? 'auth=anonymous-empty-pass' : r.passUsed ? `auth=anonymous-pass:${r.passUsed}` : null,
                    Array.isArray(r.triedPasses) && r.triedPasses.length
                      ? `tried=${r.triedPasses.map((p) => (p === '' ? '<empty>' : p)).join(',')}`
                      : null,
                    'evidence=active_check',
                  ]
                    .filter(Boolean)
                    .join(' • '),
                  url: null,
                });
                const authHow =
                  r.passUsed === '' ? 'PASS <empty>' : r.passUsed ? `PASS ${r.passUsed}` : 'sem PASS';
                log(`[FTP] ⚠ login anônimo permitido em ${k} (${authHow})`, 'warn');
              } else {
                const why = r.error || r.passReply || r.userReply || 'negado';
                log(`[FTP] ${k} sem login anônimo (${String(why).slice(0, 120)})`, 'info');
              }
            } catch (e) {
              log(`[FTP] erro no teste ${k}: ${e?.message || e}`, 'warn');
            }
          }
        }

        if (cap.tools.searchsploit && row.searchBlob && seenQueries.size < 12) {
          const key = row.searchBlob.toLowerCase().slice(0, 60);
          if (seenQueries.has(key)) continue;
          seenQueries.add(key);
          const hits = await searchExploitDbOne(row.searchBlob, log);
          for (const hit of hits.slice(0, 4)) {
            const title = exploitTitle(hit);
            addFinding({
              type: 'exploit',
              prio: 'high',
              score: 82,
              value: title,
              meta: `Exploit-DB / searchsploit — ref. a «${row.searchBlob.slice(0, 50)}»`,
              url: exploitUrl(hit) || undefined,
            });
          }
          if (hits.length) log(`searchsploit: ${hits.length} entrada(s) para «${row.searchBlob.slice(0, 40)}…»`, 'find');
        }
      }
      for (const row of rows) {
        if (row.port === '443' || row.port === '80') {
          const u = row.port === '443' ? `https://${row.host}/` : `http://${row.host}/`;
          if (!baseUrlsForFfuf.includes(u)) baseUrlsForFfuf.push(u);
        }
      }
    } catch (e) {
      log(`nmap: ${e.message}`, 'error');
    } finally {
      pipeTool('nmap', 'done');
    }
  } else {
    pipeTool('nmap', 'skip');
  }

  // ── WHOIS (Kali) ──
  // WHOIS é leitura externa (não é exploit), mas ainda assim é "ativo". Mantemos só quando ferramenta existe
  // e com amostra limitada de subdomínios para não explodir tempo.
  if (cap.tools.whois) {
    pipeTool('whois', 'active');
    log('═══ whois (registo domínio) ═══', 'section');

    const whoisTargets = [domain, ...(subdomainsAlive || [])]
      .map(sanitizeHost)
      .filter(Boolean)
      .slice(0, 1 + (process.env.GHOSTRECON_WHOIS_SUBDOMAINS_MAX ? Number(process.env.GHOSTRECON_WHOIS_SUBDOMAINS_MAX) : limits.whoisSubdomainsMax));

    // Normalmente whois em subdomínios devolve o mesmo registo do domínio raiz.
    // Ainda assim, seguimos a tua ideia e executamos numa amostra pequena.
    for (const t of whoisTargets) {
      try {
        const { text } = await runWhoisJsonLike({ target: t, timeoutMs: limits.whoisTimeoutMs, log });
        const parsed = parseWhoisText(t, text);
        if (!parsed.hasSomething) continue;
        const ns = parsed.nameServers?.slice(0, 6) || [];
        const valueParts = [
          parsed.registrar ? `Registrar: ${parsed.registrar}` : null,
          parsed.expires ? `Expires: ${parsed.expires}` : null,
          parsed.created ? `Created: ${parsed.created}` : null,
        ].filter(Boolean);

        addFinding(
          {
            type: 'whois',
            prio: 'low',
            score: 26,
            value: valueParts.length ? valueParts.join(' | ') : `whois: ${t}`,
            meta: [
              parsed.domainOrHost ? `Target: ${parsed.domainOrHost}` : null,
              parsed.registrantCountry ? `Country: ${parsed.registrantCountry}` : null,
              ns.length ? `NS: ${ns.join(', ')}` : null,
              parsed.updated ? `Updated: ${parsed.updated}` : null,
            ]
              .filter(Boolean)
              .join(' • '),
            url: null,
          },
          null,
        );
      } catch (e) {
        log(`whois ${t}: ${e.message}`, 'warn');
      }
    }
    pipeTool('whois', 'done');
  } else {
    pipeTool('whois', 'skip');
  }

  if (runFfuf && cap.tools.ffuf) {
    pipeTool('ffuf', 'active');
    log('═══ ffuf (apenas HTTP 200) ═══', 'section');
    const uniqBases = [...new Set(baseUrlsForFfuf)].slice(0, 5);
    for (const u of uniqBases) {
      const paths = await runFfuf200(u, log);
      for (const p of paths) {
        addFinding(
          {
            type: 'endpoint',
            prio: 'high',
            score: 72,
            value: p,
            meta: 'ffuf • código 200',
            url: p,
          },
          'endpoints',
        );
      }
      if (paths.length) log(`ffuf ${u} → ${paths.length} caminho(s) 200`, 'success');
    }
    pipeTool('ffuf', 'done');
  } else {
    pipeTool('ffuf', 'skip');
    if (!runFfuf && cap.tools.ffuf) {
      log('ffuf: omitido — activa o módulo «Ffuf (Kali)» em Sensitive Data (só com Modo Kali).', 'info');
    }
  }

  if (runNuclei && cap.tools.nuclei) {
    pipeTool('nuclei', 'active');
    log('═══ nuclei ═══', 'section');
    const targets = [...new Set(baseUrlsForFfuf.map((b) => b.replace(/\/$/, '')))].slice(0, 15);
    try {
      const findings = await runNucleiList(targets, log);
      for (const f of findings) {
        const matched = f['matched-at'] || f.host || f.url || '';
        const tid = f['template-id'] || f.templateID || 'template';
        const sev = f.info?.severity || f.severity || 'info';
        addFinding({
          type: 'nuclei',
          prio: ['critical', 'high'].includes(String(sev).toLowerCase()) ? 'high' : 'med',
          score: sev === 'critical' ? 95 : sev === 'high' ? 88 : 60,
          value: `${tid} @ ${matched}`,
          meta: nucleiEvidenceMeta({
            tid,
            sev,
            extra: matched ? `matched=${String(matched).slice(0, 120)}` : null,
          }),
          url: matched.startsWith('http') ? matched : null,
        });
      }
      log(`nuclei: ${findings.length} finding(s)`, findings.length ? 'warn' : 'info');
    } catch (e) {
      log(`nuclei: ${e.message}`, 'warn');
    } finally {
      pipeTool('nuclei', 'done');
    }
  } else {
    pipeTool('nuclei', 'skip');
    if (!runNuclei && cap.tools.nuclei) {
      log('Nuclei: omitido — activa o módulo «Nuclei (Kali)» em Sensitive Data (só com Modo Kali).', 'info');
    }
  }

  // XSS/SQLi via nuclei tags contra URLs com query string (vindas do corpus passivo)
  const canParamNuclei = runNuclei && cap.tools.nuclei && Array.isArray(paramUrls) && paramUrls.length;
  if (!canParamNuclei) {
    pipeTool('nuclei_xss', 'skip');
    pipeTool('nuclei_sqli', 'skip');
  } else {
    const urls = [...new Set(paramUrls)].slice(0, 30);

    if (xssSignals) {
      pipeTool('nuclei_xss', 'active');
      log(`═══ nuclei (xss) em URLs com parâmetros (${urls.length}) ═══`, 'section');
      try {
        const xss = await runNucleiTags(urls, 'xss', log);
        for (const f of xss) {
          const matched = f['matched-at'] || f.host || f.url || '';
          const tid = f['template-id'] || f.templateID || 'template';
          const sev = f.info?.severity || f.severity || 'info';
          addFinding({
            type: 'xss',
            prio: ['critical', 'high'].includes(String(sev).toLowerCase()) ? 'high' : 'med',
            score: sev === 'critical' ? 95 : sev === 'high' ? 90 : 70,
            value: `${tid} @ ${matched}`,
            meta: nucleiEvidenceMeta({ tid, sev, extra: 'tags=xss' }),
            url: matched.startsWith('http') ? matched : null,
          });
        }
        if (xss.length) log(`XSS: ${xss.length} finding(s)`, 'warn');
      } catch (e) {
        log(`XSS nuclei: ${e.message}`, 'warn');
      } finally {
        pipeTool('nuclei_xss', 'done');
      }
    } else {
      log('nuclei tags=xss: skip (sem sinais passivos)', 'info');
      pipeTool('nuclei_xss', 'skip');
    }

    if (sqliSignals) {
      pipeTool('nuclei_sqli', 'active');
      log(`═══ nuclei (sqli) em URLs com parâmetros (${urls.length}) ═══`, 'section');
      try {
        const sqli = await runNucleiTags(urls, 'sqli', log);
        for (const f of sqli) {
          const matched = f['matched-at'] || f.host || f.url || '';
          const tid = f['template-id'] || f.templateID || 'template';
          const sev = f.info?.severity || f.severity || 'info';
          addFinding({
            type: 'sqli',
            prio: ['critical', 'high'].includes(String(sev).toLowerCase()) ? 'high' : 'med',
            score: sev === 'critical' ? 98 : sev === 'high' ? 92 : 72,
            value: `${tid} @ ${matched}`,
            meta: nucleiEvidenceMeta({ tid, sev, extra: 'tags=sqli' }),
            url: matched.startsWith('http') ? matched : null,
          });
        }
        if (sqli.length) log(`SQLi: ${sqli.length} finding(s)`, 'warn');
      } catch (e) {
        log(`SQLi nuclei: ${e.message}`, 'warn');
      } finally {
        pipeTool('nuclei_sqli', 'done');
      }
    } else {
      log('nuclei tags=sqli: skip (sem sinais passivos)', 'info');
      pipeTool('nuclei_sqli', 'skip');
    }
  }

  if (cap.tools.wpscan) {
    const detectionMode = process.env.GHOSTRECON_WPSCAN_DETECTION_MODE || 'mixed';
    const timeoutMs = Number(process.env.GHOSTRECON_WPSCAN_TIMEOUT_MS || 240000);

    log('═══ WPScan — ferramenta wpscan (WordPress) ═══', 'section');
    const targets = Array.isArray(wordpressTargets) ? wordpressTargets : null;

    if (!targets || targets.length === 0) {
      log('[WPScan] WordPress não confirmado no passivo — wpscan não executado', 'info');
      pipeTool('wpscan', 'skip');
    } else if (isWpscanApiRequired() && !isWpscanApiTokenConfigured()) {
      log(
        '[WPScan] SKIP — token obrigatório (GHOSTRECON_WPSCAN_REQUIRE_API≠0). Define WPSCAN_API_TOKEN ou GHOSTRECON_WPSCAN_API_TOKEN no .env (wpscan.com/register). Para permitir scan sem WPVulnDB: GHOSTRECON_WPSCAN_REQUIRE_API=0',
        'warn',
      );
      pipeTool('wpscan', 'skip');
    } else {
      pipeTool('wpscan', 'active');
      if (isWpscanApiTokenConfigured()) {
        log(
          '[WPScan] WPVulnDB ligado — WPSCAN_API_TOKEN / GHOSTRECON_WPSCAN_API_TOKEN (CVEs conhecidos no JSON)',
          'success',
        );
      } else {
        log(
          '[WPScan] WPVulnDB desligado — sem token; só enumeração core/tema/plugins. Recomendado: WPSCAN_API_TOKEN no .env',
          'warn',
        );
      }
      const uniqTargets = [...new Set(targets)].slice(0, 6);
      log(`[WPScan] ${uniqTargets.length} alvo(s) WordPress — a iniciar wpscan em cada URL`, 'info');
      for (const t of uniqTargets) {
        log(`[WPScan] ▶︎ alvo: ${t}`, 'info');
        const res = await runWpscanJson({ targetUrl: t, detectionMode, timeoutMs, log });
        if (res?.json) {
          const findings = extractWpscanFindings({ targetUrl: t, wpscanJson: res.json });
          const vulnN = Number.isFinite(res.vulnDbCount) ? res.vulnDbCount : countWpvulndbFindings(res.json);
          if (findings.length) {
            log(
              `[WPScan] ✓ concluído ${t} → ${findings.length} achado(s) na lista (${vulnN} entrada(s) WPVulnDB/CVE no JSON)`,
              'success',
            );
          } else {
            log(`[WPScan] ✓ concluído ${t} → sem achados extraídos (JSON OK)`, 'info');
          }
          for (const f of findings) addFinding(f, null);
        } else {
          addFinding({
            type: 'wpscan',
            prio: 'low',
            score: 10,
            value: `wpscan failed @ ${t}`,
            meta: res?.error || 'unknown error',
            url: t,
          });
          log(`[WPScan] ✗ ${t}: sem JSON válido (${res?.error || 'unknown'})`, 'warn');
        }
      }
      log('[WPScan] Fim da fase wpscan (todos os alvos WordPress desta corrida)', 'info');
      pipeTool('wpscan', 'done');
    }
  } else {
    pipeTool('wpscan', 'skip');
  }

  if (cap.tools.dalfox && xssSignals && Array.isArray(paramUrls) && paramUrls.length) {
    pipeTool('dalfox', 'active');
    const targets = [...new Set(paramUrls)].slice(0, Number(process.env.GHOSTRECON_DALFOX_MAX_URLS || 12));
    log(`═══ dalfox (XSS) em URLs com parâmetros (${targets.length}) ═══`, 'section');
    try {
    for (const u of targets) {
      const r = await runDalfoxUrl(u, log, auth);
      if (!r.ok) {
        log(`dalfox ${u}: ${r.error}`, 'warn');
        continue;
      }
      for (const h of r.hits) {
        addFinding({
          type: 'dalfox',
          prio: 'high',
          score: 90,
          value: `dalfox hit @ ${u}`,
          meta: `scanner=dalfox • format=${r.stdoutFormat || 'mixed'} • confidence=tool_output • ${h}`,
          url: u,
        });
      }
      if (r.hits.length) log(`dalfox ${u} → ${r.hits.length} hit(s)`, 'warn');
    }
    } finally {
      pipeTool('dalfox', 'done');
    }
  } else if (cap.tools.dalfox && !xssSignals && Array.isArray(paramUrls) && paramUrls.length) {
    log('dalfox: skip (sem sinais XSS passivos)', 'info');
    pipeTool('dalfox', 'skip');
  } else {
    pipeTool('dalfox', 'skip');
  }

  // Executa após a etapa XSS (nuclei/dalfox): scanner xss_vibes externo.
  if (cap.tools.xss_vibes && xssSignals && Array.isArray(paramUrls) && paramUrls.length) {
    pipeTool('xss_vibes', 'active');
    log(`═══ xss_vibes (XSS) em URLs com parâmetros (${paramUrls.length}) ═══`, 'section');
    try {
    const r = await runXssVibesBatch({ urls: paramUrls, cap, log, auth });
    if (!r.ok) {
      log(`[xss_vibes] erro: ${r.error || 'falha desconhecida'}`, 'warn');
    } else {
      for (const hit of r.hits) {
        addFinding({
          type: 'xss',
          prio: 'high',
          score: 93,
          value: `xss_vibes hit @ ${hit}`,
          meta: 'scanner=xss_vibes • confidence=tool_output',
          url: hit,
        });
      }
      if (r.hits.length) log(`[xss_vibes] ${r.hits.length} hit(s) adicionado(s) como finding XSS`, 'warn');
    }
    } finally {
      pipeTool('xss_vibes', 'done');
    }
  } else if (cap.tools.xss_vibes && !xssSignals && Array.isArray(paramUrls) && paramUrls.length) {
    log('[xss_vibes] skip (sem sinais XSS passivos)', 'info');
    pipeTool('xss_vibes', 'skip');
  } else if (!cap.tools.xss_vibes) {
    log('[xss_vibes] indisponível (python + Xss/xss_vibes/main.py/payloads.json)', 'info');
    pipeTool('xss_vibes', 'skip');
  } else {
    pipeTool('xss_vibes', 'skip');
  }

  log('═══ Fim modo Kali ═══', 'section');
}
