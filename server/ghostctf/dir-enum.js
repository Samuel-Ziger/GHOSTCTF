import fs from 'fs';
import { mkdtemp, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { spawn } from 'node:child_process';

const WORDLISTS = [
  '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt',
  '/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt',
  '/usr/share/seclists/Discovery/Web-Content/common.txt',
  '/usr/share/wordlists/dirb/common.txt',
];

function whichTool(cmd) {
  return new Promise((resolve) => {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const p = spawn(finder, [cmd], { stdio: ['ignore', 'pipe', 'pipe'] });
    p.on('error', () => resolve(false));
    p.on('close', (c) => resolve(c === 0));
  });
}

function pickFirstExisting(files) {
  for (const f of files) {
    try {
      if (fs.existsSync(f)) return f;
    } catch {
      /* */
    }
  }
  return null;
}

function runProc(cmd, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const t = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        /* */
      }
      reject(new Error(`${cmd} timeout (${timeoutMs}ms)`));
    }, timeoutMs);

    const out = [];
    const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => {
      clearTimeout(t);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(t);
      resolve({
        code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      });
    });
  });
}

export function urlDedupDirEnum(href) {
  try {
    const u = new URL(href);
    u.hash = '';
    let path = u.pathname;
    if (path.length > 1 && path.endsWith('/')) path = path.slice(0, -1);
    u.pathname = path || '/';
    return u.href;
  } catch {
    return String(href || '');
  }
}

function parseGobusterHits(stdout, stderr, baseUrl) {
  const base = String(baseUrl || '').replace(/\/$/, '');
  const text = `${stdout}\n${stderr}`;
  const hits = new Set();
  for (const line of text.split(/\r?\n/)) {
    const m1 = line.match(/^(https?:\/\/\S+)/);
    if (m1) {
      hits.add(m1[1].replace(/[\])}'"]+$/, ''));
      continue;
    }
    const m2 = line.match(/^\s*(\/?[^\s(]+)\s*\(Status:\s*\d+/);
    if (m2) {
      try {
        hits.add(new URL(m2[1], `${base}/`).href);
      } catch {
        /* */
      }
    }
  }
  return [...hits];
}

function parseDirbHits(stdout) {
  const hits = new Set();
  for (const line of String(stdout).split(/\r?\n/)) {
    const m = line.match(/^\+\s+(https?:\/\/\S+)/);
    if (!m) continue;
    let u = m[1];
    const pipe = u.indexOf('|');
    if (pipe !== -1) u = u.slice(0, pipe);
    hits.add(u.trim());
  }
  return [...hits];
}

/**
 * ffuf — JSON.
 */
export async function ffufDirEnum({ baseUrl, timeoutMs = 120000, log, maxResults = 120 } = {}) {
  const ffufOk = await whichTool('ffuf');
  if (!ffufOk) return { ok: false, tool: 'ffuf', urls: [], hint: 'ffuf não encontrado no PATH' };
  const wordlist = pickFirstExisting(WORDLISTS);
  if (!wordlist) return { ok: false, tool: 'ffuf', urls: [], hint: 'wordlist não encontrada (Seclists/dirb)' };

  const dir = await mkdtemp(join(tmpdir(), 'ghffuf-'));
  const outPath = join(dir, 'out.json');
  const u = String(baseUrl || '').replace(/\/$/, '');

  const args = [
    '-u',
    `${u}/FUZZ`,
    '-w',
    wordlist,
    '-mc',
    '200,204,301,302,307,401,403',
    '-t',
    '32',
    '-timeout',
    '10',
    '-maxtime',
    '90',
    '-of',
    'json',
    '-o',
    outPath,
    '-s',
  ];

  try {
    if (typeof log === 'function') log(`ffuf dirs: ${u}/`, 'info');
    await runProc('ffuf', args, timeoutMs);
    const raw = await fs.promises.readFile(outPath, 'utf8');
    const j = JSON.parse(raw);
    const urls = (j.results || [])
      .map((r) => r.url)
      .filter(Boolean)
      .slice(0, maxResults);
    return { ok: urls.length > 0, tool: 'ffuf', urls };
  } catch (e) {
    if (typeof log === 'function') log(`ffuf erro: ${e.message}`, 'warn');
    return { ok: false, tool: 'ffuf', urls: [], hint: e.message };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/**
 * gobuster dir (v3+): quiet, TLS skip, códigos alinhados ao ffuf.
 */
export async function gobusterDirEnum({ baseUrl, wordlist, timeoutMs = 120000, log, maxResults = 120 } = {}) {
  const ok = await whichTool('gobuster');
  if (!ok) return { ok: false, tool: 'gobuster', urls: [], hint: 'gobuster não encontrado no PATH' };
  if (!wordlist) return { ok: false, tool: 'gobuster', urls: [], hint: 'sem wordlist' };

  const u = String(baseUrl || '').replace(/\/$/, '');
  const target = `${u}/`;

  const args = [
    'dir',
    '-u',
    target,
    '-w',
    wordlist,
    '-t',
    '25',
    '-k',
    '-q',
    '--no-progress',
    '-s',
    '200,204,301,302,307,401,403',
    '--timeout',
    '10s',
  ];

  try {
    if (typeof log === 'function') log(`gobuster dirs: ${target}`, 'info');
    const { stdout, stderr, code } = await runProc('gobuster', args, Math.min(timeoutMs, 120000));
    const urls = parseGobusterHits(stdout, stderr, u).slice(0, maxResults);
    if (code !== 0 && !urls.length && typeof log === 'function') {
      log(`gobuster: exit ${code} (sem hits ou flags não suportadas nesta versão)`, 'info');
    }
    return { ok: urls.length > 0, tool: 'gobuster', urls };
  } catch (e) {
    if (typeof log === 'function') log(`gobuster erro: ${e.message}`, 'warn');
    return { ok: false, tool: 'gobuster', urls: [], hint: e.message };
  }
}

/**
 * dirb — modo não recursivo (-r) para não explodir tempo.
 */
export async function dirbDirEnum({ baseUrl, wordlist, timeoutMs = 120000, log, maxResults = 120 } = {}) {
  const ok = await whichTool('dirb');
  if (!ok) return { ok: false, tool: 'dirb', urls: [], hint: 'dirb não encontrado no PATH' };
  if (!wordlist) return { ok: false, tool: 'dirb', urls: [], hint: 'sem wordlist' };

  const u = String(baseUrl || '').replace(/\/$/, '');
  const target = `${u}/`;

  const args = [target, wordlist, '-S', '-r', '-w'];

  try {
    if (typeof log === 'function') log(`dirb: ${target}`, 'info');
    const { stdout } = await runProc('dirb', args, Math.min(timeoutMs, 120000));
    const urls = parseDirbHits(stdout, u).slice(0, maxResults);
    return { ok: urls.length > 0, tool: 'dirb', urls };
  } catch (e) {
    if (typeof log === 'function') log(`dirb erro: ${e.message}`, 'warn');
    return { ok: false, tool: 'dirb', urls: [], hint: e.message };
  }
}

/**
 * Corre ffuf, gobuster e dirb em paralelo (cada um devolve 0+ URLs) e faz merge deduplicado.
 */
export async function dirEnumAllTools({ baseUrl, log, timeoutMs = 90000, maxMergedUrls = 80 } = {}) {
  const wordlist = pickFirstExisting(WORDLISTS);
  if (!wordlist) {
    if (typeof log === 'function') log('dir enum: nenhuma wordlist em /usr/share/seclists ou dirb', 'warn');
    return { ok: false, urls: [], tools: [], hint: 'wordlist não encontrada' };
  }

  const perMs = Math.min(Number(timeoutMs) || 90000, 120000);
  const u = String(baseUrl || '').replace(/\/$/, '');

  const [ff, gb, db] = await Promise.all([
    ffufDirEnum({ baseUrl: u, log, timeoutMs: perMs }).catch(() => ({ urls: [], tool: 'ffuf' })),
    gobusterDirEnum({ baseUrl: u, wordlist, log, timeoutMs: perMs }).catch(() => ({ urls: [], tool: 'gobuster' })),
    dirbDirEnum({ baseUrl: u, wordlist, log, timeoutMs: perMs }).catch(() => ({ urls: [], tool: 'dirb' })),
  ]);

  const seen = new Set();
  const merged = [];

  const pushList = (list) => {
    for (const x of list || []) {
      if (!x) continue;
      const key = urlDedupDirEnum(String(x));
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(String(x).split('#')[0]);
      if (merged.length >= maxMergedUrls) return;
    }
  };

  pushList(ff.urls);
  pushList(gb.urls);
  pushList(db.urls);

  const tools = [
    ff.urls?.length ? 'ffuf' : null,
    gb.urls?.length ? 'gobuster' : null,
    db.urls?.length ? 'dirb' : null,
  ].filter(Boolean);

  if (typeof log === 'function' && merged.length) {
    log(`dir enum merge: ${merged.length} URL(s) únicas (ffuf=${ff.urls?.length || 0} gobuster=${gb.urls?.length || 0} dirb=${db.urls?.length || 0})`, 'success');
  }

  return { ok: merged.length > 0, urls: merged, tools };
}
