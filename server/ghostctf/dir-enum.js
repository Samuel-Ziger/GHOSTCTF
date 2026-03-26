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
      // ignore
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
      } catch {}
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
      resolve({ code, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') });
    });
  });
}

export async function ffufDirEnum({ baseUrl, timeoutMs = 120000, log }) {
  const ffufOk = await whichTool('ffuf');
  if (!ffufOk) return { ok: false, hint: 'ffuf não encontrado no PATH' };
  const wordlist = pickFirstExisting(WORDLISTS);
  if (!wordlist) return { ok: false, hint: 'wordlist não encontrada (configure PATH/Seclists)' };

  const dir = await mkdtemp(join(tmpdir(), 'ghffuf-'));
  const outPath = join(dir, 'out.json');
  const u = baseUrl.replace(/\/$/, '');

  // Em CTF, respostas com 200 e 301/302 frequentemente indicam diretórios existentes.
  // Ajustamos apenas "merge" no cliente: o objetivo aqui é descobrir paths para tentar curl/flag scan.
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
    if (typeof log === 'function') log(`ffuf dirs: ${u}`, 'info');
    await runProc('ffuf', args, timeoutMs);
    const raw = await fs.promises.readFile(outPath, 'utf8');
    const j = JSON.parse(raw);
    const urls = (j.results || [])
      .map((r) => r.url)
      .filter(Boolean)
      .slice(0, 30);
    return { ok: true, urls };
  } catch (e) {
    if (typeof log === 'function') log(`ffuf erro: ${e.message}`, 'warn');
    return { ok: false, hint: e.message };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

