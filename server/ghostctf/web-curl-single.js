import fs from 'fs';
import { mkdtemp, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { UA } from '../config.js';
import { detectTech } from '../modules/tech.js';

function parseHttpHeadersBlock(raw) {
  const out = new Map();
  const lines = String(raw || '').split(/\r?\n/).filter(Boolean);
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const k = line.slice(0, idx).trim().toLowerCase();
    const v = line.slice(idx + 1).trim();
    out.set(k, v);
  }
  return out;
}

function extractLastHeaderBlock(bufText) {
  const t = String(bufText || '');
  const parts = t.split(/\r?\n\r?\n/);
  for (let i = parts.length - 1; i >= 0; i--) {
    if (parts[i].trim()) return parts[i];
  }
  return '';
}

function parseStatusCode(headersText) {
  const firstLine = String(headersText || '').split(/\r?\n/)[0] || '';
  const m = firstLine.match(/HTTP\/\d\.\d\s+(\d{3})/i);
  return m ? Number(m[1]) : null;
}

export async function curlWebSingle({ url, timeoutMs = 12000, maxBodyBytes = 250000 }) {
  const dir = await mkdtemp(join(tmpdir(), 'ghcurl1-'));
  const headersPath = join(dir, 'headers.txt');
  const bodyPath = join(dir, 'body.bin');

  const timeoutSec = String(Math.max(1, Math.floor(timeoutMs / 1000)));
  const args = [
    '-k',
    '-sS',
    '-L',
    '--max-redirs',
    '1',
    '--connect-timeout',
    timeoutSec,
    '--max-time',
    timeoutSec,
    '-A',
    UA,
    '-D',
    headersPath,
    '-o',
    bodyPath,
    url,
  ];

  const { spawn } = await import('node:child_process');
  const proc = await new Promise((resolve, reject) => {
    const child = spawn('curl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const errChunks = [];
    child.stderr.on('data', (d) => errChunks.push(d));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stderr: Buffer.concat(errChunks).toString('utf8') }));
  });

  let headersText = '';
  let bodyBuf = Buffer.alloc(0);
  try {
    headersText = await fs.promises.readFile(headersPath, 'utf8');
    bodyBuf = await fs.promises.readFile(bodyPath);
  } catch {
    // ignore
  } finally {
    await rm(dir, { recursive: true, force: true });
  }

  const lastHeaders = extractLastHeaderBlock(headersText);
  const headersMap = parseHttpHeadersBlock(lastHeaders);
  const status = parseStatusCode(lastHeaders);
  const bodySlice = bodyBuf.length > maxBodyBytes ? bodyBuf.slice(0, maxBodyBytes) : bodyBuf;
  const bodyText = bodySlice.toString('utf8');

  const techHints = detectTech(
    {
      get: (n) => headersMap.get(String(n || '').toLowerCase()) || '',
    },
    bodyText,
  );

  return { ok: true, url, status: status ?? 0, headersText, headers: headersMap, bodyText, tech: techHints, curlExitCode: proc.code };
}

