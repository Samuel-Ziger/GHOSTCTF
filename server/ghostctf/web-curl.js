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
  // Em -D - + redirects, pode ter múltiplos blocos.
  const t = String(bufText || '');
  const parts = t.split(/\r?\n\r?\n/);
  // remove blocos finais vazios
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

async function runCurl({ url, timeoutMs = 12000, maxBodyBytes = 250_000 }) {
  const dir = await mkdtemp(join(tmpdir(), 'ghcurl-'));
  const headersPath = join(dir, 'headers.txt');
  const bodyPath = join(dir, 'body.bin');

  // -k: ignora TLS invalid (muitos CTFs têm cert self-signed)
  // -L + --max-redirs 1: tenta seguir no máximo 1 redirect para evitar explosão de múltiplos headers
  const args = [
    '-k',
    '-sS',
    '-L',
    '--max-redirs',
    '1',
    '--connect-timeout',
    String(Math.max(1, Math.floor(timeoutMs / 1000))),
    '--max-time',
    String(Math.max(1, Math.floor(timeoutMs / 1000))),
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
    child.on('close', (code) => {
      resolve({ code, stderr: Buffer.concat(errChunks).toString('utf8') });
    });
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
  // para heurísticas, tentamos utf8 com replacement
  const bodyText = bodySlice.toString('utf8');
  const techHints = detectTech(
    {
      get: (n) => headersMap.get(String(n || '').toLowerCase()) || '',
    },
    bodyText,
  );

  return {
    ok: true,
    url,
    status: status ?? 0,
    headersText,
    headers: headersMap,
    bodyText,
    tech: techHints,
    curlExitCode: proc.code,
    curlStderr: proc.stderr || '',
  };
}

function isProbablyWebPort(port) {
  const p = Number(port);
  if (!Number.isFinite(p)) return false;
  return [80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 9443, 3000, 5000, 5001, 8888].includes(p);
}

function isProbablyHttpService(name, product) {
  const s = `${name || ''} ${product || ''}`.toLowerCase();
  return s.includes('http') || s.includes('https') || s.includes('nginx') || s.includes('apache') || s.includes('ssl/http');
}

export async function curlWebFromNmap({ ip, nmapRows, timeoutMs, maxBodyBytes, log }) {
  const webCandidates = [];
  const seen = new Set();

  for (const r of nmapRows || []) {
    if (String(r.proto).toLowerCase() !== 'tcp') continue;
    const port = Number(r.port);
    if (!Number.isFinite(port)) continue;

    const name = r.name || '';
    const product = r.product || '';
    if (!isProbablyWebPort(port) && !isProbablyHttpService(name, product) && !isProbablyHttpService(r.extrainfo, name)) continue;

    const httpUrl = `http://${ip}:${port}/`;
    const httpsUrl = `https://${ip}:${port}/`;

    // tenta HTTP primeiro; se falhar, tenta HTTPS (muitas VMs aceitam só um)
    for (const u of [httpUrl, httpsUrl]) {
      if (seen.has(u)) continue;
      seen.add(u);
      webCandidates.push({ url: u, port, portName: name, proto: 'tcp' });
    }
  }

  if (!webCandidates.length) {
    // fallback: só tenta em portas conhecidas se nmap não deu hints
    const defaults = [80, 443, 8080, 8081, 8000, 8443];
    for (const p of defaults) {
      webCandidates.push({ url: `http://${ip}:${p}/`, port: p, proto: 'tcp' });
      webCandidates.push({ url: `https://${ip}:${p}/`, port: p, proto: 'tcp' });
    }
  }

  const out = [];
  for (const c of webCandidates) {
    try {
      if (typeof log === 'function') log(`curl web: ${c.url}`, 'info');
      const r = await runCurl({ url: c.url, timeoutMs, maxBodyBytes });
      out.push({
        port: c.port,
        url: c.url,
        status: r.status,
        headersText: r.headersText,
        bodyText: r.bodyText,
        tech: r.tech,
      });
    } catch (e) {
      // ignora failures: CTFs costumam ter portas “abertas” mas não web de verdade
      out.push({ port: c.port, url: c.url, status: 0, headersText: '', bodyText: '', tech: [] });
    }
  }

  return out;
}

