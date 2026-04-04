import { mkdtemp, rm, readFile } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { spawn } from 'node:child_process';
import { UA } from '../config.js';

const DEFAULT_PREFIXES = [
  'www',
  'api',
  'flow',
  'dev',
  'test',
  'staging',
  'admin',
  'mail',
  'app',
  'lb-test',
  'cdn',
  'beta',
  'portal',
  'dashboard',
  'internal',
  'vpn',
];

function parseExtraPrefixes(raw) {
  if (!raw) return [];
  return String(raw)
    .split(/[\n,\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter((s) => /^[a-z0-9-]{1,40}$/.test(s));
}

async function curlGetWithHost({ targetUrl, hostHeader, timeoutSec }) {
  const dir = await mkdtemp(join(tmpdir(), 'ghvh-'));
  const headersPath = join(dir, 'h.txt');
  const bodyPath = join(dir, 'b.bin');
  const args = [
    '-k',
    '-sS',
    '-L',
    '--max-redirs',
    '4',
    '--connect-timeout',
    String(timeoutSec),
    '--max-time',
    String(timeoutSec),
    '-A',
    UA,
    '-H',
    `Host: ${hostHeader}`,
    '-D',
    headersPath,
    '-o',
    bodyPath,
    targetUrl,
  ];

  const proc = await new Promise((resolve, reject) => {
    const child = spawn('curl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const err = [];
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stderr: Buffer.concat(err).toString('utf8') }));
  });

  let headersText = '';
  let bodyBuf = Buffer.alloc(0);
  try {
    headersText = await readFile(headersPath, 'utf8');
    bodyBuf = await readFile(bodyPath);
  } catch {
    /* */
  } finally {
    await rm(dir, { recursive: true, force: true });
  }

  const first = String(headersText || '').split(/\r?\n\r?\n/).find((b) => /HTTP\//i.test(b)) || '';
  const m = first.split(/\r?\n/)[0]?.match(/HTTP\/\d(?:\.\d)?\s+(\d{3})\b/i);
  const status = m ? Number(m[1]) : 0;
  return { status, bodyLen: bodyBuf.length, ok: proc.code === 0 };
}

/**
 * Compara respostas HTTP ao mesmo URL com Host: apex vs Host: prefix.apex — padrão CTF9 / nginx vhost.
 */
export async function runVhostPrefixFuzz({
  ip,
  baseDomain,
  extraPrefixes = '',
  log,
  timeoutMs = 12000,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const dom = String(baseDomain || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .split('/')[0];
  if (!dom || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(dom)) {
    logger('VHost fuzz: domínio base inválido — preenche (ex.: projects-blogo.sy).', 'warn');
    return { hits: [], baseline: null };
  }

  const timeoutSec = Math.max(2, Math.floor(timeoutMs / 1000));
  const targetUrl = `http://${ip}/`;
  const prefixes = [...new Set([...DEFAULT_PREFIXES, ...parseExtraPrefixes(extraPrefixes)])];

  logger(`VHost fuzz: baseline GET ${targetUrl} com Host: ${dom}`, 'info');
  let baseline;
  try {
    baseline = await curlGetWithHost({ targetUrl, hostHeader: dom, timeoutSec });
  } catch (e) {
    logger(`VHost fuzz: baseline falhou — ${e?.message || String(e)}`, 'warn');
    return { hits: [], baseline: null };
  }

  const hits = [];
  const thresh = Math.max(250, Math.floor(baseline.bodyLen * 0.12));

  for (const pre of prefixes) {
    const hostH = `${pre}.${dom}`;
    try {
      const r = await curlGetWithHost({ targetUrl, hostHeader: hostH, timeoutSec });
      const delta = Math.abs(r.bodyLen - baseline.bodyLen);
      const statusDiff = r.status !== baseline.status;
      if (delta >= thresh || statusDiff) {
        hits.push({
          hostHeader: hostH,
          status: r.status,
          bodyLen: r.bodyLen,
          baselineLen: baseline.bodyLen,
          delta,
        });
        logger(
          `VHost fuzz: candidato ${hostH} — HTTP ${r.status} · corpo=${r.bodyLen} B (baseline ${baseline.bodyLen} B, Δ=${delta})`,
          'success',
        );
      }
    } catch {
      /* */
    }
  }

  return { hits, baseline: { status: baseline.status, bodyLen: baseline.bodyLen } };
}
