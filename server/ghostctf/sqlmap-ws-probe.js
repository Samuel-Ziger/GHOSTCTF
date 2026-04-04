import { spawn } from 'node:child_process';

function runProc(cmd, args, timeoutMs = 120000) {
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
        /* */
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

async function hasSqlmap() {
  const finder = process.platform === 'win32' ? 'where' : 'which';
  try {
    const r = await runProc(finder, ['sqlmap'], 5000);
    return r.code === 0;
  } catch {
    return false;
  }
}

function extractWsUrlsFromText(text) {
  const t = String(text || '');
  const found = [];
  const re = /\b(wss?:\/\/[^\s"'<>)\]}]+)/gi;
  let m;
  while ((m = re.exec(t)) !== null) {
    const u = String(m[1] || '').replace(/[,;.]+$/, '');
    if (u.length > 8 && u.length < 512) found.push(u);
  }
  return [...new Set(found)];
}

function collectWsUrls(webResponses, max = 24) {
  const out = [];
  const seen = new Set();
  for (const r of webResponses || []) {
    const chunks = [r?.bodyText, r?.headersText, r?.url, r?.finalUrl].map((x) => String(x || ''));
    for (const c of chunks) {
      for (const u of extractWsUrlsFromText(c)) {
        if (seen.has(u)) continue;
        seen.add(u);
        out.push(u);
        if (out.length >= max) return out;
      }
    }
  }
  return out;
}

function extractDbs(text) {
  const t = String(text || '');
  const dbs = [];
  const re = /\[\*\]\s+([^\r\n]+)/g;
  let m;
  while ((m = re.exec(t)) !== null) {
    const name = String(m[1] || '').trim();
    if (name && !dbs.includes(name)) dbs.push(name);
    if (dbs.length >= 12) break;
  }
  return dbs;
}

/**
 * SQLMap contra endpoints WebSocket (ex.: JSON com parâmetro injectável).
 * Usa --data com placeholder * num campo típico.
 */
export async function runSqlmapWsProbe({
  webResponses,
  log,
  maxTargets = 3,
  timeoutPerTargetMs = 120000,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const ok = await hasSqlmap();
  if (!ok) return { ok: false, reason: 'sqlmap_missing', attempts: 0, hits: [] };

  const urls = collectWsUrls(webResponses, maxTargets + 8).slice(0, maxTargets);
  if (!urls.length) return { ok: true, attempts: 0, hits: [] };

  const hits = [];
  let attempts = 0;
  const dataTemplates = ['{"id":"*"}', '{"bookID":"*"}', '{"q":"*"}', '{"user":"*"}'];

  wsloop: for (const wsUrl of urls) {
    for (const data of dataTemplates) {
      if (attempts >= maxTargets) break wsloop;
      attempts += 1;
      const args = [
        '-u',
        wsUrl,
        '--data',
        data,
        '--batch',
        '--level=2',
        '--risk=2',
        '--threads=2',
        '--timeout=10',
        '--retries=1',
        '--dbs',
      ];
      logger(`[sqlmap-ws] ${wsUrl} data=${data}`, 'info');
      try {
        const r = await runProc('sqlmap', args, timeoutPerTargetMs);
        const joined = `${r.stdout || ''}\n${r.stderr || ''}`;
        const low = joined.toLowerCase();
        const injectable =
          low.includes('is vulnerable') ||
          (low.includes('parameter') && low.includes('injectable')) ||
          low.includes('sql injection');
        const dbs = extractDbs(joined);
        if (injectable || dbs.length) {
          hits.push({
            url: wsUrl,
            data,
            injectable: Boolean(injectable),
            dbs,
            evidence: dbs.length ? `dbs=${dbs.join(',')}` : 'sqlmap (ws) indicou possível injeção',
          });
          break;
        }
      } catch (e) {
        logger(`[sqlmap-ws] ${wsUrl}: ${e?.message || String(e)}`, 'warn');
      }
    }
  }

  return { ok: true, attempts, hits };
}
