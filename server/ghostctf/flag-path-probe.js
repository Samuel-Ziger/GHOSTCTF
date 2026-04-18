import { curlWebSingle } from './web-curl-single.js';
import { ghostctfPositiveIntEnv } from './env-budgets.js';

/**
 * Caminhos HTTP comuns em CTF (read-only GET). O pipeline já faz dir-enum;
 * isto cobre ficheiros “óbvios” na raiz do vhost sem wordlist.
 */
const CTF_FLAG_HTTP_PATHS = [
  '/flag',
  '/flag.txt',
  '/root/flag.txt',
  '/user.txt',
  '/proof.txt',
  '/secret.txt',
  '/.flag',
  '/var/www/html/flag.txt',
  '/var/www/html/flag',
  '/home/user/flag.txt',
  '/home/www/flag.txt',
];

function collectOrigins(webResponses, ip) {
  const origins = new Set();
  for (const r of webResponses || []) {
    if (!r?.url || !r?.status) continue;
    try {
      const u = new URL(String(r.url));
      origins.add(`${u.protocol}//${u.host}`);
    } catch {
      /* ignore */
    }
  }
  if (!origins.size && ip) origins.add(`http://${ip}`);
  return [...origins];
}

/**
 * GET nos paths fixos por origem já descoberta (mesma lógica que disclosure/robots).
 * Respostas são acrescentadas a `webResponses` com `__via=ctf-flag-paths` para o scan de flags.
 */
export async function appendCtfFlagPathHttpProbes(webResponses, {
  ip,
  log,
  timeoutMs = 9000,
  maxBodyBytes = 140000,
  maxOrigins = 10,
  maxPathsPerOrigin = 10,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const capOrigins = ghostctfPositiveIntEnv('GHOSTCTF_MAX_FLAGPATH_ORIGINS', maxOrigins);
  const capPaths = ghostctfPositiveIntEnv('GHOSTCTF_MAX_FLAGPATH_PATHS_PER_ORIGIN', maxPathsPerOrigin);
  const origins = collectOrigins(webResponses, ip).slice(0, Math.max(1, capOrigins));
  const seen = new Set((webResponses || []).map((r) => String(r?.url || '')).filter(Boolean));
  let fetched = 0;
  let tried = 0;
  const paths = CTF_FLAG_HTTP_PATHS.slice(0, Math.max(1, capPaths));

  for (const origin of origins) {
    const base = String(origin).replace(/\/$/, '');
    for (const p of paths) {
      const u = `${base}${p}`;
      if (seen.has(u)) continue;
      tried += 1;
      try {
        logger(`[http] CTF flag-path → GET ${u}`, 'info');
        const r = await curlWebSingle({ url: u, timeoutMs, maxBodyBytes });
        seen.add(u);
        r.__via = 'ctf-flag-paths';
        r.__ctfFlagPath = p;
        webResponses.push(r);
        fetched += 1;
        if (r.status === 200) {
          logger(`CTF flag-path: HTTP 200 — ${u}`, 'find');
        }
      } catch (e) {
        logger(`CTF flag-path: erro ${u} — ${e?.message || e}`, 'info');
      }
    }
  }

  return { fetched, tried, origins: origins.length };
}
