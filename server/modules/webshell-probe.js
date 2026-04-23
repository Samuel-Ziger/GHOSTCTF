import { stealthPause, pickStealthUserAgent } from './request-policy.js';
import { limits } from '../config.js';

/** Rotas típicas de webshell PHP (módulo conservador). */
export const WEBSHELL_HEURISTIC_PATHS = ['shell.php', 'c99.php', 'cmd.php'];

/**
 * Saída típica de `id` em Linux (evita HTML genérico que mencione "uid" em CSS/JS).
 */
export function looksLikeLinuxIdOutput(body, contentType = '') {
  const t = String(body || '');
  const len = t.length;
  if (len < 10 || len > 8000) return false;
  const ct = String(contentType || '').toLowerCase();
  const htmlish =
    /text\/html|application\/xhtml/i.test(ct) || /<(html|!doctype|head|body)\b/i.test(t.slice(0, 1200));
  if (htmlish && !/uid=\d+\s*\(/i.test(t)) return false;
  if (!/uid=\d+\s*\([^)]*\)\s*gid=\d+\s*\(/i.test(t)) return false;
  if (/<(script|style|svg)\b/i.test(t) && t.length > 800) return false;
  return true;
}

function buildHeaders(auth, modules) {
  const h = {
    'User-Agent': pickStealthUserAgent(modules),
    Accept: 'text/html,text/plain,*/*;q=0.8',
  };
  const extra = auth?.headers && typeof auth.headers === 'object' ? auth.headers : {};
  for (const [k, v] of Object.entries(extra)) {
    if (!k || v == null) continue;
    h[String(k)] = String(v);
  }
  if (auth?.cookie) h.Cookie = String(auth.cookie);
  return h;
}

/**
 * GET opcional `?cmd=id` em rotas conhecidas de webshell — muito conservador.
 * @param {{ origins: string[], auth?: object, modules?: string[], log?: function, maxOrigins?: number }} ctx
 * @returns {Promise<object[]>} achados `intel` (nunca "confirmed" automático)
 */
export async function runWebshellHeuristicProbe(ctx) {
  const { origins = [], auth = null, modules = [], log } = ctx || {};
  const maxO = Math.max(1, Math.min(14, Number(ctx?.maxOrigins) || 10));
  const timeoutMs = Math.max(5000, Number(limits.probeTimeoutMs) || 12000);
  const out = [];
  const uniq = [...new Set(origins.map((o) => String(o || '').trim()).filter(Boolean))].slice(0, maxO);

  for (const origin of uniq) {
    let base;
    try {
      const u = new URL(origin.endsWith('/') ? origin : `${origin}/`);
      base = `${u.protocol}//${u.host}/`;
    } catch {
      continue;
    }
    for (const path of WEBSHELL_HEURISTIC_PATHS) {
      const probeUrl = `${base}${path}?cmd=id`;
      await stealthPause(modules);
      try {
        const res = await fetch(probeUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs),
          headers: buildHeaders(auth, modules),
        });
        const raw = await res.text().catch(() => '');
        const text = raw.slice(0, 12000);
        const ct = res.headers.get('content-type') || '';
        if (res.status !== 200) continue;
        if (!looksLikeLinuxIdOutput(text, ct)) continue;
        const snippet = text.replace(/\s+/g, ' ').trim().slice(0, 160);
        out.push({
          type: 'intel',
          prio: 'high',
          score: 78,
          value: `Possível webshell (saída tipo \`id\`) — ${path} @ ${new URL(base).host}`,
          meta: `webshell_heuristic • url=${probeUrl} • revisar falso positivo (CMS, proxy, página de ajuda)`,
          url: probeUrl,
        });
        if (typeof log === 'function') log(`Webshell heurístico: sinal forte em ${probeUrl}`, 'warn');
      } catch {
        /* ignore */
      }
    }
  }
  return out;
}
