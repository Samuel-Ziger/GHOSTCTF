import { pickStealthUserAgent } from './request-policy.js';

function buildHeaders(auth = {}, modules = []) {
  const h = {
    'User-Agent': pickStealthUserAgent(modules),
    Accept: 'text/html,application/xhtml+xml,application/json,*/*;q=0.8',
  };
  const extra = auth?.headers && typeof auth.headers === 'object' ? auth.headers : {};
  for (const [k, v] of Object.entries(extra)) {
    if (!k || v == null) continue;
    h[String(k)] = String(v);
  }
  if (auth?.cookie) h.Cookie = String(auth.cookie);
  return h;
}

function resolveUrl(f) {
  if (f?.url && /^https?:\/\//i.test(String(f.url))) return String(f.url);
  const v = f?.value;
  if (typeof v === 'string' && /^https?:\/\//i.test(v)) return v;
  return null;
}

/**
 * Pedido HTTP leve em achados HIGH / HIGH_PROBABILITY com URL, para refrescar meta (status).
 */
export async function runHighPrioHttpRecheck({ findings, auth, modules, log, limit = 20 }) {
  const cap = Math.max(1, Number(process.env.GHOSTRECON_HIGH_RECHECK_MAX || limit));
  const picked = [];
  for (const f of findings || []) {
    if (picked.length >= cap) break;
    if (f?.prio !== 'high' && f?.attackTier !== 'HIGH_PROBABILITY') continue;
    const url = resolveUrl(f);
    if (!url) continue;
    picked.push({ f, url });
  }
  if (!picked.length) return { checked: 0 };
  if (typeof log === 'function') log(`Recheck HIGH: ${picked.length} URL(s) com GET rápido`, 'info');

  for (const { f, url } of picked) {
    try {
      const res = await fetch(url, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(12_000),
        headers: buildHeaders(auth, modules),
      });
      const tag = `recheck_http=${res.status}@${new Date().toISOString()}`;
      f.meta = [f.meta, tag].filter(Boolean).join(' • ');
    } catch (e) {
      const tag = `recheck_http=err:${String(e?.message || e).slice(0, 80)}@${new Date().toISOString()}`;
      f.meta = [f.meta, tag].filter(Boolean).join(' • ');
    }
  }
  return { checked: picked.length };
}
