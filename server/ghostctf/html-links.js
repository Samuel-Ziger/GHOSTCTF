import { curlWebSingle } from './web-curl-single.js';

/** Hostname do URL deve coincidir com o IP do alvo (recon por IP). */
export function hostMatchesTarget(hostname, targetIp) {
  const h = String(hostname || '').toLowerCase();
  const t = String(targetIp || '').toLowerCase();
  return h === t;
}

export function urlDedupKey(href) {
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

/**
 * Extrai URLs http(s) no mesmo host que targetIp a partir de HTML (href, action).
 * Resolve relativas contra baseUrl.
 */
export function extractInScopeHttpUrls(html, baseUrl, targetIp) {
  const out = new Set();
  const base = String(baseUrl || '');
  if (!html || !base) return [];

  const tryAdd = (raw) => {
    let h = String(raw || '').trim();
    if (!h || h.startsWith('#')) return;
    const low = h.toLowerCase();
    if (
      low.startsWith('javascript:') ||
      low.startsWith('mailto:') ||
      low.startsWith('tel:') ||
      low.startsWith('data:') ||
      low.startsWith('blob:')
    ) {
      return;
    }
    let abs;
    try {
      abs = new URL(h, base);
    } catch {
      return;
    }
    if (abs.protocol !== 'http:' && abs.protocol !== 'https:') return;
    if (!hostMatchesTarget(abs.hostname, targetIp)) return;
    abs.hash = '';
    out.add(abs.href);
  };

  const re = /(?:href|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const val = String(m[1] ?? m[2] ?? m[3] ?? '').trim();
    if (val) tryAdd(val);
  }

  return [...out];
}

/**
 * Faz curl em páginas descobertas por links no HTML (BFS por profundidade).
 * Altera webResponses in-place (push dos novos curl).
 * @returns {{ fetched: number }}
 */
export async function expandWebResponsesWithLinkCrawl(webResponses, {
  ip,
  log,
  maxDepth = 2,
  maxNewFetches = 40,
  timeoutMs = 12000,
  maxBodyBytes = 250_000,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const seen = new Set();
  for (const r of webResponses || []) {
    if (r?.url) seen.add(urlDedupKey(r.url));
  }

  let fetched = 0;
  let frontier = (webResponses || []).filter((r) => r && r.status && r.bodyText && r.url);

  for (let d = 0; d < maxDepth && fetched < maxNewFetches; d += 1) {
    const nextFrontier = [];
    for (const r of frontier) {
      const links = extractInScopeHttpUrls(String(r.bodyText), String(r.url), ip);
      for (const link of links) {
        if (fetched >= maxNewFetches) break;
        const k = urlDedupKey(link);
        if (seen.has(k)) continue;
        seen.add(k);
        try {
          logger(`curl link HTML (nível ${d + 1}): ${link}`, 'info');
          const resp = await curlWebSingle({ url: link, timeoutMs, maxBodyBytes });
          fetched += 1;
          webResponses.push(resp);
          if (resp.status && resp.bodyText) nextFrontier.push(resp);
        } catch {
          /* ignorar timeouts / falhas de rede */
        }
      }
      if (fetched >= maxNewFetches) break;
    }
    frontier = nextFrontier;
  }

  return { fetched };
}
