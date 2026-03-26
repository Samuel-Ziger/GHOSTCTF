import { curlWebSingle } from './web-curl-single.js';

/**
 * Para cada origem (protocolo + host:porta) onde já houve resposta HTTP no recon,
 * pede `/robots.txt`. Se não houver origens (curl falhou em tudo), tenta
 * `http://IP/robots.txt` e `https://IP/robots.txt`.
 * Só acrescenta ao array quando o servidor responde **200** (ficheiro existe).
 */
export async function appendRobotsTxtResponses(webResponses, {
  ip,
  log,
  timeoutMs = 10000,
  maxBodyBytes = 128000,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  /** @type {Set<string>} */
  const origins = new Set();

  for (const r of webResponses || []) {
    if (!r?.url || !r.status) continue;
    try {
      const u = new URL(String(r.url));
      origins.add(`${u.protocol}//${u.host}`);
    } catch {
      /* ignorar */
    }
  }

  if (origins.size === 0 && ip) {
    origins.add(`http://${ip}`);
    origins.add(`https://${ip}`);
  }

  const tried = new Set();
  let fetched = 0;

  for (const origin of origins) {
    const base = String(origin).replace(/\/$/, '');
    const robotsUrl = `${base}/robots.txt`;
    if (tried.has(robotsUrl)) continue;
    tried.add(robotsUrl);

    try {
      logger(`curl robots.txt: ${robotsUrl}`, 'info');
      const resp = await curlWebSingle({ url: robotsUrl, timeoutMs, maxBodyBytes });
      if (resp.status === 200) {
        resp.__via = 'robots.txt';
        webResponses.push(resp);
        fetched += 1;
        logger(`robots.txt: OK (200) — ${robotsUrl}`, 'success');
      } else {
        logger(`robots.txt: sem ficheiro ou negado — HTTP ${resp.status || '?'} @ ${robotsUrl}`, 'info');
      }
    } catch (e) {
      logger(`robots.txt: erro @ ${robotsUrl} — ${e?.message || e}`, 'info');
    }
  }

  return { fetched };
}
