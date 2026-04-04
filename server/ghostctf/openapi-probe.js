import { curlWebSingle } from './web-curl-single.js';

const OPENAPI_PATHS = ['/openapi.json', '/v3/api-docs', '/api/openapi.json', '/docs/openapi.json', '/swagger.json'];

function collectOriginsFromWebResponses(webResponses, max = 8) {
  const origins = new Set();
  for (const r of webResponses || []) {
    if (!r?.url || !r.status || r.status < 200 || r.status >= 500) continue;
    try {
      const u = new URL(String(r.url));
      if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
      origins.add(`${u.protocol}//${u.host}`);
    } catch {
      /* */
    }
  }
  return [...origins].slice(0, max);
}

function looksLikeOpenApiDoc(bodyText) {
  const t = String(bodyText || '').slice(0, 8000);
  if (!t) return false;
  if (/["']openapi["']\s*:\s*["']3/i.test(t)) return true;
  if (/["']swagger["']\s*:\s*["']2/i.test(t)) return true;
  if (/\bopenapi\s*:\s*3\./i.test(t)) return true;
  if (/paths["']\s*:\s*\{/i.test(t) && /(info|components)/i.test(t)) return true;
  return false;
}

/**
 * GET típicos de OpenAPI/Swagger por origem — útil para Langflow, FastAPI, Springdoc, etc.
 */
export async function runOpenApiDiscovery({
  webResponses,
  log,
  timeoutMs = 12000,
  maxBodyBytes = 180000,
  /** Se definido, faz push das respostas 200 para flag scan / pipeline. */
  appendResponses = false,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const origins = collectOriginsFromWebResponses(webResponses);
  if (!origins.length) {
    logger('OpenAPI probe: sem origens HTTP válidas — skip.', 'info');
    return { fetched: 0, urls: [] };
  }

  const urls = [];
  let fetched = 0;

  for (const origin of origins) {
    for (const p of OPENAPI_PATHS) {
      const url = `${origin.replace(/\/$/, '')}${p}`;
      try {
        logger(`[openapi] GET ${url}`, 'info');
        const r = await curlWebSingle({ url, timeoutMs, maxBodyBytes });
        if (r.status === 200 && looksLikeOpenApiDoc(r.bodyText)) {
          fetched += 1;
          urls.push(url);
          logger(`OpenAPI: documento provável em ${url} (${(r.bodyText || '').length} B)`, 'success');
          if (appendResponses && Array.isArray(webResponses)) {
            webResponses.push({ ...r, url, finalUrl: r.finalUrl || url, __via: 'openapi' });
          }
        }
      } catch {
        /* */
      }
    }
  }

  return { fetched, urls };
}
