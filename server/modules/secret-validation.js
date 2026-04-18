import { UA } from '../config.js';

const SECRET_HINT_RE = /(token|secret|api[_-]?key|password|authorization|bearer|jwt)/i;

export async function validateSecretFindings(findings = [], log) {
  const out = [];
  const secrets = findings.filter((f) => f?.type === 'secret').slice(0, 30);

  for (const f of secrets) {
    const url = String(f.url || '').trim();
    if (!url || !/^https?:\/\//i.test(url)) {
      out.push({ ref: f.value, status: 'unknown', reason: 'no_url' });
      continue;
    }
    try {
      const res = await fetch(url, {
        method: 'GET',
        redirect: 'follow',
        signal: AbortSignal.timeout(12000),
        headers: { 'User-Agent': UA, Accept: '*/*' },
      });
      const body = await res.text().catch(() => '');
      const hasSecretSignals = SECRET_HINT_RE.test(body) || SECRET_HINT_RE.test(String(f.value || ''));
      const status =
        res.status >= 200 && res.status < 300 && hasSecretSignals
          ? 'live'
          : res.status >= 200 && res.status < 400
            ? 'probable'
            : 'dead';
      out.push({
        ref: String(f.value || '').slice(0, 160),
        status,
        reason: `http_${res.status}`,
      });
    } catch (e) {
      out.push({ ref: String(f.value || '').slice(0, 160), status: 'dead', reason: e.message });
      if (typeof log === 'function') log(`secret validation: ${e.message}`, 'warn');
    }
  }
  return out;
}
