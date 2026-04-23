/**
 * Extração leve de href/action a partir de HTML (superfície passiva).
 */
export function extractHtmlSurface(html, baseUrl, opts = {}) {
  const maxLinks = opts.maxLinks ?? 48;
  const maxForms = opts.maxForms ?? 16;
  const links = new Set();
  const formActions = new Set();

  const s = String(html || '');
  const hrefRe = /href\s*=\s*["']([^"'<>]+)["']/gi;
  let m;
  while ((m = hrefRe.exec(s)) !== null && links.size < maxLinks) {
    const raw = m[1].trim();
    if (!raw || raw.startsWith('javascript:') || raw.startsWith('mailto:') || raw.startsWith('#')) continue;
    try {
      const abs = new URL(raw, baseUrl).href;
      if (/^https?:\/\//i.test(abs)) links.add(abs);
    } catch {
      /* ignore */
    }
  }

  const actRe = /<form[^>]*\saction\s*=\s*["']([^"'<>]+)["']/gi;
  while ((m = actRe.exec(s)) !== null && formActions.size < maxForms) {
    const raw = m[1].trim();
    if (!raw) continue;
    try {
      formActions.add(new URL(raw, baseUrl).href);
    } catch {
      /* ignore */
    }
  }

  return { links: [...links], formActions: [...formActions] };
}

/**
 * Comentários HTML com formato típico de flag CTF, credencial em nota, etc. (falso positivo possível em dev).
 * @param {string} html
 * @param {{ max?: number }} [opts]
 * @returns {string[]} trechos normalizados (curtos)
 */
export function extractSuspiciousHtmlComments(html, opts = {}) {
  const max = Math.max(1, Math.min(12, opts.max ?? 4));
  const s = String(html || '').slice(0, 400_000);
  const out = [];
  const re = /<!--([\s\S]{1,420}?)-->/gi;
  let m;
  while ((m = re.exec(s)) !== null && out.length < max) {
    const inner = String(m[1] || '')
      .replace(/\s+/g, ' ')
      .trim();
    if (inner.length < 6) continue;
    if (
      /\{[A-Za-z0-9_!#%^&*+=.\-/:]{8,220}\}/.test(inner) ||
      /\b(flag|ctf|solyd|key)\s*[\[{]/i.test(inner) ||
      /\b(password|passwd|api[_-]?key|secret)\s*[:=]/i.test(inner)
    ) {
      out.push(inner.length > 220 ? `${inner.slice(0, 220)}…` : inner);
    }
  }
  return out;
}
