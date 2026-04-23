function toShortText(v, max = 800) {
  if (v == null) return '';
  return String(v).replace(/\s+/g, ' ').trim().slice(0, max);
}

function uniq(arr) {
  return [...new Set(arr.filter(Boolean))];
}

function normalizeGhostBaseUrl(raw) {
  const v = String(raw || '').trim();
  if (!v) return 'http://127.0.0.1:8000';
  return v.replace(/\/+$/, '');
}

function envOn(name, def = true) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return def;
  return ['1', 'true', 'yes', 'on'].includes(String(raw).trim().toLowerCase());
}

function buildKnowledgePayload({ target, fingerprint, snapshot, notes, brainCategoryTitle }) {
  const s = snapshot && typeof snapshot === 'object' ? snapshot : {};
  const type = toShortText(s.type || 'finding', 80);
  const prio = toShortText(s.prio || 'unknown', 24);
  const score = Number.isFinite(Number(s.score)) ? Number(s.score) : null;
  const value = toShortText(s.value, 1200);
  const meta = toShortText(s.meta, 2000);
  const url = toShortText(s.url, 600);
  const categoryLabel = toShortText(brainCategoryTitle || 'sem-categoria', 120);

  const topic = `[CORTEX] ${categoryLabel} :: ${type} @ ${target}`;
  const content = [
    'Achado validado manualmente no Reporte e ligado ao modo cérebro (Cortex).',
    '',
    `- target: ${target}`,
    `- fingerprint: ${fingerprint}`,
    `- category: ${categoryLabel}`,
    `- type: ${type}`,
    `- prio: ${prio}`,
    score != null ? `- score: ${score}` : null,
    url ? `- url: ${url}` : null,
    value ? `- value: ${value}` : null,
    meta ? `- meta: ${meta}` : null,
    notes ? `- notes: ${toShortText(notes, 1800)}` : null,
  ]
    .filter(Boolean)
    .join('\n');

  const tags = uniq([
    'ghostrecon',
    'cortex',
    'manual_validated',
    `target:${target}`,
    `fp:${fingerprint.slice(0, 16)}`,
    type ? `type:${type.toLowerCase().replace(/[^a-z0-9_.-]+/g, '_')}` : '',
    prio ? `prio:${prio.toLowerCase()}` : '',
    brainCategoryTitle ? `brain:${categoryLabel.toLowerCase().replace(/[^a-z0-9_.-]+/g, '_')}` : '',
  ]).slice(0, 16);

  return {
    topic,
    content,
    category: process.env.GHOSTRECON_GHOST_KB_CATEGORY?.trim() || 'ghostrecon_validated',
    tags,
  };
}

/**
 * Envia um achado validado + ligado ao cérebro para a base local do GHOST (/memory/teach).
 * Best-effort: nunca lança exceção para não bloquear UX do Reporte.
 */
export async function syncValidatedCortexFindingToGhostKb({ target, fingerprint, snapshot, notes, brainCategoryTitle }) {
  try {
    if (!envOn('GHOSTRECON_GHOST_KB_SYNC', true)) {
      return { ok: false, skipped: true, reason: 'sync_disabled' };
    }
    const t = String(target || '').trim().toLowerCase();
    const fp = String(fingerprint || '').trim().toLowerCase();
    if (!t || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(t)) {
      return { ok: false, skipped: true, reason: 'invalid_target' };
    }
    if (!/^[a-f0-9]{64}$/.test(fp)) {
      return { ok: false, skipped: true, reason: 'invalid_fingerprint' };
    }

    const payload = buildKnowledgePayload({
      target: t,
      fingerprint: fp,
      snapshot,
      notes,
      brainCategoryTitle,
    });

    const base = normalizeGhostBaseUrl(process.env.GHOSTRECON_GHOST_BASE_URL);
    const url = `${base}/memory/teach`;
    const ac = new AbortController();
    const timeoutMs = Math.max(1000, Math.min(15000, Number(process.env.GHOSTRECON_GHOST_KB_TIMEOUT_MS || 4500)));
    const timer = setTimeout(() => ac.abort(), timeoutMs);
    let res;
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: ac.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      return { ok: false, status: res.status, error: txt.slice(0, 300) || `HTTP ${res.status}` };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e?.message || String(e) };
  }
}
