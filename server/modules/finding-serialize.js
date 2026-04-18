/**
 * Serialização de findings para persistência (runs.findings_json) e export.
 * Corta campos pesados para caber no limite de bytes.
 */

const DEFAULT_MAX_BYTES = 8_000_000;

function truncateStr(s, max) {
  const t = String(s ?? '');
  if (t.length <= max) return t;
  return `${t.slice(0, max)}…[truncated ${t.length - max} chars]`;
}

function slimEvidence(ev, maxSnippet = 4000) {
  if (!ev || typeof ev !== 'object') return ev;
  const o = { ...ev };
  if (typeof o.responseSnippet === 'string') o.responseSnippet = truncateStr(o.responseSnippet, maxSnippet);
  if (typeof o.requestSnippet === 'string') o.requestSnippet = truncateStr(o.requestSnippet, 2000);
  return o;
}

function cloneFindingForSnapshot(f) {
  if (!f || typeof f !== 'object') return f;
  const o = {
    type: f.type,
    prio: f.prio,
    score: f.score,
    value: typeof f.value === 'string' ? truncateStr(f.value, 24_000) : f.value,
    meta: typeof f.meta === 'string' ? truncateStr(f.meta, 24_000) : f.meta,
    url: f.url,
    fingerprint: f.fingerprint,
    compositeScore: f.compositeScore,
    attackTier: f.attackTier,
    bountyProbability: f.bountyProbability,
    priorityWhy: Array.isArray(f.priorityWhy) ? f.priorityWhy.slice(0, 80) : f.priorityWhy,
    provenance: f.provenance,
    owasp: Array.isArray(f.owasp) ? f.owasp : undefined,
    mitre: Array.isArray(f.mitre) ? f.mitre : undefined,
  };
  if (f.verification) {
    o.verification = {
      classification: f.verification.classification,
      confidenceScore: f.verification.confidenceScore,
      verifiedAt: f.verification.verifiedAt,
      evidence: f.verification.evidence ? slimEvidence(f.verification.evidence) : undefined,
    };
  }
  return o;
}

/**
 * @param {object[]} findings
 * @param {number} [maxBytes]
 * @returns {string|null} JSON string ou null se vazio
 */
export function serializeFindingsForRunSnapshot(findings, maxBytes = DEFAULT_MAX_BYTES) {
  const lim = Number(process.env.GHOSTRECON_FINDINGS_SNAPSHOT_MAX_BYTES || maxBytes);
  const list = (findings || []).map(cloneFindingForSnapshot);
  let payload = {
    schemaVersion: 1,
    savedAt: new Date().toISOString(),
    count: list.length,
    findings: list,
    truncated: false,
    droppedTail: 0,
  };
  let json = JSON.stringify(payload);
  let guard = 0;
  while (Buffer.byteLength(json, 'utf8') > lim && payload.findings.length > 20 && guard < 40) {
    guard += 1;
    const drop = Math.max(1, Math.floor(payload.findings.length * 0.08));
    payload.findings = payload.findings.slice(0, payload.findings.length - drop);
    payload.count = payload.findings.length;
    payload.truncated = true;
    payload.droppedTail += drop;
    json = JSON.stringify(payload);
  }
  if (Buffer.byteLength(json, 'utf8') > lim) {
    payload = {
      schemaVersion: 1,
      savedAt: payload.savedAt,
      truncated: true,
      error: 'snapshot_exceeds_max_bytes_after_trim',
      count: 0,
      findings: [],
    };
    json = JSON.stringify(payload);
  }
  return json;
}

export function parseFindingsSnapshotJson(text) {
  if (!text || typeof text !== 'string') return null;
  try {
    const p = JSON.parse(text);
    if (Array.isArray(p)) return p;
    if (Array.isArray(p.findings)) return p.findings;
    return null;
  } catch {
    return null;
  }
}
