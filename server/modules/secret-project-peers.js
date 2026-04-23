/**
 * Correlação de segredos (mesmo material bruto) entre **alvos diferentes** dentro do **mesmo nome de projeto** (campo UI).
 * O fingerprint por finding continua por-alvo; aqui usamos `value_fp` no meta (hash do material antes de mascarar).
 */
import { norm, extractSecretValueFpFromMeta } from './db-common.js';

function sanitizeProjectName(raw) {
  let s = String(raw || '')
    .trim()
    .replace(/\.\./g, '')
    .replace(/[/\\]+/g, '_')
    .replace(/[^a-zA-Z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 96);
  if (!s) s = '_unnamed';
  return s;
}

export function extractKindHintFromSecretValue(value) {
  const m = String(value || '').match(/^\[([^\]]+)\]/);
  return m ? m[1].slice(0, 120) : '';
}

/**
 * @param {string} projectName
 * @param {string} target
 * @param {number} runId
 * @param {object[]} findings
 * @returns {Array<{project_name:string,value_fp:string,target:string,kind_hint:string,value_preview:string,url:string|null,last_run_id:number,ts:string}>}
 */
export function buildSecretPeerRows(projectName, target, runId, findings) {
  const raw = String(projectName || '').trim();
  if (!raw) return [];
  const pn = sanitizeProjectName(raw);
  const t = norm(target);
  const now = new Date().toISOString();
  const rows = [];
  for (const f of findings || []) {
    if (f?.type !== 'secret') continue;
    const fp = extractSecretValueFpFromMeta(f.meta);
    if (!fp) continue;
    rows.push({
      project_name: pn,
      value_fp: fp,
      target: t,
      kind_hint: extractKindHintFromSecretValue(f.value),
      value_preview: String(f.value || '').slice(0, 240),
      url: f.url || null,
      last_run_id: runId,
      ts: now,
    });
  }
  return rows;
}

export { sanitizeProjectName };
