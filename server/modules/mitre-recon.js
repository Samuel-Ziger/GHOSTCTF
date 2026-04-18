/**
 * MITRE ATT&CK (subconjunto fixo: recon / resource-development / initial-access).
 * Dados em `mitre-attack/recon-bundle.json` (gerado por `npm run mitre:extract`).
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const defaultBundlePath = path.resolve(__dirname, '../../mitre-attack/recon-bundle.json');

/** @type {object | null | undefined} undefined = não carregado */
let cachedBundle;
let bundlePathOverride;

export function __setMitreReconBundlePathForTests(p) {
  bundlePathOverride = p;
  cachedBundle = undefined;
}

export function __setMitreReconBundleForTests(bundle) {
  bundlePathOverride = null;
  cachedBundle = bundle === undefined ? null : bundle;
}

/** Repor cache entre testes ou após injeção de bundle em memória. */
export function __resetMitreReconBundleCache() {
  bundlePathOverride = undefined;
  cachedBundle = undefined;
}

function loadBundleFromDisk() {
  const p = bundlePathOverride || defaultBundlePath;
  try {
    const raw = fs.readFileSync(p, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function getBundle() {
  if (cachedBundle !== undefined) return cachedBundle;
  cachedBundle = loadBundleFromDisk();
  return cachedBundle;
}

function labelFor(tech) {
  const phases = Array.isArray(tech.phases) && tech.phases.length ? tech.phases.join(', ') : '';
  const base = `${tech.id} — ${tech.name || tech.id}`;
  return phases ? `${base} (${phases})` : base;
}

/**
 * Heurística: tipos do GHOSTRECON → IDs de técnicas presentes no bundle.
 * @param {object} f
 * @returns {string[]}
 */
export function inferMitreTechniqueIds(f) {
  const t = String(f?.type || '').toLowerCase();
  const meta = String(f?.meta || '').toLowerCase();
  const val = String(f?.value || '').toLowerCase();
  const blob = `${meta} ${val}`;

  const add = (/** @type {Set<string>} */ s, /** @type {string[]} */ ids) => {
    for (const id of ids) if (id) s.add(id);
  };
  const ids = new Set();

  if (t === 'subdomain') add(ids, ['T1589', 'T1595']);
  if (t === 'dns') add(ids, ['T1592']);
  if (t === 'rdap' || t === 'whois') add(ids, ['T1589']);
  if (t === 'tech') add(ids, ['T1592']);
  if (t === 'tls') add(ids, ['T1592']);
  if (t === 'js') add(ids, ['T1592']);
  if (t === 'param') add(ids, ['T1592']);

  if (t === 'security' || t === 'waf') add(ids, ['T1592', 'T1595']);
  if (t === 'nmap') add(ids, ['T1595']);
  if (t === 'dork') add(ids, ['T1593']);

  if (t === 'takeover') add(ids, ['T1583.001']);

  if (t === 'endpoint') {
    if (/\bwayback\b|\bcommon crawl\b/i.test(meta)) add(ids, ['T1592', 'T1593']);
    else if (/html surface/i.test(meta)) add(ids, ['T1592']);
    else add(ids, ['T1592']);
  }

  if (t === 'secret' && /github/i.test(meta)) add(ids, ['T1593']);
  if (t === 'intel') {
    if (/github clone local|github code search/i.test(meta)) add(ids, ['T1588', 'T1593']);
    else if (/\bdork\b|google cse|cse →/i.test(blob)) add(ids, ['T1593']);
    else if (/waf|shodan|certificate transparency|virus\s*total/i.test(blob)) add(ids, ['T1592', 'T1595']);
  }

  if (['nuclei', 'xss', 'sqli', 'lfi', 'dalfox', 'open_redirect', 'idor', 'exploit', 'phpinfo'].includes(t))
    add(ids, ['T1190']);
  if (t === 'nuclei' && /scan|template|tcp|port|service/i.test(blob) && !/\b(cve|xss|sqli|rce|ssrf|idor)\b/i.test(blob))
    add(ids, ['T1595']);

  if (t === 'wpscan') add(ids, ['T1190', 'T1595']);

  return [...ids];
}

/**
 * @param {object} f
 * @returns {{ id: string, title: string, label: string, url?: string }[]}
 */
export function inferMitreTags(f) {
  const bundle = getBundle();
  if (!bundle || !Array.isArray(bundle.techniques)) return [];

  const byId = new Map(bundle.techniques.map((x) => [x.id, x]));
  const want = inferMitreTechniqueIds(f);
  const ordered = [];
  const seen = new Set();
  for (const id of want) {
    const tech = byId.get(id);
    if (!tech || seen.has(id)) continue;
    seen.add(id);
    ordered.push({
      id: tech.id,
      title: tech.name || tech.id,
      label: labelFor(tech),
      url: tech.url || undefined,
    });
  }
  return ordered;
}

/**
 * Muta findings in-place: `f.mitre` = array de etiquetas ATT&CK (subconjunto recon).
 * @param {object[]} findings
 */
export function applyMitreTagsToFindings(findings) {
  for (const f of findings || []) {
    const tags = inferMitreTags(f);
    f.mitre = tags.length ? tags : undefined;
  }
}
