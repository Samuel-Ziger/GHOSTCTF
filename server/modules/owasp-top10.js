/**
 * OWASP Top 10 (2025) — etiquetas heurísticas a partir de findings do GHOSTRECON.
 * Referência: categorias fornecidas pelo utilizador; o mapeamento é aproximado (recon ≠ pentest completo).
 */

export const OWASP_TOP10_2025 = {
  A01: { id: 'A01', year: 2025, title: 'Broken Access Control' },
  A02: { id: 'A02', year: 2025, title: 'Security Misconfiguration' },
  A03: { id: 'A03', year: 2025, title: 'Software Supply Chain Failures' },
  A04: { id: 'A04', year: 2025, title: 'Cryptographic Failures' },
  A05: { id: 'A05', year: 2025, title: 'Injection' },
  A06: { id: 'A06', year: 2025, title: 'Insecure Design' },
  A07: { id: 'A07', year: 2025, title: 'Authentication Failures' },
  A08: { id: 'A08', year: 2025, title: 'Software or Data Integrity Failures' },
  A09: { id: 'A09', year: 2025, title: 'Security Logging and Alerting Failures' },
  A10: { id: 'A10', year: 2025, title: 'Mishandling of Exceptional Conditions' },
};

function labelFor(id) {
  const e = OWASP_TOP10_2025[id];
  return e ? `${e.id}:2025 — ${e.title}` : id;
}

function add(set, id) {
  if (OWASP_TOP10_2025[id]) set.add(id);
}

/**
 * @param {object} f — finding normalizado do pipeline
 * @returns {{ id: string, title: string }[]}
 */
export function inferOwaspTags(f) {
  const set = new Set();
  const t = String(f?.type || '').toLowerCase();
  const meta = String(f?.meta || '').toLowerCase();
  const val = String(f?.value || '').toLowerCase();
  const url = String(f?.url || f?.value || '').toLowerCase();
  const blob = `${meta} ${val} ${url}`;

  if (['xss', 'sqli', 'lfi', 'dalfox'].includes(t)) add(set, 'A05');
  if (t === 'nuclei' && /xss|sqli|ssti|injection|ldap|cmdi|rce|template/i.test(blob)) add(set, 'A05');
  if (t === 'nuclei' && !set.has('A05') && /misconfig|disclosure|exposed|tls|ssl|header|information|cve-202/i.test(blob))
    add(set, 'A02');

  if (['idor', 'takeover'].includes(t)) add(set, 'A01');
  if (t === 'open_redirect') {
    add(set, 'A01');
    add(set, 'A06');
  }
  if (t === 'endpoint' && /\b(id|user_id|uid|account|order_id|invoice_id)=/i.test(url)) add(set, 'A01');
  if (t === 'intel' && /idor|broken access|horizontal|vertical privilege/i.test(blob)) add(set, 'A01');

  if (t === 'security' || t === 'waf' || (t === 'nuclei' && !set.has('A05'))) add(set, 'A02');
  if (t === 'nmap' && /default|anonymous|misconfig/i.test(blob)) add(set, 'A02');
  if (t === 'tls' && /weak|expired|self-?signed|deprecated/i.test(blob)) add(set, 'A02');

  if (['secret', 'secret_validation'].includes(t)) add(set, 'A04');
  if (t === 'tls' && !set.has('A02')) add(set, 'A04');
  if (blob.match(/\b(jwt|api[_-]?key|bearer|client_secret|private[_-]?key|BEGIN RSA|BEGIN OPENSSH)\b/)) add(set, 'A04');

  if (t === 'github' || meta.includes('github code search') || meta.includes('shannon') || meta.includes('wpscan')) add(set, 'A03');
  if (t === 'intel' && /clone|repository|package\.json|npm|pip|maven|gradle/i.test(blob)) add(set, 'A03');

  if (/\/(login|signin|oauth|auth|session|register|reset-password)(\/|$)/i.test(url) || /auth=required|session|cookie|csrf/i.test(blob))
    add(set, 'A07');

  if (t === 'intel' && /checklist|dork|workflow/i.test(blob) && !set.size) add(set, 'A06');
  if (t === 'dork') {
    if (/categoria:\s*github|categoria:\s*passwords/i.test(meta)) add(set, 'A04');
    if (/categoria:\s*(sqlerrors|config|phpinfo|database|backup)/i.test(meta)) add(set, 'A02');
    if (/categoria:\s*(sensitive|login)/i.test(meta)) add(set, 'A01');
    if (/categoria:\s*nmap_version_exploit_google/i.test(meta)) add(set, 'A06');
    if (!set.size) add(set, 'A06');
  }

  if (blob.match(/\b(integrity|sri|subresource|signature|tamper)\b/i)) add(set, 'A08');

  if (blob.match(/\b(log|audit|siem|alerting|monitor)\b.*\b(fail|missing|disabled)\b/i)) add(set, 'A09');

  if (t === 'phpinfo' || /\/(debug|actuator|trace|error|exception|swagger-ui|graphql)/i.test(url))
    add(set, 'A10');
  if (meta.includes('stack') && meta.includes('trace')) add(set, 'A10');

  const ordered = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'];
  return ordered.filter((id) => set.has(id)).map((id) => ({
    id,
    title: OWASP_TOP10_2025[id].title,
    label: labelFor(id),
  }));
}

/**
 * Muta findings in-place: `f.owasp` = array de { id, title, label }.
 * @param {object[]} findings
 */
export function applyOwaspTagsToFindings(findings) {
  for (const f of findings || []) {
    const tags = inferOwaspTags(f);
    f.owasp = tags.length ? tags : undefined;
  }
}
