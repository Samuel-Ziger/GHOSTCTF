/**
 * Resumo de cobertura do recon (módulos, Kali, contagens) para UI / export.
 */

function countByType(findings) {
  const m = {};
  for (const f of findings || []) {
    const t = f?.type || 'unknown';
    m[t] = (m[t] || 0) + 1;
  }
  return m;
}

/**
 * @param {object} opts
 * @param {string} opts.domain
 * @param {string[]} opts.modules
 * @param {boolean} opts.kaliMode
 * @param {object[]} opts.findings
 * @param {object|null} [opts.kaliCap] resultado de getKaliCapabilities()
 */
export function buildReconCoverageSnapshot({ domain, modules, kaliMode, findings, kaliCap = null }) {
  const mods = Array.isArray(modules) ? modules : [];
  const tools = kaliCap?.tools || {};
  const notes = [];
  if (!mods.includes('kali_nuclei')) notes.push('Nuclei (Kali): módulo UI desligado');
  if (!mods.includes('kali_ffuf')) notes.push('Ffuf (Kali): módulo UI desligado');
  if (!kaliMode) {
    notes.push('Modo Kali: desligado (nmap/ffuf/nuclei/dalfox/xss_vibes/wpscan não executam no servidor)');
  } else if (kaliCap && !kaliCap.ok) {
    notes.push(`Kali: ambiente sem suporte (${kaliCap.message || 'cap desconhecido'})`);
  }
  if (kaliMode && kaliCap?.ok) {
    const inactive = Object.entries(tools)
      .filter(([, v]) => !v)
      .map(([k]) => k);
    if (inactive.length) notes.push(`Ferramentas ausentes no PATH: ${inactive.slice(0, 12).join(', ')}`);
  }

  const byType = countByType(findings);
  const high = (findings || []).filter((f) => f?.prio === 'high').length;
  const hpt = (findings || []).filter((f) => f?.attackTier === 'HIGH_PROBABILITY').length;

  return {
    schemaVersion: 1,
    domain,
    generatedAt: new Date().toISOString(),
    modulesActive: mods,
    kaliMode: Boolean(kaliMode),
    toolsPresent: kaliCap?.tools || undefined,
    counts: {
      totalFindings: findings?.length ?? 0,
      highPrio: high,
      highProbabilityTier: hpt,
      byType,
    },
    notes,
  };
}
