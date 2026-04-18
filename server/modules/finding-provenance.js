/**
 * Contexto de descoberta para achados — explicar **como** surgiu e **ligação ao alvo**.
 * A UI e os exports JSON incluem `provenance` quando presente.
 */

/**
 * @param {object} finding
 * @param {{ how?: string, relation?: string }} p
 * @returns {object}
 */
export function withProvenance(finding, p) {
  const how = String(p?.how ?? '').trim();
  const relation = String(p?.relation ?? '').trim();
  if (!how && !relation) return finding;
  return {
    ...finding,
    provenance: { how, relation },
  };
}
