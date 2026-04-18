/**
 * Inteiro positivo a partir de `process.env[name]`; `def` quando ausente ou inválido.
 * Usado para limitar GETs (flag-path, disclosure, link crawl) em alvos ruidosos.
 */
export function ghostctfPositiveIntEnv(name, def) {
  const raw = process.env[name];
  if (raw == null || String(raw).trim() === '') return def;
  const v = Number(raw);
  if (!Number.isFinite(v) || v < 1) return def;
  return Math.min(1_000_000, Math.floor(v));
}
