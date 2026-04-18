import fs from 'fs';
import path from 'path';
import { homedir } from 'os';

/** Pastas comuns para dalfox (Go), sqlmap, nuclei, etc. (prefixo sugerido para o PATH do recon). */
export function buildSuggestedExtraPath() {
  const h = homedir();
  const parts = [
    '/usr/local/bin',
    '/opt/homebrew/bin',
    '/usr/bin',
    '/bin',
    path.join(h, 'go', 'bin'),
    path.join(h, '.local', 'bin'),
    path.join(h, 'bin'),
  ];
  return parts.join(path.delimiter);
}

/**
 * No arranque do processo Node: prefixa a `process.env.PATH` pastas comuns que **existem no disco**
 * e ainda **não** estão no PATH (para dalfox em ~/go/bin, etc.). Idempotente.
 * Desliga com `GHOSTRECON_AUTO_PATH=0` no `.env`.
 * @returns {string[]} pastas efectivamente prefixadas (para log)
 */
export function augmentProcessPathFromCommonDirs() {
  if (process.env.GHOSTRECON_AUTO_PATH === '0') return [];
  const sep = path.delimiter;
  const dirs = parseExtraPathInput(buildSuggestedExtraPath());
  const current = process.env.PATH || '';
  const seenAbs = new Set();
  for (const s of current.split(sep)) {
    const t = s.trim();
    if (!t) continue;
    try {
      seenAbs.add(path.resolve(t));
    } catch {
      /* ignore */
    }
  }
  const toPrepend = [];
  for (const d of dirs) {
    if (!d) continue;
    let abs;
    try {
      abs = path.resolve(d);
    } catch {
      continue;
    }
    if (seenAbs.has(abs)) continue;
    let st;
    try {
      st = fs.statSync(abs);
    } catch {
      continue;
    }
    if (!st.isDirectory()) continue;
    toPrepend.push(abs);
    seenAbs.add(abs);
  }
  if (toPrepend.length) {
    process.env.PATH = toPrepend.join(sep) + sep + current;
  }
  return toPrepend;
}

/**
 * Segmentos a partir de texto (separador = PATH do SO; também aceita quebras de linha).
 * Expande ~/ e ~ no início de segmento.
 */
export function parseExtraPathInput(raw) {
  const home = homedir();
  const out = [];
  const sep = path.delimiter;
  for (const line of String(raw || '').split(/\r?\n/)) {
    for (const chunk of line.split(sep)) {
      let t = chunk.trim();
      if (!t) continue;
      if (t.startsWith(`~${path.sep}`)) t = path.join(home, t.slice(2));
      else if (t === '~') t = home;
      else if (t.startsWith('~/')) t = path.join(home, t.slice(2));
      out.push(t);
    }
  }
  return [...new Set(out)];
}

/** Junta segmentos extra + PATH base (para process.env.PATH). */
export function prependExtraPathToEnvPath(extraPathRaw, basePath) {
  const segments = parseExtraPathInput(extraPathRaw);
  if (!segments.length) return basePath || '';
  const sep = path.delimiter;
  return segments.join(sep) + sep + (basePath || '');
}
