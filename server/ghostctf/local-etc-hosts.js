import { readFile } from 'node:fs/promises';
import { isIPv4, isIPv6 } from 'node:net';

function stripLineComment(line) {
  const idx = String(line).indexOf('#');
  return (idx >= 0 ? String(line).slice(0, idx) : String(line)).trim();
}

function normalizeHostsFileIp(s) {
  const t = String(s || '').trim().toLowerCase();
  if (t.startsWith('::ffff:')) {
    const tail = t.slice(7);
    if (isIPv4(tail)) return tail;
  }
  return t;
}

function ipMatchesTarget(lineIp, targetIp) {
  const a = normalizeHostsFileIp(lineIp);
  const b = normalizeHostsFileIp(targetIp);
  if (!a || !b) return false;
  if (isIPv4(a) && isIPv4(b)) return a === b;
  if (isIPv6(a) && isIPv6(b)) return a === b;
  return false;
}

/**
 * Extrai hostnames de texto no formato `/etc/hosts` cujo primeiro campo (IP) coincide com `targetIp`.
 * Usado para CTF: mapeaste `IP challenge.ctf` no hosts da máquina do analista — o pipeline incorpora `challenge.ctf`.
 *
 * @param {string} content — conteúdo do ficheiro (UTF-8)
 * @param {string} targetIp — IPv4 ou IPv6 do alvo
 * @param {{ max?: number }} [opts]
 * @returns {string[]} hostnames na ordem de aparição (dedup case-insensitive)
 */
export function parseEtcHostsContentForTarget(content, targetIp, { max = 32 } = {}) {
  const target = String(targetIp || '').trim();
  if (!target || (!isIPv4(target) && !isIPv6(target))) return [];

  const cap = Math.max(1, Math.min(64, Number(max) || 32));
  const hostnames = [];
  const seen = new Set();

  for (let line of String(content || '').split(/\r?\n/)) {
    line = stripLineComment(line);
    if (!line) continue;
    const parts = line.split(/\s+/).filter(Boolean);
    if (parts.length < 2) continue;
    if (!ipMatchesTarget(parts[0], target)) continue;
    for (let i = 1; i < parts.length; i++) {
      const raw = String(parts[i]).trim();
      if (!raw) continue;
      const key = raw.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      hostnames.push(raw);
      if (hostnames.length >= cap) return hostnames;
    }
  }
  return hostnames;
}

/**
 * Lê `/etc/hosts` no sistema onde corre o Node (ex.: Kali do analista).
 * @returns {Promise<string[]>}
 */
export async function collectHostnamesFromLocalEtcHosts(targetIp, opts = {}) {
  try {
    const content = await readFile('/etc/hosts', 'utf8');
    return parseEtcHostsContentForTarget(content, targetIp, opts);
  } catch {
    return [];
  }
}
