import { Buffer } from 'node:buffer';

const B32_RFC4648 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Razão mínima de bytes “legíveis” (UTF-8 ou latin1) para aceitar decode. */
function readableRatio(s) {
  const t = String(s || '');
  if (!t.length) return 0;
  let ok = 0;
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13) ok++;
    else if (c >= 32 && c <= 126) ok++;
    else if (c >= 128 && c !== 65533) ok++;
  }
  return ok / t.length;
}

/**
 * Base32 RFC 4648 (alfabeto A–Z e 2–7, padding =).
 * @returns {Buffer|null}
 */
export function tryDecodeBase32Rfc4648(raw) {
  const s = String(raw || '')
    .replace(/\s+/g, '')
    .replace(/=+$/i, '')
    .toUpperCase();
  if (s.length < 8) return null;
  let bits = 0;
  let v = 0;
  const out = [];
  for (let i = 0; i < s.length; i++) {
    const idx = B32_RFC4648.indexOf(s[i]);
    if (idx < 0) return null;
    v = (v << 5) | idx;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((v >> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

export function tryDecodeBase64Chunk(raw) {
  let t = String(raw || '').replace(/\s+/g, '');
  if (t.length < 12) return null;
  if (t.length % 4 === 1) return null;
  while (t.length % 4) t += '=';
  try {
    const buf = Buffer.from(t, 'base64');
    if (!buf.length || buf.length > 512000) return null;
    const utf8 = buf.toString('utf8');
    if (readableRatio(utf8) >= 0.72) return buf;
    const latin1 = buf.toString('latin1');
    if (readableRatio(latin1) >= 0.72) return buf;
    return null;
  } catch {
    return null;
  }
}

function bufToDisplayString(buf, maxChars) {
  const cap = Math.max(200, Math.min(maxChars || 4000, 32000));
  const utf8 = buf.toString('utf8');
  if (readableRatio(utf8) >= 0.68) {
    const s = utf8.replace(/\0/g, ' ');
    return s.length > cap ? `${s.slice(0, cap)}…` : s;
  }
  const latin1 = buf.toString('latin1').replace(/\0/g, ' ');
  return latin1.length > cap ? `${latin1.slice(0, cap)}…` : latin1;
}

/**
 * Procura blocos Base64 / Base32 na resposta, tenta decodificar e devolve trechos UTF‑8 (truncados).
 * @param {string} text
 * @param {{ maxPerKind?: number, maxUtf8?: number }} [opts]
 * @returns {{ encoding: 'base64'|'base32', rawSample: string, decodedUtf8: string, decodedBytes: number }[]}
 */
export function sniffDecodeBase64Base32(text, opts = {}) {
  const maxPerKind = Math.min(6, Math.max(1, Number(opts.maxPerKind) || 3));
  const maxUtf8 = Math.min(32000, Math.max(400, Number(opts.maxUtf8) || 4500));
  const src = String(text || '').slice(0, 200000);
  const out = [];
  const seenB64 = new Set();
  const seenB32 = new Set();

  const b64Re = /[A-Za-z0-9+/]{20,}={0,2}/g;
  let m;
  b64Re.lastIndex = 0;
  while ((m = b64Re.exec(src))) {
    const chunk = m[0];
    if (chunk.length < 20 || seenB64.has(chunk)) continue;
    seenB64.add(chunk);
    const buf = tryDecodeBase64Chunk(chunk);
    if (!buf || buf.length < 6) continue;
    const dec = bufToDisplayString(buf, maxUtf8);
    if (dec.length < 4) continue;
    out.push({
      encoding: 'base64',
      rawSample: chunk.length > 72 ? `${chunk.slice(0, 72)}…` : chunk,
      decodedUtf8: dec,
      decodedBytes: buf.length,
    });
    if (out.filter((x) => x.encoding === 'base64').length >= maxPerKind) break;
  }

  const b32Re = /[A-Z2-7]{16,}={0,6}/g;
  b32Re.lastIndex = 0;
  while ((m = b32Re.exec(src))) {
    let chunk = m[0].replace(/\s+/g, '').toUpperCase();
    if (chunk.length < 16 || seenB32.has(chunk)) continue;
    if (!/^[A-Z2-7=]+$/.test(chunk)) continue;
    seenB32.add(chunk);
    const buf = tryDecodeBase32Rfc4648(chunk.replace(/=+$/, ''));
    if (!buf || buf.length < 4) continue;
    const dec = bufToDisplayString(buf, maxUtf8);
    if (dec.length < 3 || readableRatio(dec) < 0.55) continue;
    out.push({
      encoding: 'base32',
      rawSample: chunk.length > 72 ? `${chunk.slice(0, 72)}…` : chunk,
      decodedUtf8: dec,
      decodedBytes: buf.length,
    });
    if (out.filter((x) => x.encoding === 'base32').length >= maxPerKind) break;
  }

  return out.slice(0, maxPerKind * 2);
}

/**
 * Anexa a `evidence` o campo `decodedExtractions` (não entra em evidenceHash em verify.js).
 */
export function attachDecodedExtractions(evidence, responseText, opts) {
  if (!evidence || responseText == null) return evidence;
  const list = sniffDecodeBase64Base32(responseText, opts);
  if (list.length) evidence.decodedExtractions = list;
  return evidence;
}
