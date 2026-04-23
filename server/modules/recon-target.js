import net from 'node:net';

/** Hostname / IP para usar em https:// ou http:// (IPv6 precisa de []). */
export function hostLiteralForUrl(host) {
  const h = String(host ?? '').trim();
  if (!h) return h;
  if (net.isIPv6(h)) return `[${h}]`;
  return h;
}

export function targetIsIp(host) {
  const h = String(host ?? '').trim();
  return net.isIPv4(h) || net.isIPv6(h);
}

const DOMAIN_KEY_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

function looksLikeBareIpv6(s) {
  return typeof s === 'string' && s.includes(':') && !s.includes('://') && !s.startsWith('[');
}

/**
 * Aceita domínio, URL http(s) com host, IPv4 ou IPv6 (com ou sem []).
 * @returns {{ ok: true, target: string } | { ok: false, message: string }}
 */
export function parseReconTarget(raw) {
  const s0 = String(raw ?? '').trim();
  if (!s0) return { ok: false, message: 'Alvo vazio' };

  if (net.isIPv4(s0)) return { ok: true, target: s0 };
  if (net.isIPv6(s0)) return { ok: true, target: s0.toLowerCase() };

  if (/^\[[0-9a-f:]+\]$/i.test(s0)) {
    const inner = s0.slice(1, -1);
    if (net.isIPv6(inner)) return { ok: true, target: inner.toLowerCase() };
  }

  let candidate = s0;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) {
    candidate = `https://${candidate}`;
  }
  try {
    const u = new URL(candidate);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (!host) return { ok: false, message: 'Alvo sem hostname válido' };
    if (net.isIPv4(host)) return { ok: true, target: host };
    if (net.isIPv6(host)) return { ok: true, target: host.toLowerCase() };
    const lower = host.toLowerCase();
    if (!DOMAIN_KEY_RE.test(lower)) return { ok: false, message: 'Domínio ou IP inválido' };
    return { ok: true, target: lower };
  } catch {
    if (looksLikeBareIpv6(s0) && net.isIPv6(s0)) return { ok: true, target: s0.toLowerCase() };
    return { ok: false, message: 'URL ou alvo inválido' };
  }
}

/** Chave normalizada para disco / validações (domínio ou IP). */
export function isReconTargetStorageKey(s) {
  const t = String(s ?? '').trim().toLowerCase();
  if (!t) return false;
  if (net.isIPv4(t) || net.isIPv6(t)) return true;
  return /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(t);
}
