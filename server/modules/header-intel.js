/**
 * Heurísticas de cabeçalhos HTTP de resposta “suspeitos” (vazamento de stack,
 * debug, proxies) + sugestão rápida de linhas para /etc/hosts quando há
 * hostname alternativo útil para teste de vhost (só em alvos autorizados).
 */

const RFC1918 = /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/;

/** @param {Headers|Array<[string, string]>|Iterable<[string, string]>} headers */
export function flattenResponseHeaderPairs(headers) {
  const out = [];
  const isFetchHeaders =
    headers &&
    typeof headers.get === 'function' &&
    typeof headers.append === 'function' &&
    !Array.isArray(headers);
  if (isFetchHeaders) {
    for (const [k, v] of headers.entries()) {
      if (!k) continue;
      out.push([String(k), String(v ?? '')]);
    }
    return out;
  }
  for (const pair of headers || []) {
    if (!pair || pair.length < 2) continue;
    out.push([String(pair[0]), String(pair[1] ?? '')]);
  }
  return out;
}

function isIpv4(s) {
  const m = String(s).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  return m.slice(1).every((x) => Number(x) <= 255);
}

function isLikelyFqdn(s) {
  const h = String(s).trim().toLowerCase();
  if (h.length < 4 || h.length > 253) return false;
  if (isIpv4(h)) return false;
  if (h.includes('..') || h.startsWith('.') || h.endsWith('.')) return false;
  return /^[a-z0-9*][a-z0-9*.-]*\.[a-z0-9.-]+$/i.test(h);
}

function extractFqdnsFromText(text) {
  const t = String(text);
  const found = new Set();
  const re = /\b([a-z0-9][a-z0-9-]{0,62}\.)+[a-z]{2,}\b/gi;
  let m;
  while ((m = re.exec(t)) !== null) {
    const w = m[0].toLowerCase();
    if (w.length > 3 && isLikelyFqdn(w)) found.add(w);
  }
  return [...found];
}

function hostsFromForwardedValue(v) {
  const hosts = new Set();
  for (const chunk of String(v).split(',')) {
    const hostEq = chunk.match(/\bhost=([^;,"]+)/i);
    if (hostEq) {
      const h = hostEq[1].trim().replace(/^"|"$/g, '').toLowerCase();
      if (isLikelyFqdn(h)) hosts.add(h);
    }
  }
  return [...hosts];
}

function collectVhostCandidates(nameLower, value) {
  const v = String(value).trim();
  const out = new Set();
  if (!v) return [];
  if (nameLower === 'forwarded') {
    for (const h of hostsFromForwardedValue(v)) out.add(h);
    return [...out];
  }
  if (
    nameLower === 'x-forwarded-host' ||
    nameLower === 'x-original-host' ||
    nameLower === 'x-host' ||
    nameLower === 'x-forwarded-server' ||
    nameLower === 'x-envoy-upstream-service-host'
  ) {
    for (const part of v.split(/[\s,|]+/)) {
      const p = part.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
      if (isLikelyFqdn(p)) out.add(p);
    }
  }
  if (nameLower === 'x-forwarded-host' || nameLower === 'x-original-host') {
    for (const h of extractFqdnsFromText(v)) out.add(h);
  }
  return [...out];
}

function buildEtcHostsSnippet(extraHosts, pageHost, primaryIpv4) {
  const page = String(pageHost).toLowerCase();
  const uniq = [...new Set(extraHosts.map((h) => String(h).toLowerCase()))].filter(
    (h) => h && h !== page && isLikelyFqdn(h),
  );
  if (!uniq.length) return '';
  const ip = primaryIpv4 && isIpv4(primaryIpv4) ? primaryIpv4 : '<DEST_IP>';
  const note =
    ip === '<DEST_IP>'
      ? '# Substitua <DEST_IP> pelo IPv4 do edge/origem que queres testar.'
      : '# IP preenchido a partir do DNS do recon (A do host pedido).';
  const lines = [note, ...uniq.map((h) => `${ip}\t${h}`)];
  return lines.join('\n');
}

/**
 * @param {Array<[string, string]>} pairs
 * @param {{ pageUrl: string, pageHost: string, apexDomain?: string, primaryIpv4?: string }} ctx
 * @returns {{ prio: string, score: number, value: string, meta: string }[]}
 */
export function analyzeSuspiciousResponseHeaders(pairs, ctx) {
  const pageHost = String(ctx.pageHost || '').toLowerCase();
  const primaryIpv4 = String(ctx.primaryIpv4 || '').trim();
  const hits = [];
  const vhostCandidates = new Set();

  const push = (prio, score, value, meta) => {
    hits.push({ prio, score, value, meta });
  };

  for (const [rawName, rawVal] of pairs || []) {
    const name = String(rawName || '').trim();
    const nameLower = name.toLowerCase();
    const val = String(rawVal ?? '').trim();
    const valSample = val.length > 200 ? `${val.slice(0, 200)}…` : val;

    for (const h of collectVhostCandidates(nameLower, val)) {
      if (h && h !== pageHost) vhostCandidates.add(h);
    }

    if (nameLower === 'x-powered-by' && val) {
      push('med', 46, `Stack leak: ${name} @ ${pageHost}`, `Valor: ${valSample}`);
    } else if (nameLower === 'server' && /apache|nginx|iis|lighttpd|caddy|openresty|microsoft-iis/i.test(val)) {
      if (/\d+\.\d+|\/[\d.]+/i.test(val)) {
        push('low', 34, `Server com versão: ${val.slice(0, 80)} @ ${pageHost}`, `Cabeçalho Server`);
      }
    } else if (nameLower === 'x-aspnet-version' || nameLower === 'x-aspnetmvc-version') {
      push('med', 48, `ASP.NET exposto: ${name}=${valSample} @ ${pageHost}`, 'Framework / versão');
    } else if (nameLower === 'x-generator' && val) {
      push('low', 36, `CMS / gerador: ${name} @ ${pageHost}`, valSample);
    } else if (/^x-debug/i.test(nameLower) || nameLower === 'x-debug-token' || nameLower === 'x-debug-token-link') {
      push('high', 62, `Debug exposto: ${name} @ ${pageHost}`, valSample);
    } else if (nameLower === 'x-symfony-debug' || nameLower === 'symfony-debug-toolbar') {
      push('high', 60, `Symfony debug: ${name} @ ${pageHost}`, valSample);
    } else if (nameLower === 'x-robots-tag' && /noindex/i.test(val) && /noai|gptbot|ccbot/i.test(val)) {
      push('low', 22, `X-Robots-Tag (crawlers): ${val.slice(0, 100)} @ ${pageHost}`, 'Política de bots');
    } else if (nameLower === 'via' && val.length > 3) {
      push('low', 28, `Via (cadeia proxy): ${valSample} @ ${pageHost}`, 'Encaminhamento');
    } else if (nameLower === 'x-original-url' || nameLower === 'x-rewrite-url') {
      push('med', 50, `URL interna no header ${name} @ ${pageHost}`, valSample);
    } else if (nameLower === 'x-accel-redirect' || nameLower === 'x-internal') {
      push('med', 52, `Cabeçalho interno: ${name} @ ${pageHost}`, valSample);
    } else if (nameLower === 'x-forwarded-for' || nameLower === 'x-real-ip') {
      if (RFC1918.test(val) || val.split(/[\s,]+/).some((p) => RFC1918.test(p))) {
        push('med', 44, `IP interno em ${name} @ ${pageHost}`, valSample);
      }
    } else if (nameLower === 'access-control-allow-origin' && val === '*') {
      push('low', 30, `CORS wildcard (Access-Control-Allow-Origin: *) @ ${pageHost}`, 'Rever credenciais / reflexão');
    } else if (nameLower === 'strict-transport-security' && !/max-age=\d+/i.test(val)) {
      push('low', 32, `HSTS malformado ou fraco @ ${pageHost}`, valSample);
    }
  }

  if (vhostCandidates.size) {
    const snippet = buildEtcHostsSnippet([...vhostCandidates], pageHost, primaryIpv4);
    if (snippet) {
      push(
        'med',
        42,
        `Vhost / hostname alternativo nos headers → sugerir /etc/hosts (${vhostCandidates.size}) @ ${pageHost}`,
        `Colar no /etc/hosts (teste local):\n${snippet}`,
      );
    }
  }

  hits.sort((a, b) => b.score - a.score);
  return hits.slice(0, 24);
}
