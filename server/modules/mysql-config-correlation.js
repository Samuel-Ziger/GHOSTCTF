/**
 * Correlaciona portas MySQL (3306) vistas no nmap com URLs de configuração na mesma origem.
 */

function normalizeHost(h) {
  return String(h || '')
    .trim()
    .replace(/^\[|\]$/g, '')
    .toLowerCase();
}

/** Hosts com 3306/tcp (ou udp) a partir de achados `nmap` ou intel mysql_cli. */
export function collectMysql3306HostsFromFindings(findings) {
  const hosts = new Set();
  for (const f of findings || []) {
    const v = String(f?.value || '');
    const meta = String(f?.meta || '');
    if (f?.type === 'nmap') {
      const m = v.match(/(?:^|\s)(tcp|udp)\/3306\s+(\S+)/i);
      if (m) hosts.add(normalizeHost(m[2]));
    }
    if (meta.includes('mysql_cli=mysql')) {
      const m2 = meta.match(/mysql_cli=mysql\s+-h\s+([^\s]+)/i);
      if (m2) hosts.add(normalizeHost(m2[1]));
    }
  }
  return [...hosts].filter(Boolean);
}

export function pathnameLooksLikeDbOrAppConfig(pathname) {
  const p = String(pathname || '').toLowerCase();
  if (!p || p.length > 260) return false;
  if (/\.env($|[.@])|\/\.env($|[.@])/i.test(p)) return true;
  if (/(^|\/)wp-config\.php$/i.test(p)) return true;
  if (/(^|\/)(config|database|settings|credentials)\.php$/i.test(p)) return true;
  if (/\/config\/[^/]+\.(php|ya?ml|json|yml)$/i.test(p)) return true;
  if (/(^|\/)application\.ya?ml$/i.test(p)) return true;
  if (/(^|\/)docker-compose\.ya?ml$/i.test(p)) return true;
  if (/(^|\/)credentials\.(json|ya?ml|yml|properties)$/i.test(p)) return true;
  if (/(^|\/)database\.ya?ml$/i.test(p)) return true;
  return false;
}

/**
 * @param {object[]} findings
 * @param {{ max?: number }} [opts]
 * @returns {object[]} achados `intel` a acrescentar
 */
export function buildMysqlConfigSurfaceCorrelationFindings(findings, opts = {}) {
  const max = Math.max(1, Math.min(24, opts.max ?? 14));
  const mysqlHosts = new Set(collectMysql3306HostsFromFindings(findings));
  if (!mysqlHosts.size) return [];

  const out = [];
  const seenUrl = new Set();

  const considerUrl = (urlStr) => {
    if (out.length >= max) return;
    if (!urlStr || typeof urlStr !== 'string' || !/^https?:\/\//i.test(urlStr)) return;
    let u;
    try {
      u = new URL(urlStr);
    } catch {
      return;
    }
    const host = normalizeHost(u.hostname);
    if (!mysqlHosts.has(host)) return;
    if (!pathnameLooksLikeDbOrAppConfig(u.pathname)) return;
    const key = u.href.split('#')[0];
    if (seenUrl.has(key)) return;
    seenUrl.add(key);
    out.push({
      type: 'intel',
      prio: 'high',
      score: 72,
      value: `3306/tcp (MySQL) na mesma origem que ficheiro de configuração: ${u.pathname}`,
      meta: `mysql_config_surface • host=${host} • rever credenciais em ficheiro + acesso à BD (só alvo autorizado)`,
      url: key,
    });
  };

  for (const f of findings || []) {
    if (f?.type === 'endpoint') considerUrl(f.url || f.value);
    if (f?.type === 'param' && f.url) considerUrl(f.url);
    if (f?.type === 'intel' && f.url && /config|\.env|database|credentials/i.test(String(f.value || f.meta || ''))) {
      considerUrl(f.url);
    }
  }
  return out;
}
