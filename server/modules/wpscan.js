import { readFile, writeFile, mkdtemp, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { spawn } from 'node:child_process';

/**
 * Token da WordPress Vulnerability Database (wpscan.com).
 * WPScan CLI lê `WPSCAN_API_TOKEN` no ambiente (v3.7.10+); também aceitamos `GHOSTRECON_WPSCAN_API_TOKEN`.
 */
export function resolveWpscanApiToken() {
  const a = String(process.env.WPSCAN_API_TOKEN || '').trim();
  const b = String(process.env.GHOSTRECON_WPSCAN_API_TOKEN || '').trim();
  return a || b || '';
}

export function isWpscanApiTokenConfigured() {
  return Boolean(resolveWpscanApiToken());
}

/**
 * Por defeito o WPScan só corre com token (WPVulnDB).
 * `GHOSTRECON_WPSCAN_REQUIRE_API=0` permite executar wpscan sem API (só enumeração).
 */
export function isWpscanApiRequired() {
  return String(process.env.GHOSTRECON_WPSCAN_REQUIRE_API ?? '1').trim() !== '0';
}

function runProc(cmd, args, timeoutMs, spawnOpts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      ...spawnOpts,
    });
    const out = [];
    const err = [];
    let killed = false;

    const t = setTimeout(() => {
      killed = true;
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
      reject(new Error(`${cmd} timeout (${timeoutMs}ms)`));
    }, timeoutMs);

    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => {
      clearTimeout(t);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(t);
      if (killed) return;
      resolve({
        code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      });
    });
  });
}

function safeConfidence(n) {
  const x = Number(n);
  return Number.isFinite(x) ? x : null;
}

function prioScoreFromVersionConfidence({ hasVersion, confidence }) {
  const c = safeConfidence(confidence);
  if (!hasVersion) return { prio: 'low', score: 40 };
  if (c != null && c >= 80) return { prio: 'med', score: 80 };
  return { prio: 'med', score: 70 };
}

function extractMainThemeFindings(targetUrl, wps) {
  const out = [];
  const mt = wps?.main_theme;
  if (!mt?.slug) return out;

  const location = mt.location || null;
  const version = mt?.version?.number || null;
  const confidence = mt?.version?.confidence ?? null;

  const { prio, score } = prioScoreFromVersionConfidence({ hasVersion: Boolean(version), confidence });
  out.push({
    type: 'wpscan',
    prio,
    score,
    value: version ? `Main theme: ${mt.slug} v${version}` : `Main theme: ${mt.slug}`,
    meta: `found_by=${mt?.version?.found_by || mt?.found_by || 'unknown'}; confidence=${confidence ?? '—'}`,
    url: location || targetUrl,
  });

  return out;
}

function extractPluginsFindings(targetUrl, wps) {
  const out = [];
  const plugins = wps?.plugins;
  if (!plugins || typeof plugins !== 'object') return out;

  for (const [slug, p] of Object.entries(plugins)) {
    if (slug === '*') continue; // placeholder entry
    if (!p || typeof p !== 'object') continue;

    const location = p.location || null;
    const version = p?.version?.number || null;
    const confidence = p?.version?.confidence ?? p?.confidence ?? null;

    const { prio, score } = prioScoreFromVersionConfidence({ hasVersion: Boolean(version), confidence });
    out.push({
      type: 'wpscan',
      prio,
      score,
      value: version ? `Plugin: ${slug} v${version}` : `Plugin: ${slug}`,
      meta: `found_by=${p?.version?.found_by || p?.found_by || 'unknown'}; confidence=${confidence ?? '—'}`,
      url: location || targetUrl,
    });
  }

  return out;
}

function cvesFromReferences(refs) {
  if (!refs || typeof refs !== 'object') return [];
  const raw = refs.cve ?? refs.CVE ?? refs.cves;
  if (Array.isArray(raw)) return raw.map((x) => String(x).trim()).filter(Boolean);
  if (typeof raw === 'string') return [raw.trim()].filter(Boolean);
  return [];
}

function normalizeVulnArray(v) {
  if (!Array.isArray(v)) return [];
  return v.filter((x) => x && typeof x === 'object');
}

/**
 * Vulnerabilidades da WPVulnDB (só aparecem no JSON com `--api-token` / WPSCAN_API_TOKEN).
 */
function extractVulnerabilityFindings(targetUrl, wps) {
  const out = [];
  const seen = new Set();

  function pushVuln(contextLabel, vuln, pageUrl) {
    const title = String(vuln.title || vuln.Title || 'Vulnerability').trim() || 'Vulnerability';
    const refs = vuln.references;
    const cves = cvesFromReferences(refs);
    const key = `${contextLabel}|${title}|${cves.join(',')}`;
    if (seen.has(key)) return;
    seen.add(key);

    const cveStr = cves.length ? cves.join(', ') : '';
    const value = cveStr
      ? `WPVulnDB: ${contextLabel} — ${cveStr}`
      : `WPVulnDB: ${contextLabel} — ${title}`;
    const fixed = vuln.fixed_in ? `fixed_in=${vuln.fixed_in}` : '';
    const meta = [title, cveStr && `CVE: ${cveStr}`, fixed].filter(Boolean).join(' · ');

    out.push({
      type: 'wpscan',
      prio: cveStr ? 'high' : 'med',
      score: cveStr ? 88 : 68,
      value,
      meta,
      url: pageUrl || targetUrl,
    });
  }

  const vCore = normalizeVulnArray(wps?.version?.vulnerabilities);
  for (const vuln of vCore) pushVuln('WordPress core', vuln, targetUrl);

  const mt = wps?.main_theme;
  if (mt?.slug) {
    const label = `Theme ${mt.slug}`;
    for (const vuln of normalizeVulnArray(mt.vulnerabilities)) pushVuln(label, vuln, mt.location || targetUrl);
    for (const vuln of normalizeVulnArray(mt.version?.vulnerabilities)) pushVuln(label, vuln, mt.location || targetUrl);
  }

  const plugins = wps?.plugins;
  if (plugins && typeof plugins === 'object') {
    for (const [slug, p] of Object.entries(plugins)) {
      if (slug === '*' || !p || typeof p !== 'object') continue;
      const label = `Plugin ${slug}`;
      const loc = p.location || targetUrl;
      for (const vuln of normalizeVulnArray(p.vulnerabilities)) pushVuln(label, vuln, loc);
      for (const vuln of normalizeVulnArray(p.version?.vulnerabilities)) pushVuln(label, vuln, loc);
    }
  }

  return out;
}

/** Número de vulnerabilidades reportadas no JSON (campos alimentados pela WPVulnDB com token). */
export function countWpvulndbFindings(wpscanJson) {
  if (!wpscanJson || typeof wpscanJson !== 'object') return 0;
  return extractVulnerabilityFindings('https://example.invalid/', wpscanJson).length;
}

function extractCoreVersionFindings(targetUrl, wps) {
  const out = [];
  const v = wps?.version;
  if (!v || typeof v !== 'object') return out;

  const number = v?.number;
  if (!number) return out;

  const confidence = v?.confidence ?? null;
  const { prio, score } = prioScoreFromVersionConfidence({ hasVersion: true, confidence });
  out.push({
    type: 'wpscan',
    prio,
    score,
    value: `WordPress version: ${number}`,
    meta: `found_by=${v?.found_by || 'unknown'}; confidence=${confidence ?? '—'}`,
    url: targetUrl,
  });
  return out;
}

export function extractWpscanFindings({ targetUrl, wpscanJson }) {
  if (!wpscanJson || typeof wpscanJson !== 'object') return [];
  const vulns = extractVulnerabilityFindings(targetUrl, wpscanJson);
  const rest = [
    ...extractCoreVersionFindings(targetUrl, wpscanJson),
    ...extractMainThemeFindings(targetUrl, wpscanJson),
    ...extractPluginsFindings(targetUrl, wpscanJson),
  ];

  // Vulnerabilidades (API) primeiro; depois enumeração de versões.
  const merged = [...vulns, ...rest];
  const maxFindings = 100;
  return merged.slice(0, maxFindings);
}

/**
 * Rodar wpscan e retornar JSON parseado.
 * @returns {Promise<{ json: any|null, error?: string, stderr?: string, vulnDbCount?: number }>}
 */
export async function runWpscanJson({ targetUrl, detectionMode, timeoutMs, log }) {
  const dir = await mkdtemp(join(tmpdir(), 'ghwp-'));
  const outJson = join(dir, 'wpscan.json');

  const mode = detectionMode || 'mixed';
  const timeout = Number(timeoutMs) > 0 ? Number(timeoutMs) : 240000;
  const apiToken = resolveWpscanApiToken();

  try {
    const args = [
      '--url',
      targetUrl,
      '--detection-mode',
      mode,
      '--format',
      'json',
      '-o',
      outJson,
      '--random-user-agent',
      '--no-banner',
      '--force',
    ];

    if (apiToken) {
      args.push('--api-token', apiToken);
    }

    const spawnEnv = { ...process.env };
    if (apiToken) spawnEnv.WPSCAN_API_TOKEN = apiToken;

    const label = `wpscan ${mode} ${targetUrl}${apiToken ? ' (API WPVulnDB)' : ''}`;
    if (typeof log === 'function') {
      log(`[WPScan] A executar ferramenta: wpscan --url ${targetUrl} --detection-mode ${mode} --format json …`, 'info');
      log(
        `[WPScan] WPVulnDB (API CVEs): ${apiToken ? 'ligado — token definido' : 'desligado — sem WPSCAN_API_TOKEN'}`,
        apiToken ? 'success' : 'warn',
      );
      log(`[WPScan] Timeout: ${timeout}ms (JSON escrito em ficheiro temporário, depois parseado)`, 'info');
      log(`Executando ${label}...`, 'info');
    }

    const proc = await runProc('wpscan', args, timeout, { env: spawnEnv });
    if (proc.code !== 0) {
      if (typeof log === 'function') log(`[WPScan] ${label} terminou com código ${proc.code}`, 'warn');
    }

    const raw = await readFile(outJson, 'utf8');
    try {
      const json = JSON.parse(raw);
      const vulnDbCount = countWpvulndbFindings(json);
      if (typeof log === 'function') {
        log(`[WPScan] JSON analisado — entradas WPVulnDB (CVEs) no relatório: ${vulnDbCount}`, vulnDbCount ? 'success' : 'info');
        const va = json?.vuln_api;
        if (va && typeof va === 'object' && va.error) {
          log(`[WPScan] Aviso API WPVulnDB: ${String(va.error)}`, 'warn');
        }
      }
      return { json, vulnDbCount, stderr: proc.stderr || '' };
    } catch (e) {
      return { json: null, error: `JSON parse error: ${e.message}`, stderr: proc.stderr || '' };
    }
  } catch (e) {
    return { json: null, error: String(e?.message || e), stderr: '' };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

