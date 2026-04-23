import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

function defaultGhostRoot() {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

/**
 * Resolve o diretório raiz do Shannon Lite (clone em IAs/shannon).
 * @param {string} [ghostRoot]
 */
export function resolveShannonHome(ghostRoot = defaultGhostRoot()) {
  const raw = String(process.env.GHOSTRECON_SHANNON_HOME || '').trim();
  if (raw) return path.resolve(raw);
  return path.join(ghostRoot, 'IAs', 'shannon');
}

/**
 * Diagnóstico read-only para UI e gate no recon.
 * @param {{ ghostRoot?: string }} [opts]
 */
export async function getShannonCapabilities(opts = {}) {
  const ghostRoot = opts.ghostRoot || defaultGhostRoot();
  const home = resolveShannonHome(ghostRoot);

  const checks = {
    docker: false,
    shannonHome: false,
    entryScript: false,
    cliBuilt: false,
    workerImage: false,
  };

  try {
    await execFileAsync('docker', ['info'], { timeout: 8000, maxBuffer: 512 * 1024 });
    checks.docker = true;
  } catch {
    /* ignore */
  }

  try {
    checks.shannonHome = fs.existsSync(home) && fs.statSync(home).isDirectory();
  } catch {
    checks.shannonHome = false;
  }

  const entry = path.join(home, 'shannon');
  try {
    checks.entryScript = fs.existsSync(entry) && fs.statSync(entry).isFile();
  } catch {
    checks.entryScript = false;
  }

  const cliDist = path.join(home, 'apps', 'cli', 'dist', 'index.mjs');
  try {
    checks.cliBuilt = fs.existsSync(cliDist) && fs.statSync(cliDist).isFile();
  } catch {
    checks.cliBuilt = false;
  }

  try {
    const { stdout } = await execFileAsync('docker', ['images', '-q', 'shannon-worker'], {
      timeout: 12000,
      maxBuffer: 64 * 1024,
    });
    checks.workerImage = Boolean(String(stdout || '').trim());
  } catch {
    checks.workerImage = false;
  }

  const ok =
    checks.docker &&
    checks.shannonHome &&
    checks.entryScript &&
    checks.cliBuilt &&
    checks.workerImage;

  const parts = [];
  if (!checks.docker) parts.push('Docker não responde (docker info)');
  if (!checks.shannonHome) parts.push(`Pasta Shannon ausente: ${home}`);
  if (!checks.entryScript) parts.push('Script ./shannon não encontrado');
  if (!checks.cliBuilt) parts.push('CLI não compilada (em IAs/shannon: pnpm install && pnpm build)');
  if (!checks.workerImage) parts.push('Imagem Docker shannon-worker ausente (em IAs/shannon: ./shannon build)');

  const message = ok
    ? 'Dependências Shannon OK (Docker + build local).'
    : parts.join(' · ');

  return {
    ok,
    home,
    checks,
    message,
    prepHints: {
      localBuild: 'cd IAs/shannon && pnpm install && pnpm build && ./shannon build',
      pullUpstream: 'Opcional: POST /api/shannon/prep com {"pullUpstream":true} para docker pull keygraph/shannon:latest (fluxo npx)',
    },
  };
}

/**
 * Tenta puxar a imagem publicada (útil se no futuro usares npx); no modo local o worker é shannon-worker.
 * @returns {{ ok: boolean, note?: string, dockerPullLog?: string }}
 */
export async function shannonPullUpstreamWorkerImage() {
  const pullArgs = ['pull', 'keygraph/shannon:latest'];
  const opts = {
    timeout: 600000,
    maxBuffer: 4 * 1024 * 1024,
    encoding: 'utf8',
  };
  try {
    const { stdout, stderr } = await execFileAsync('docker', pullArgs, opts);
    const dockerPullLog = [stdout, stderr].filter(Boolean).join('\n').trim();
    return {
      ok: true,
      note: 'keygraph/shannon:latest atualizada.',
      dockerPullLog: dockerPullLog || '(docker pull sem saída no stdout/stderr)',
    };
  } catch (e) {
    const stderr = typeof e?.stderr === 'string' ? e.stderr : '';
    const stdout = typeof e?.stdout === 'string' ? e.stdout : '';
    const dockerPullLog = [stdout, stderr].filter(Boolean).join('\n').trim();
    return {
      ok: false,
      note: e?.message || String(e),
      dockerPullLog: dockerPullLog || undefined,
    };
  }
}
