import fs from 'fs/promises';
import path from 'path';
import { spawn } from 'child_process';

const ONE_DAY_MS = 24 * 60 * 60 * 1000;
const ONE_MONTH_MS = 30 * ONE_DAY_MS;

function parseBool(v, defaultValue = false) {
  if (v == null || String(v).trim() === '') return defaultValue;
  const n = String(v).trim().toLowerCase();
  return n === '1' || n === 'true' || n === 'yes' || n === 'on';
}

export function githubCloneConfig() {
  const enabled = parseBool(
    process.env.GHOSTCTF_GITHUB_CLONE_ENABLED ?? process.env.GHOSTRECON_GITHUB_CLONE_ENABLED,
    true,
  );
  const cloneDir = String(process.env.GHOSTCTF_CLONE_DIR || process.env.GHOSTRECON_CLONE_DIR || 'clone')
    .trim()
    .replace(/\\/g, '/');
  const maxRepos = Math.max(1, Math.min(Number(process.env.GHOSTRECON_CLONE_MAX_REPOS) || 3, 10));
  const cloneTimeoutMs = Math.max(15000, Math.min(Number(process.env.GHOSTRECON_CLONE_TIMEOUT_MS) || 120000, 600000));
  const maxSizeMb = Math.max(50, Math.min(Number(process.env.GHOSTRECON_CLONE_MAX_SIZE_MB) || 200, 4096));
  const retentionDays = Math.max(1, Math.min(Number(process.env.GHOSTRECON_CLONE_RETENTION_DAYS) || 30, 365));
  return {
    enabled,
    cloneDir,
    maxRepos,
    cloneTimeoutMs,
    maxSizeBytes: maxSizeMb * 1024 * 1024,
    retentionMs: retentionDays * ONE_DAY_MS || ONE_MONTH_MS,
  };
}

function safeName(input) {
  return String(input || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 120) || 'repo';
}

function buildRepoCloneDir(baseDir, targetDomain, fullName) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const domainPart = safeName(targetDomain);
  const repoPart = safeName(String(fullName || '').replace(/\//g, '__'));
  return path.join(baseDir, `${domainPart}__${repoPart}__${stamp}`);
}

async function dirExists(p) {
  try {
    const st = await fs.stat(p);
    return st.isDirectory();
  } catch {
    return false;
  }
}

async function ensureDir(p) {
  await fs.mkdir(p, { recursive: true });
  return p;
}

function runGitClone(cloneUrl, targetDir, timeoutMs) {
  return new Promise((resolve, reject) => {
    const args = ['clone', '--depth', '1', '--filter=blob:none', '--no-tags', cloneUrl, targetDir];
    const child = spawn('git', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`timeout no clone (${timeoutMs}ms)`));
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      stdout += String(d || '');
    });
    child.stderr.on('data', (d) => {
      stderr += String(d || '');
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve({ ok: true, stdout, stderr });
      else reject(new Error(`git clone falhou (${code}): ${(stderr || stdout || '').slice(0, 400)}`));
    });
  });
}

async function calcDirSizeBytes(dirPath, capBytes) {
  let total = 0;
  const stack = [dirPath];
  while (stack.length) {
    const current = stack.pop();
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const st = await fs.stat(full);
      total += st.size || 0;
      if (total > capBytes) return total;
    }
  }
  return total;
}

export async function pruneOldCloneDirs(baseDir, retentionMs, log = null) {
  if (!(await dirExists(baseDir))) return { scanned: 0, removed: 0 };
  const now = Date.now();
  const entries = await fs.readdir(baseDir, { withFileTypes: true });
  let scanned = 0;
  let removed = 0;
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    scanned += 1;
    const full = path.join(baseDir, entry.name);
    try {
      const st = await fs.stat(full);
      if (now - st.mtimeMs <= retentionMs) continue;
      await fs.rm(full, { recursive: true, force: true });
      removed += 1;
    } catch (e) {
      if (typeof log === 'function') log(`Clone cleanup falhou em ${entry.name}: ${e.message}`, 'warn');
    }
  }
  return { scanned, removed };
}

export async function cloneGithubReposForTarget({ targetDomain, repos, log = null } = {}) {
  const cfg = githubCloneConfig();
  if (!cfg.enabled) return { ok: true, skipped: true, reason: 'disabled' };
  const baseDir = path.resolve(process.cwd(), cfg.cloneDir);
  await ensureDir(baseDir);

  const cleanup = await pruneOldCloneDirs(baseDir, cfg.retentionMs, log);
  if (typeof log === 'function' && cleanup.removed > 0) {
    log(`Clone cleanup: ${cleanup.removed} pasta(s) removida(s) por retenção`, 'info');
  }

  const selected = Array.isArray(repos) ? repos.slice(0, cfg.maxRepos) : [];
  const cloned = [];
  const failed = [];

  for (const repo of selected) {
    const fullName = String(repo.full_name || '').trim();
    const cloneUrl = String(repo.clone_url || '').trim();
    if (!fullName || !cloneUrl) continue;
    const repoDir = buildRepoCloneDir(baseDir, targetDomain, fullName);
    try {
      await runGitClone(cloneUrl, repoDir, cfg.cloneTimeoutMs);
      const sizeBytes = await calcDirSizeBytes(repoDir, cfg.maxSizeBytes);
      if (sizeBytes > cfg.maxSizeBytes) {
        await fs.rm(repoDir, { recursive: true, force: true });
        throw new Error(`repo acima do limite (${Math.round(sizeBytes / (1024 * 1024))}MB)`);
      }
      cloned.push({
        full_name: fullName,
        clone_url: cloneUrl,
        local_path: repoDir,
        size_bytes: sizeBytes,
      });
    } catch (e) {
      try {
        await fs.rm(repoDir, { recursive: true, force: true });
      } catch {
        /* ignore */
      }
      failed.push({
        full_name: fullName,
        error: e?.message || String(e),
      });
    }
  }

  return {
    ok: true,
    base_dir: baseDir,
    retention_ms: cfg.retentionMs,
    max_repos: cfg.maxRepos,
    cloned,
    failed,
    selected_count: selected.length,
  };
}
