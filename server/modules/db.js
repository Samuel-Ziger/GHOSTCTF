import * as sqlite from './db-sqlite.js';
import * as supabase from './db-supabase.js';
import * as pg from './db-pg.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

export { fingerprintFinding, norm } from './db-common.js';
export { resolveLocalProjectDbDir, sanitizePathSegment } from './db-sqlite.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..', '..');
const VALIDATE_DIR = path.join(ROOT, 'Validate');

/** Conexão direta Postgres (recomendado no Node; IPv4 → Session Pooler no dashboard). */
function useDatabaseUrl() {
  return Boolean(process.env.DATABASE_URL?.trim());
}

function useSupabaseApi() {
  if (useDatabaseUrl()) return false;
  const url = process.env.SUPABASE_URL?.trim();
  const key =
    process.env.SUPABASE_SERVICE_ROLE_KEY?.trim() ||
    process.env.SUPABASE_ANON_KEY?.trim() ||
    process.env.SUPABASE_KEY?.trim() ||
    process.env.SUPABASE_PUBLISHABLE_KEY?.trim();
  return Boolean(url && key);
}

export function isUsingSupabase() {
  return useDatabaseUrl() || useSupabaseApi();
}

export function storageLabel() {
  if (useDatabaseUrl()) return 'Supabase Postgres (DATABASE_URL)';
  if (useSupabaseApi()) return 'Supabase (API REST)';
  return 'SQLite (data/bugbounty.db)';
}

function ensureValidateDir() {
  fs.mkdirSync(VALIDATE_DIR, { recursive: true });
  return VALIDATE_DIR;
}

function isSha256FingerprintHex(fp) {
  return /^[a-f0-9]{64}$/.test(String(fp || '').trim().toLowerCase());
}

function normalizeValidationArchiveRecord(row) {
  const target = String(row?.target || '')
    .trim()
    .toLowerCase();
  const fingerprint = String(row?.fingerprint || '')
    .trim()
    .toLowerCase();
  const domainOk = /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(target);
  const ipOk = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(target);
  if (!target || (!domainOk && !ipOk)) return null;
  if (!isSha256FingerprintHex(fingerprint)) return null;
  return {
    target,
    fingerprint,
    validated_at: String(row?.validated_at || row?.validatedAt || new Date().toISOString()),
    notes: row?.notes != null ? String(row.notes) : '',
    snapshot: row?.snapshot && typeof row.snapshot === 'object' ? row.snapshot : null,
    brainCategoryId:
      row?.brainCategoryId != null && Number.isFinite(Number(row.brainCategoryId))
        ? Number(row.brainCategoryId)
        : null,
    brainCategoryTitle:
      row?.brainCategoryTitle != null && String(row.brainCategoryTitle).trim()
        ? String(row.brainCategoryTitle).trim()
        : null,
  };
}

function validationArchivePath(targetRaw, fingerprintRaw) {
  const target = sqlite.sanitizePathSegment(String(targetRaw || '').trim().toLowerCase(), 'target');
  const fp = String(fingerprintRaw || '').trim().toLowerCase();
  return path.join(ensureValidateDir(), target, `${fp}.json`);
}

function writeValidationArchive(row) {
  const rec = normalizeValidationArchiveRecord(row);
  if (!rec) return;
  const filePath = validationArchivePath(rec.target, rec.fingerprint);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(rec, null, 2), 'utf8');
}

function deleteValidationArchive(targetRaw, fingerprintRaw) {
  const filePath = validationArchivePath(targetRaw, fingerprintRaw);
  try {
    fs.unlinkSync(filePath);
  } catch (e) {
    if (e?.code !== 'ENOENT') throw e;
  }
}

function listValidationArchivesForTarget(targetRaw) {
  const target = String(targetRaw || '')
    .trim()
    .toLowerCase();
  const domainOk = /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(target);
  const ipOk = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(target);
  if (!target || (!domainOk && !ipOk)) return [];
  const dir = path.join(ensureValidateDir(), sqlite.sanitizePathSegment(target, 'target'));
  if (!fs.existsSync(dir)) return [];
  let names = [];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    if (!name.endsWith('.json')) continue;
    const full = path.join(dir, name);
    try {
      const raw = fs.readFileSync(full, 'utf8');
      const rec = normalizeValidationArchiveRecord(JSON.parse(raw));
      if (rec && rec.target === target) out.push(rec);
    } catch {
      /* ignora ficheiro inválido */
    }
  }
  out.sort((a, b) => String(b.validated_at).localeCompare(String(a.validated_at)));
  return out;
}

/**
 * @param {object} payload
 * @param {string} [payload.localProjectName] nome da pasta projeto; cria `escopo/{nome}/{domínio}/ghostrecon.db`
 * @returns {Promise<{ runId: number, intelMerge: object, localMirrorPath?: string } | null>}
 */
export async function saveRun(payload) {
  const { localProjectName, ...rest } = payload;
  const projectDir = sqlite.resolveLocalProjectDbDir(localProjectName, rest.target);
  const useRemote = useDatabaseUrl() || useSupabaseApi();

  let result = null;
  if (useDatabaseUrl()) {
    result = await pg.saveRun(rest);
  } else if (useSupabaseApi()) {
    result = await supabase.saveRun(rest);
  } else if (projectDir) {
    result = sqlite.saveRunToProjectDir(projectDir, rest);
  } else {
    result = sqlite.saveRun(rest);
  }

  if (projectDir && useRemote) {
    try {
      const mirror = sqlite.saveRunToProjectDir(projectDir, rest);
      if (mirror?.dbPath) {
        if (result) {
          result = { ...result, localMirrorPath: mirror.dbPath };
        } else {
          result = {
            runId: mirror.runId,
            intelMerge: mirror.intelMerge,
            localMirrorPath: mirror.dbPath,
            remoteSaveFailed: true,
          };
        }
      }
    } catch (e) {
      console.error('[GHOSTRECON local mirror]', e);
    }
  }

  if (result?.runId != null && String(localProjectName || '').trim() && Array.isArray(rest.findings)) {
    try {
      const d = sqlite.getDb();
      const m = sqlite.mergeProjectSecretPeersDb(d, localProjectName, rest.target, result.runId, rest.findings);
      result = { ...result, projectSecretDuplicates: m.duplicates };
    } catch (e) {
      console.warn('[GHOSTCTF project_secret_peers]', e?.message || e);
    }
  }

  return result;
}

/** Correlação de segredos (value_fp) entre alvos no mesmo nome de projeto — índice em SQLite local. */
export function listProjectSecretDuplicates(projectName) {
  try {
    const d = sqlite.getDb();
    return sqlite.listProjectSecretDuplicatesSqlite(d, sqlite.sanitizePathSegment(String(projectName || '').trim()));
  } catch (e) {
    console.error('[GHOSTCTF listProjectSecretDuplicates]', e.message);
    return [];
  }
}

export async function listRuns(limit) {
  if (useDatabaseUrl()) return pg.listRuns(limit);
  if (useSupabaseApi()) return supabase.listRuns(limit);
  return sqlite.listRuns(limit);
}

export async function getRunById(id) {
  if (useDatabaseUrl()) return pg.getRunById(id);
  if (useSupabaseApi()) return supabase.getRunById(id);
  return sqlite.getRunById(id);
}

export async function listIntelForTarget(target, limit) {
  if (useDatabaseUrl()) return pg.listIntelForTarget(target, limit);
  if (useSupabaseApi()) return supabase.listIntelForTarget(target, limit);
  return sqlite.listIntelForTarget(target, limit);
}

export async function intelCountForTarget(target) {
  if (useDatabaseUrl()) return pg.intelCountForTarget(target);
  if (useSupabaseApi()) return supabase.intelCountForTarget(target);
  return sqlite.intelCountForTarget(target);
}

export async function listKnowledge(limit) {
  if (useDatabaseUrl()) return [];
  if (useSupabaseApi()) return [];
  return sqlite.listKnowledge(limit);
}

/** Validação manual sempre em SQLite local + espelho em `Validate/`. */
export async function listManualValidationsForTarget(target) {
  const fromArchive = listValidationArchivesForTarget(target);
  const archiveByFp = new Map(fromArchive.map((x) => [x.fingerprint, x]));
  try {
    const fromDb = sqlite.listManualValidationsForTarget(target);
    const merged = fromDb.map((x) => {
      const a = archiveByFp.get(String(x.fingerprint || '').toLowerCase());
      return a
        ? {
            ...x,
            notes: a.notes != null ? String(a.notes) : x.notes,
            snapshot: a.snapshot ?? x.snapshot ?? null,
          }
        : x;
    });
    const mergedFp = new Set(merged.map((x) => String(x.fingerprint || '').toLowerCase()));
    for (const a of fromArchive) {
      if (mergedFp.has(a.fingerprint)) continue;
      merged.push({
        fingerprint: a.fingerprint,
        validated_at: a.validated_at,
        notes: a.notes,
        snapshot: a.snapshot,
        brainCategoryId: a.brainCategoryId,
        brainCategoryTitle: a.brainCategoryTitle,
      });
    }
    return merged.sort((a, b) => String(b.validated_at).localeCompare(String(a.validated_at)));
  } catch (e) {
    console.error('[GHOSTRECON manual_validations list]', e?.message || e);
    return fromArchive;
  }
}

export async function upsertManualValidation(row) {
  const out = sqlite.upsertManualValidation(row);
  try {
    writeValidationArchive({
      target: row?.target,
      fingerprint: row?.fingerprint,
      validated_at: new Date().toISOString(),
      snapshot: row?.snapshot ?? null,
      notes: row?.notes ?? '',
    });
  } catch (e) {
    console.error('[GHOSTRECON manual_validations archive write]', e?.message || e);
  }
  return out;
}

export async function deleteManualValidation(target, fingerprint) {
  const out = sqlite.deleteManualValidation(target, fingerprint);
  try {
    deleteValidationArchive(target, fingerprint);
  } catch (e) {
    console.error('[GHOSTRECON manual_validations archive delete]', e?.message || e);
  }
  return out;
}

/** Categorias do «cérebro» sempre em SQLite local. */
export async function listBrainCategories() {
  try {
    return sqlite.listBrainCategories();
  } catch (e) {
    console.error('[GHOSTRECON brain categories]', e?.message || e);
    return [];
  }
}

export async function createBrainCategory(title, description = '') {
  return sqlite.createBrainCategory(title, description);
}

/** Apaga categoria e ligações (`brain_links`). Só SQLite local; categorias semente não podem ser apagadas. */
export async function deleteBrainCategory(idRaw) {
  if (useDatabaseUrl() || useSupabaseApi()) {
    throw new Error('Apagar categorias do cérebro está disponível apenas com SQLite local.');
  }
  return sqlite.deleteBrainCategoryById(idRaw);
}

/** Limpeza no cérebro: categorias derivadas de `historicos/CTFsSolyd/falhas em ordem` (sem criar biblioteca; só SQLite local). */
export async function syncBrainHistoricoFalhas() {
  if (useDatabaseUrl() || useSupabaseApi()) {
    return {
      ok: false,
      error: 'Sincronização histórico → cérebro disponível apenas com SQLite local.',
      count: 0,
    };
  }
  const { runSyncFalhasHistoricoToBrain } = await import('../ghostctf/brain-sync-falhas-historico.js');
  return runSyncFalhasHistoricoToBrain();
}

export async function updateBrainCategoryDescription(id, description) {
  return sqlite.updateBrainCategoryDescription(id, description);
}

export async function upsertBrainLink(row) {
  return sqlite.upsertBrainLink(row);
}

export async function listBrainLinksForFinding(target, fingerprint) {
  try {
    return sqlite.listBrainLinksForFinding(target, fingerprint);
  } catch (e) {
    console.error('[GHOSTCTF brain finding links]', e?.message || e);
    return [];
  }
}

export async function deleteBrainLink(row) {
  return sqlite.deleteBrainLink(row);
}

export async function getBrainCategoryById(id) {
  try {
    return sqlite.getBrainCategoryById(id);
  } catch {
    return null;
  }
}

export async function listBrainLinksForCategory(categoryId) {
  try {
    return sqlite.listBrainLinksForCategory(categoryId);
  } catch (e) {
    console.error('[GHOSTRECON brain links]', e?.message || e);
    return [];
  }
}
