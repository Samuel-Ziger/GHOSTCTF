import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { findingsForRunsTable, fingerprintFinding, knowledgeKeyFromFinding, norm } from './db-common.js';
import { buildSecretPeerRows } from './secret-project-peers.js';
import { parseFindingsSnapshotJson } from './finding-serialize.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..', '..');
export const DATA_DIR = path.join(ROOT, 'data');
/** Raiz local por projeto/escopo — pasta `escopo/` na raiz do repo (ignorada no git). */
export const SCOPE_DIR = path.join(ROOT, 'escopo');
const DEFAULT_DB = path.join(DATA_DIR, 'bugbounty.db');

const SCHEMA_SQL = `
    CREATE TABLE IF NOT EXISTS runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      exact_match INTEGER NOT NULL DEFAULT 0,
      modules_json TEXT NOT NULL,
      stats_json TEXT NOT NULL,
      correlation_json TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id INTEGER NOT NULL,
      type TEXT,
      prio TEXT,
      score INTEGER,
      value TEXT,
      meta TEXT,
      url TEXT,
      FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);

    CREATE TABLE IF NOT EXISTS bounty_intel (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      fp TEXT NOT NULL,
      type TEXT,
      prio TEXT,
      score INTEGER,
      value TEXT,
      meta TEXT,
      url TEXT,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      last_run_id INTEGER,
      UNIQUE(target, fp)
    );
    CREATE INDEX IF NOT EXISTS idx_intel_target ON bounty_intel(target);

    CREATE TABLE IF NOT EXISTS ctf_knowledge (
      k TEXT PRIMARY KEY,
      type TEXT,
      sample TEXT,
      count INTEGER NOT NULL DEFAULT 0,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_knowledge_type ON ctf_knowledge(type);

    CREATE TABLE IF NOT EXISTS manual_validations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      validated_at TEXT NOT NULL,
      snapshot_json TEXT,
      notes TEXT,
      UNIQUE(target, fingerprint)
    );
    CREATE INDEX IF NOT EXISTS idx_manual_val_target ON manual_validations(target);

    CREATE TABLE IF NOT EXISTS brain_categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_brain_cat_title ON brain_categories(title);

    CREATE TABLE IF NOT EXISTS brain_links (
      category_id INTEGER NOT NULL,
      target TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      linked_at TEXT NOT NULL,
      PRIMARY KEY (category_id, target, fingerprint),
      FOREIGN KEY (category_id) REFERENCES brain_categories(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_brain_links_category ON brain_links(category_id);

    CREATE TABLE IF NOT EXISTS project_secret_peers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_name TEXT NOT NULL,
      value_fp TEXT NOT NULL,
      target TEXT NOT NULL,
      kind_hint TEXT,
      value_preview TEXT,
      url TEXT,
      last_run_id INTEGER,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      UNIQUE(project_name, value_fp, target)
    );
    CREATE INDEX IF NOT EXISTS idx_psp_proj_fp ON project_secret_peers(project_name, value_fp);
  `;

const BRAIN_CATEGORY_SEED_TITLES = [
  'XSS',
  'SQLi',
  'FTP (anónimo / sem auth)',
  'SSRF',
  'IDOR',
  'RCE',
  'LFI',
  'Open Redirect',
  'XXE',
  'Information Disclosure',
  'Outro',
];

function ensureRunsFindingsJsonColumn(d) {
  try {
    const cols = d.prepare(`PRAGMA table_info(runs)`).all();
    if (!cols.some((c) => c.name === 'findings_json')) {
      d.exec(`ALTER TABLE runs ADD COLUMN findings_json TEXT`);
    }
  } catch {
    /* ignore */
  }
}

function applySqliteSchema(d) {
  d.exec(SCHEMA_SQL);
  ensureRunsFindingsJsonColumn(d);
  ensureBrainCategoryDescriptionColumn(d);
  ensureBrainSeedCategories(d);
  ensureBrainLinksCompositePrimaryKey(d);
}

/**
 * Migração: schema antigo tinha PRIMARY KEY (target, fingerprint) — uma ligação por achado.
 * Novo: PRIMARY KEY (category_id, target, fingerprint) — o mesmo achado pode estar em várias categorias.
 */
function ensureBrainLinksCompositePrimaryKey(d) {
  try {
    const row = d.prepare(`SELECT sql FROM sqlite_master WHERE type='table' AND name='brain_links'`).get();
    const s = String(row?.sql || '');
    if (!s) return;
    if (s.includes('PRIMARY KEY (category_id, target, fingerprint)')) return;
    if (!s.includes('PRIMARY KEY (target, fingerprint)')) return;
    d.exec('PRAGMA foreign_keys = OFF');
    d.exec('BEGIN IMMEDIATE');
    d.exec(`
      CREATE TABLE brain_links__mc (
        category_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        linked_at TEXT NOT NULL,
        PRIMARY KEY (category_id, target, fingerprint),
        FOREIGN KEY (category_id) REFERENCES brain_categories(id) ON DELETE CASCADE
      );
    `);
    d.prepare(
      `INSERT OR IGNORE INTO brain_links__mc (category_id, target, fingerprint, linked_at)
       SELECT category_id, target, fingerprint, linked_at FROM brain_links`,
    ).run();
    d.exec('DROP TABLE brain_links');
    d.exec('ALTER TABLE brain_links__mc RENAME TO brain_links');
    d.exec('CREATE INDEX IF NOT EXISTS idx_brain_links_category ON brain_links(category_id)');
    d.exec('COMMIT');
    d.exec('PRAGMA foreign_keys = ON');
  } catch (e) {
    try {
      d.exec('ROLLBACK');
    } catch (_) {
      /* */
    }
    try {
      d.exec('PRAGMA foreign_keys = ON');
    } catch (_) {
      /* */
    }
    console.error('[GHOSTCTF brain_links PK migration]', e?.message || e);
  }
}

function ensureBrainCategoryDescriptionColumn(d) {
  try {
    const cols = d.prepare(`PRAGMA table_info(brain_categories)`).all();
    if (!cols.some((c) => c.name === 'description')) {
      d.exec(`ALTER TABLE brain_categories ADD COLUMN description TEXT NOT NULL DEFAULT ''`);
    }
  } catch {
    /* ignore */
  }
}

/** Título corresponde a uma categoria semente inicial (não apagável). */
export function isBrainSeedCategoryTitle(titleRaw) {
  const t = String(titleRaw || '').trim().toLowerCase();
  return BRAIN_CATEGORY_SEED_TITLES.some((s) => String(s).trim().toLowerCase() === t);
}

function ensureBrainSeedCategories(d) {
  try {
    const n = d.prepare('SELECT COUNT(*) AS c FROM brain_categories').get();
    if ((n?.c ?? 0) > 0) return;
    const now = new Date().toISOString();
    const ins = d.prepare('INSERT INTO brain_categories (title, created_at) VALUES (?, ?)');
    const tx = d.transaction((titles) => {
      for (const t of titles) ins.run(t, now);
    });
    tx(BRAIN_CATEGORY_SEED_TITLES);
  } catch (e) {
    console.error('[GHOSTCTF brain seed]', e?.message || e);
  }
}

let dbInstance = null;

/** Segmento seguro para pasta (projeto ou domínio). */
export function sanitizePathSegment(raw, fallback = 'unnamed') {
  let s = String(raw || '')
    .trim()
    .replace(/\.\./g, '')
    .replace(/[/\\]+/g, '_')
    .replace(/[^a-zA-Z0-9._-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 96);
  if (!s) s = fallback;
  return s;
}

/**
 * `escopo/{projeto}/{alvo}/` na raiz do repositório — alvo = domínio (escopo técnico).
 * @returns {string|null} caminho absoluto ou null se sem nome de projeto
 */
export function resolveLocalProjectDbDir(projectName, domain) {
  const p = String(projectName || '').trim();
  if (!p) return null;
  const safeProject = sanitizePathSegment(p);
  const safeScope = sanitizePathSegment(domain, 'scope');
  return path.join(SCOPE_DIR, safeProject, safeScope);
}

export function getDb() {
  if (dbInstance) return dbInstance;
  const dbPath = process.env.GHOSTCTF_DB ?? process.env.GHOSTRECON_DB ?? DEFAULT_DB;
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  dbInstance = new Database(dbPath);
  dbInstance.pragma('journal_mode = WAL');
  applySqliteSchema(dbInstance);
  return dbInstance;
}

export function mergeIntelForTargetDb(d, target, runId, findings) {
  try {
    const now = new Date().toISOString();
    let newArtifacts = 0;
    let alreadyKnown = 0;

    const sel = d.prepare('SELECT id FROM bounty_intel WHERE target = ? AND fp = ?');
    const ins = d.prepare(
      `INSERT INTO bounty_intel (target, fp, type, prio, score, value, meta, url, first_seen, last_seen, last_run_id)
       VALUES (@target, @fp, @type, @prio, @score, @value, @meta, @url, @first, @last, @run)`,
    );
    const upd = d.prepare(
      `UPDATE bounty_intel SET
         last_seen = @last,
         last_run_id = @run,
         score = CASE WHEN @score > score OR score IS NULL THEN @score ELSE score END,
         prio = CASE WHEN @score > COALESCE(score, 0) THEN @prio ELSE prio END,
         meta = COALESCE(NULLIF(@meta, ''), meta),
         url = COALESCE(NULLIF(@url, ''), url)
       WHERE target = @target AND fp = @fp`,
    );

    const tx = d.transaction((rows) => {
      for (const f of rows) {
        const fp = fingerprintFinding(target, f);
        if (sel.get(target, fp)) {
          upd.run({
            target,
            fp,
            last: now,
            run: runId,
            score: f.score ?? null,
            prio: f.prio ?? null,
            meta: f.meta ?? '',
            url: f.url ?? '',
          });
          alreadyKnown++;
        } else {
          ins.run({
            target,
            fp,
            type: f.type ?? null,
            prio: f.prio ?? null,
            score: f.score ?? null,
            value: f.value ?? '',
            meta: f.meta ?? null,
            url: f.url ?? null,
            first: now,
            last: now,
            run: runId,
          });
          newArtifacts++;
        }
      }
    });
    tx(findings);

    const row = d.prepare('SELECT COUNT(*) AS c FROM bounty_intel WHERE target = ?').get(target);
    const totalKnownForTarget = row?.c ?? 0;

    return { newArtifacts, alreadyKnown, totalKnownForTarget };
  } catch (e) {
    console.error('[GHOSTRECON DB intel]', e.message);
    return { newArtifacts: 0, alreadyKnown: 0, totalKnownForTarget: 0, error: e.message };
  }
}

export function mergeIntelForTarget(target, runId, findings) {
  return mergeIntelForTargetDb(getDb(), target, runId, findings);
}

export function mergeProjectSecretPeersDb(d, projectName, target, runId, findings) {
  const rows = buildSecretPeerRows(projectName, target, runId, findings);
  if (!rows.length) {
    return {
      inserted: 0,
      duplicates: listProjectSecretDuplicatesSqlite(d, sanitizePathSegment(String(projectName || '').trim())),
    };
  }
  const ins = d.prepare(`
    INSERT INTO project_secret_peers (
      project_name, value_fp, target, kind_hint, value_preview, url, last_run_id, first_seen, last_seen
    ) VALUES (
      @project_name, @value_fp, @target, @kind_hint, @value_preview, @url, @last_run_id, @ts, @ts
    )
    ON CONFLICT(project_name, value_fp, target) DO UPDATE SET
      last_seen = excluded.last_seen,
      last_run_id = excluded.last_run_id,
      kind_hint = COALESCE(excluded.kind_hint, project_secret_peers.kind_hint),
      value_preview = COALESCE(excluded.value_preview, project_secret_peers.value_preview),
      url = COALESCE(excluded.url, project_secret_peers.url)
  `);
  const tx = d.transaction((list) => {
    for (const r of list) ins.run(r);
  });
  tx(rows);
  return {
    inserted: rows.length,
    duplicates: listProjectSecretDuplicatesSqlite(d, sanitizePathSegment(String(projectName || '').trim())),
  };
}

export function listProjectSecretDuplicatesSqlite(d, projectNameSanitized) {
  const pn = String(projectNameSanitized || '').trim();
  if (!pn) return [];
  try {
    const rows = d
      .prepare(
        `SELECT value_fp, kind_hint,
          GROUP_CONCAT(DISTINCT target) AS targets_csv,
          COUNT(DISTINCT target) AS n_targets,
          MAX(value_preview) AS preview,
          MAX(url) AS sample_url
         FROM project_secret_peers
         WHERE project_name = ?
         GROUP BY value_fp
         HAVING COUNT(DISTINCT target) >= 2
         ORDER BY n_targets DESC, value_fp`,
      )
      .all(pn);
    return (rows || []).map((r) => ({
      value_fp: r.value_fp,
      kind_hint: r.kind_hint || '',
      targets: String(r.targets_csv || '')
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean),
      targetCount: Number(r.n_targets) || 0,
      preview: r.preview || '',
      sample_url: r.sample_url || null,
    }));
  } catch (e) {
    console.error('[GHOSTCTF project_secret_peers list]', e.message);
    return [];
  }
}

function saveRunWithDb(d, { target, exactMatch, modules, stats, findings, correlation, findingsJson = null }) {
  const now = new Date().toISOString();
  const insRun = d.prepare(
    `INSERT INTO runs (target, exact_match, modules_json, stats_json, correlation_json, findings_json, created_at)
     VALUES (@target, @exact, @modules, @stats, @corr, @findings_json, @created)`,
  );
  const insFinding = d.prepare(
    `INSERT INTO findings (run_id, type, prio, score, value, meta, url)
     VALUES (@run_id, @type, @prio, @score, @value, @meta, @url)`,
  );

  const runResult = insRun.run({
    target,
    exact: exactMatch ? 1 : 0,
    modules: JSON.stringify(modules),
    stats: JSON.stringify(stats),
    corr: correlation ? JSON.stringify(correlation) : null,
    findings_json: findingsJson,
    created: now,
  });
  const runId = Number(runResult.lastInsertRowid);

  const insertAll = d.transaction((rows) => {
    for (const f of rows) {
      insFinding.run({
        run_id: runId,
        type: f.type,
        prio: f.prio,
        score: f.score ?? null,
        value: f.value,
        meta: f.meta ?? null,
        url: f.url ?? null,
      });
    }
  });
  insertAll(findingsForRunsTable(target, findings));

  const intelMerge = mergeIntelForTargetDb(d, target, runId, findings);
  try {
    mergeKnowledgeCtf(d, findings);
  } catch (e) {
    console.error('[GHOSTCTF DB knowledge]', e?.message || e);
  }
  return { runId, intelMerge };
}

function mergeKnowledgeCtf(d, findings) {
  const now = new Date().toISOString();
  const sel = d.prepare('SELECT k, count FROM ctf_knowledge WHERE k = ?');
  const ins = d.prepare(
    `INSERT INTO ctf_knowledge (k, type, sample, count, first_seen, last_seen)
     VALUES (@k, @type, @sample, @count, @first, @last)`,
  );
  const upd = d.prepare(
    `UPDATE ctf_knowledge SET
       count = count + @inc,
       last_seen = @last,
       sample = COALESCE(NULLIF(@sample, ''), sample)
     WHERE k = @k`,
  );
  const seen = new Set();
  for (const f of findings || []) {
    if (!f) continue;
    if (f.type === 'domain' || f.type === 'subdomain') continue;
    const key = knowledgeKeyFromFinding(f);
    if (!key || seen.has(key)) continue;
    seen.add(key);
    const type = String(f.type || '').trim().toLowerCase();
    const sample = String(f.value || '').slice(0, 280);
    const cur = sel.get(key);
    if (cur) {
      upd.run({ k: key, inc: 1, last: now, sample });
    } else {
      ins.run({ k: key, type, sample, count: 1, first: now, last: now });
    }
  }
}

export function listKnowledge(limit = 80) {
  try {
    const d = getDb();
    const lim = Math.min(500, Math.max(1, Number(limit) || 80));
    return d
      .prepare(
        `SELECT k, type, sample, count, first_seen, last_seen
         FROM ctf_knowledge
         ORDER BY count DESC, last_seen DESC
         LIMIT ?`,
      )
      .all(lim);
  } catch (e) {
    console.error('[GHOSTCTF DB knowledge list]', e?.message || e);
    return [];
  }
}

/**
 * Grava run + intel num SQLite dedicado (espelho local ou único quando sem cloud).
 * @returns {{ runId: number, intelMerge: object, dbPath: string } | null}
 */
export function saveRunToProjectDir(projectRootDir, payload) {
  try {
    fs.mkdirSync(projectRootDir, { recursive: true });
    const dbPath = path.join(projectRootDir, 'ghostrecon.db');
    const d = new Database(dbPath);
    d.pragma('journal_mode = WAL');
    applySqliteSchema(d);
    try {
      const out = saveRunWithDb(d, payload);
      return { ...out, dbPath };
    } finally {
      d.close();
    }
  } catch (e) {
    console.error('[GHOSTRECON DB project dir]', e.message);
    return null;
  }
}

export function saveRun({ target, exactMatch, modules, stats, findings, correlation, findingsJson = null }) {
  try {
    const d = getDb();
    return saveRunWithDb(d, { target, exactMatch, modules, stats, findings, correlation, findingsJson });
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return null;
  }
}

export function listRuns(limit = 50) {
  try {
    const d = getDb();
    const rows = d
      .prepare(`SELECT id, target, created_at, stats_json FROM runs ORDER BY id DESC LIMIT ?`)
      .all(Math.min(200, Math.max(1, limit)));
    return rows.map((r) => ({
      id: r.id,
      target: r.target,
      created_at: r.created_at,
      stats: JSON.parse(r.stats_json),
    }));
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return [];
  }
}

export function getRunById(id) {
  try {
    const d = getDb();
    const run = d.prepare(`SELECT * FROM runs WHERE id = ?`).get(id);
    if (!run) return null;
    const tableFindings = d
      .prepare(`SELECT type, prio, score, value, meta, url FROM findings WHERE run_id = ? ORDER BY id`)
      .all(id);
    const snap = run.findings_json ? parseFindingsSnapshotJson(run.findings_json) : null;
    const findings = snap?.length ? snap : tableFindings;
    return {
      id: run.id,
      target: run.target,
      exact_match: Boolean(run.exact_match),
      modules: JSON.parse(run.modules_json),
      stats: JSON.parse(run.stats_json),
      correlation: run.correlation_json ? JSON.parse(run.correlation_json) : null,
      created_at: run.created_at,
      findings,
      findingsScopeRows: snap?.length ? tableFindings : undefined,
    };
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return null;
  }
}

export function listIntelForTarget(target, limit = 500) {
  try {
    const d = getDb();
    const t = String(target).trim().toLowerCase();
    return d
      .prepare(
        `SELECT type, prio, score, value, meta, url, first_seen, last_seen, last_run_id
         FROM bounty_intel WHERE target = ? ORDER BY last_seen DESC LIMIT ?`,
      )
      .all(t, Math.min(2000, Math.max(1, limit)));
  } catch (e) {
    console.error('[GHOSTRECON DB]', e.message);
    return [];
  }
}

export function intelCountForTarget(target) {
  try {
    const d = getDb();
    const t = String(target).trim().toLowerCase();
    const r = d.prepare('SELECT COUNT(*) AS c FROM bounty_intel WHERE target = ?').get(t);
    return r?.c ?? 0;
  } catch {
    return 0;
  }
}

function safeJsonParse(s) {
  try {
    return JSON.parse(String(s || 'null'));
  } catch {
    return null;
  }
}

/** Lista validações manuais persistidas para o alvo (fingerprints iguais aos do pipeline). */
export function listManualValidationsForTarget(targetRaw) {
  const d = getDb();
  const target = norm(targetRaw);
  const rows = d
    .prepare(
      `SELECT mv.fingerprint, mv.validated_at, mv.snapshot_json, mv.notes
       FROM manual_validations mv
       WHERE mv.target = ? ORDER BY datetime(mv.validated_at) DESC`,
    )
    .all(target);
  const linkStmt = d.prepare(
    `SELECT bl.category_id AS id, bc.title AS title
     FROM brain_links bl
     JOIN brain_categories bc ON bc.id = bl.category_id
     WHERE bl.target = ? AND bl.fingerprint = ?
     ORDER BY lower(trim(bc.title))`,
  );
  return rows.map((r) => {
    const links = linkStmt.all(target, r.fingerprint);
    const ids = links.map((x) => Number(x.id));
    const titles = links.map((x) => String(x.title || ''));
    return {
      fingerprint: r.fingerprint,
      validated_at: r.validated_at,
      notes: r.notes || '',
      snapshot: r.snapshot_json ? safeJsonParse(r.snapshot_json) : null,
      brainCategories: links.map((x) => ({ id: Number(x.id), title: String(x.title || '') })),
      brainCategoryIds: ids,
      brainCategoryTitles: titles,
      brainCategoryId: ids.length ? ids[0] : null,
      brainCategoryTitle: titles.length ? titles.join(' · ') : null,
    };
  });
}

/** Categorias do cérebro ligadas a um achado (target + fingerprint). */
export function listBrainLinksForFinding(targetRaw, fingerprintRaw) {
  const d = getDb();
  const target = norm(targetRaw);
  const fp = String(fingerprintRaw || '').trim().toLowerCase();
  if (!target || !/^[a-f0-9]{64}$/.test(fp)) return [];
  const rows = d
    .prepare(
      `SELECT bl.category_id AS id, bc.title AS title, bl.linked_at AS linked_at
       FROM brain_links bl
       JOIN brain_categories bc ON bc.id = bl.category_id
       WHERE bl.target = ? AND bl.fingerprint = ?
       ORDER BY lower(trim(bc.title))`,
    )
    .all(target, fp);
  return rows.map((r) => ({
    id: Number(r.id),
    title: r.title,
    linked_at: r.linked_at,
  }));
}

export function listBrainCategories() {
  const d = getDb();
  ensureBrainSeedCategories(d);
  const rows = d
    .prepare(
      `SELECT c.id, c.title, c.description, c.created_at,
        (SELECT COUNT(*) FROM brain_links bl WHERE bl.category_id = c.id) AS link_count
       FROM brain_categories c ORDER BY lower(trim(c.title))`,
    )
    .all();
  return rows.map((r) => ({
    id: Number(r.id),
    title: r.title,
    description: r.description || '',
    created_at: r.created_at,
    linkCount: Number(r.link_count) || 0,
    isSeed: isBrainSeedCategoryTitle(r.title),
  }));
}

export function getBrainCategoryById(idRaw) {
  const d = getDb();
  const cid = Number(idRaw);
  if (!Number.isFinite(cid) || cid < 1) return null;
  const r = d.prepare('SELECT id, title, description, created_at FROM brain_categories WHERE id = ?').get(cid);
  if (!r) return null;
  return { id: Number(r.id), title: r.title, description: r.description || '', created_at: r.created_at };
}

export function listBrainLinksForCategory(categoryIdRaw) {
  const d = getDb();
  const cid = Number(categoryIdRaw);
  if (!Number.isFinite(cid) || cid < 1) throw new Error('categoria inválida');
  const rows = d
    .prepare(
      `SELECT bl.target, bl.fingerprint, bl.linked_at, mv.notes, mv.snapshot_json
       FROM brain_links bl
       LEFT JOIN manual_validations mv ON mv.target = bl.target AND mv.fingerprint = bl.fingerprint
       WHERE bl.category_id = ?
       ORDER BY datetime(bl.linked_at) DESC`,
    )
    .all(cid);
  return rows.map((r) => ({
    target: r.target,
    fingerprint: r.fingerprint,
    linked_at: r.linked_at,
    notes: r.notes || '',
    snapshot: r.snapshot_json ? safeJsonParse(r.snapshot_json) : null,
  }));
}

export function createBrainCategory(titleRaw, descriptionRaw = '') {
  const d = getDb();
  const title = String(titleRaw || '')
    .trim()
    .slice(0, 120);
  const description = String(descriptionRaw || '')
    .trim()
    .slice(0, 2000);
  if (!title) throw new Error('título vazio');
  ensureBrainSeedCategories(d);
  const row = d
    .prepare('SELECT id, title, description FROM brain_categories WHERE lower(trim(title)) = lower(trim(?))')
    .get(title);
  if (row) return { id: Number(row.id), title: row.title, description: row.description || '', existing: true };
  const now = new Date().toISOString();
  const info = d
    .prepare('INSERT INTO brain_categories (title, description, created_at) VALUES (?, ?, ?)')
    .run(title, description, now);
  return { id: Number(info.lastInsertRowid), title, description, existing: false };
}

/**
 * Cria categoria ou actualiza a descrição se já existir o mesmo título (case-insensitive, trim).
 * Usado pelo sync de limpeza `falhas em ordem` no Cortex (`brain-sync-falhas-historico.js`).
 * @returns {{ id: number, title: string, updated: boolean }}
 */
export function upsertBrainCategoryByTitle(titleRaw, descriptionRaw = '') {
  const d = getDb();
  const title = String(titleRaw || '')
    .trim()
    .slice(0, 120);
  const description = String(descriptionRaw || '')
    .trim()
    .slice(0, 2000);
  if (!title) throw new Error('título vazio');
  ensureBrainSeedCategories(d);
  const row = d
    .prepare('SELECT id, title, description FROM brain_categories WHERE lower(trim(title)) = lower(trim(?))')
    .get(title);
  if (row) {
    const id = Number(row.id);
    const cur = String(row.description ?? '').trim();
    if (cur !== description) {
      d.prepare('UPDATE brain_categories SET description = ? WHERE id = ?').run(description, id);
      return { id, title: row.title, updated: true };
    }
    return { id, title: row.title, updated: false };
  }
  const now = new Date().toISOString();
  const info = d
    .prepare('INSERT INTO brain_categories (title, description, created_at) VALUES (?, ?, ?)')
    .run(title, description, now);
  return { id: Number(info.lastInsertRowid), title, updated: true };
}

/**
 * Remove uma categoria pelo título (case-insensitive, trim). `brain_links` apaga em cascata.
 * @returns {{ deleted: boolean, id?: number, title?: string }}
 */
export function deleteBrainCategoryByTitle(titleRaw) {
  const d = getDb();
  const title = String(titleRaw || '')
    .trim()
    .slice(0, 120);
  if (!title) return { deleted: false };
  if (isBrainSeedCategoryTitle(title)) return { deleted: false };
  const row = d
    .prepare('SELECT id, title FROM brain_categories WHERE lower(trim(title)) = lower(trim(?))')
    .get(title);
  if (!row) return { deleted: false };
  const id = Number(row.id);
  d.prepare('DELETE FROM brain_categories WHERE id = ?').run(id);
  return { deleted: true, id, title: row.title };
}

/**
 * Remove categoria por id. `brain_links` apaga em cascata.
 * @returns {{ deleted: boolean, id?: number, title?: string }}
 */
export function deleteBrainCategoryById(idRaw) {
  const d = getDb();
  const id = Number(idRaw);
  if (!Number.isFinite(id) || id < 1) return { deleted: false };
  const row = d.prepare('SELECT id, title FROM brain_categories WHERE id = ?').get(id);
  if (!row) return { deleted: false };
  if (isBrainSeedCategoryTitle(row.title)) {
    throw new Error('Não é permitido apagar categorias semente (XSS, SQLi, …).');
  }
  d.prepare('DELETE FROM brain_categories WHERE id = ?').run(id);
  return { deleted: true, id: Number(row.id), title: row.title };
}

export function updateBrainCategoryDescription(idRaw, descriptionRaw) {
  const d = getDb();
  const cid = Number(idRaw);
  if (!Number.isFinite(cid) || cid < 1) throw new Error('categoria inválida');
  const description = String(descriptionRaw || '')
    .trim()
    .slice(0, 2000);
  const info = d.prepare('UPDATE brain_categories SET description = ? WHERE id = ?').run(description, cid);
  if (!info.changes) throw new Error('categoria não encontrada');
  const row = d.prepare('SELECT id, title, description, created_at FROM brain_categories WHERE id = ?').get(cid);
  return {
    id: Number(row.id),
    title: row.title,
    description: row.description || '',
    created_at: row.created_at,
  };
}

export function upsertBrainLink({ target: targetRaw, fingerprint, categoryId }) {
  const d = getDb();
  const target = norm(targetRaw);
  const fp = String(fingerprint || '').trim().toLowerCase();
  const cid = Number(categoryId);
  if (!target || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(target)) throw new Error('alvo inválido');
  if (!/^[a-f0-9]{64}$/.test(fp)) throw new Error('fingerprint inválido');
  if (!Number.isFinite(cid) || cid < 1) throw new Error('categoria inválida');
  const cat = d.prepare('SELECT id FROM brain_categories WHERE id = ?').get(cid);
  if (!cat) throw new Error('categoria não encontrada');
  const mv = d.prepare('SELECT 1 FROM manual_validations WHERE target = ? AND fingerprint = ?').get(target, fp);
  if (!mv) throw new Error('valida o achado no Reporte antes de ligar ao cérebro');
  const now = new Date().toISOString();
  d.prepare(
    `INSERT INTO brain_links (category_id, target, fingerprint, linked_at)
     VALUES (@cid, @target, @fp, @now)
     ON CONFLICT(category_id, target, fingerprint) DO UPDATE SET
       linked_at = excluded.linked_at`,
  ).run({ cid, target, fp, now });
  return { ok: true, target, fingerprint: fp, categoryId: cid };
}

/** Remove a ligação a uma categoria (mantém outras categorias e a validação manual). */
export function deleteBrainLink({ target: targetRaw, fingerprint, categoryId }) {
  const d = getDb();
  const target = norm(targetRaw);
  const fp = String(fingerprint || '').trim().toLowerCase();
  const cid = Number(categoryId);
  if (!target || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(target)) throw new Error('alvo inválido');
  if (!/^[a-f0-9]{64}$/.test(fp)) throw new Error('fingerprint inválido');
  if (!Number.isFinite(cid) || cid < 1) throw new Error('categoria inválida');
  const r = d.prepare('DELETE FROM brain_links WHERE target = ? AND fingerprint = ? AND category_id = ?').run(
    target,
    fp,
    cid,
  );
  return { ok: true, changes: r.changes };
}

export function upsertManualValidation({ target: targetRaw, fingerprint, snapshot, notes }) {
  const d = getDb();
  const target = norm(targetRaw);
  const fp = String(fingerprint || '').trim().toLowerCase();
  if (!target || !/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(target)) throw new Error('alvo inválido');
  if (!/^[a-f0-9]{64}$/.test(fp)) throw new Error('fingerprint inválido');
  const now = new Date().toISOString();
  const snapJson =
    snapshot && typeof snapshot === 'object' ? JSON.stringify(snapshot).slice(0, 12000) : null;
  const n = notes != null ? String(notes).slice(0, 2000) : '';
  d.prepare(
    `INSERT INTO manual_validations (target, fingerprint, validated_at, snapshot_json, notes)
     VALUES (@target, @fp, @now, @snap, @notes)
     ON CONFLICT(target, fingerprint) DO UPDATE SET
       validated_at = excluded.validated_at,
       snapshot_json = COALESCE(excluded.snapshot_json, manual_validations.snapshot_json),
       notes = excluded.notes`,
  ).run({ target, fp, now, snap: snapJson, notes: n });
  return { ok: true };
}

export function deleteManualValidation(targetRaw, fingerprint) {
  const d = getDb();
  const target = norm(targetRaw);
  const fp = String(fingerprint || '').trim().toLowerCase();
  d.prepare('DELETE FROM brain_links WHERE target = ? AND fingerprint = ?').run(target, fp);
  const r = d.prepare('DELETE FROM manual_validations WHERE target = ? AND fingerprint = ?').run(target, fp);
  return { ok: true, changes: r.changes };
}
