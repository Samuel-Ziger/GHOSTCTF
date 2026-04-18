import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { deleteBrainCategoryById, deleteBrainCategoryByTitle, listBrainCategories } from '../modules/db-sqlite.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
/** Ficheiro de referência local; o sync já não cria categorias a partir dele (só limpeza). */
export const FALHAS_HISTORICO_REL = path.join('historicos', 'CTFsSolyd', 'falhas em ordem');
export const FALHAS_HISTORICO_ABS = path.join(REPO_ROOT, 'historicos', 'CTFsSolyd', 'falhas em ordem');

/** Linhas só com separadores (o ficheiro «falhas em ordem» usa ─── entre secções — não são títulos). */
export function isFalhasHistoricoDecorativeLine(l) {
  const s = String(l || '').trim();
  if (!s) return true;
  if (/^[·•]{1,3}\s*$/.test(s)) return true;
  // Log / UI: «· ─────────» (marcador + traços / box-drawing)
  const core = s.replace(/^[·•\u00B7\u2022\u2023\u2219]\s*/u, '');
  if (core.length >= 8 && /^[\s·•\u00B7\u2022\-—–═\u2500-\u257F]+$/u.test(core)) return true;
  if (/^[\s·•\u00B7\u2022\-—–═\u2500-\u257F]{8,}$/u.test(s)) return true;
  return false;
}

/** Remove categorias cujo título é só decoração (ex. linha de log «· ───» gravada por engano). */
export function purgeGarbageBrainCategoriesFromDb() {
  const victims = listBrainCategories().filter((c) => isFalhasHistoricoDecorativeLine(c.title));
  const removed = [];
  for (const { id } of victims) {
    const del = deleteBrainCategoryById(id);
    if (del.deleted) removed.push({ title: del.title, id: del.id });
  }
  return { removed, count: removed.length };
}

function firstNonDecorativeIndex(lines) {
  let i = 0;
  while (i < lines.length && isFalhasHistoricoDecorativeLine(lines[i])) i += 1;
  return i;
}

/**
 * Formato do ficheiro: blocos separados por uma ou mais linhas em branco.
 * O primeiro bloco pode começar por «Mais comuns → menos comuns» (índice), depois linhas `───` de
 * separação, e só então o título real (ex.: «1. Divulgação…») — não confundir com categoria.
 * Demais blocos: primeira linha útil = título, resto = descrição (separadores decorativos omitidos).
 * @param {string} raw
 * @returns {{ title: string, description: string }[]}
 */
function mergeMaisComunsOrphanBlocks(blocks) {
  const merged = [];
  for (let i = 0; i < blocks.length; i += 1) {
    const b = blocks[i];
    const lines = b.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
    const onlyHeader =
      lines.length === 1 && /^Mais comuns\s*→/i.test(lines[0]);
    if (onlyHeader && i + 1 < blocks.length) {
      merged.push(`${b}\n\n${blocks[i + 1]}`);
      i += 1;
    } else {
      merged.push(b);
    }
  }
  return merged;
}

/**
 * Secções do ficheiro (título + descrição) — usado para testes e para remover categorias antigas
 * geradas pelo sync por-bloco (não voltar a criar como categorias separadas).
 */
export function parseFalhasHistoricoSections(raw) {
  const text = String(raw || '').replace(/\r\n/g, '\n').trim();
  if (!text) return [];

  const blocks = mergeMaisComunsOrphanBlocks(
    text.split(/\n\s*\n+/).map((b) => b.trim()).filter(Boolean),
  );
  const out = [];

  for (const block of blocks) {
    const lines = block.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
    if (!lines.length) continue;

    let title;
    let description;

    if (/^Mais comuns\s*→/i.test(lines[0]) && lines.length >= 2) {
      const ti = firstNonDecorativeIndex(lines.slice(1));
      const realIdx = ti + 1;
      if (realIdx >= lines.length) continue;
      title = String(lines[realIdx]).slice(0, 120);
      const bodyLines = [lines[0], ...lines.slice(realIdx + 1)].filter((l) => !isFalhasHistoricoDecorativeLine(l));
      description = bodyLines.join('\n\n').slice(0, 2000);
    } else if (lines.length >= 2) {
      const ti = firstNonDecorativeIndex(lines);
      if (ti >= lines.length) continue;
      title = String(lines[ti]).slice(0, 120);
      description = lines
        .slice(ti + 1)
        .filter((l) => !isFalhasHistoricoDecorativeLine(l))
        .join('\n\n')
        .slice(0, 2000);
    } else {
      const ti = firstNonDecorativeIndex(lines);
      if (ti >= lines.length) continue;
      title = String(lines[ti]).slice(0, 120);
      description = '';
    }

    if (!title || isFalhasHistoricoDecorativeLine(title)) continue;
    out.push({ title, description });
  }

  return out;
}

/** Título da categoria-biblioteca antiga (removida pelo sync; não voltar a criar). */
export const HISTORICO_FALHAS_BRAIN_CATEGORY_TITLE = 'Biblioteca: falhas em ordem (histórico)';

function pushRemoved(removed, del) {
  if (del.deleted) removed.push({ title: del.title, id: del.id });
}

/**
 * Remove do cérebro a biblioteca/ secções antigas derivadas de `falhas em ordem` e títulos só decorativos.
 * Não cria categorias a partir do ficheiro (o texto fica só no repositório).
 * @returns {{ ok: boolean, count?: number, error?: string, results?: [], removed?: { title: string, id?: number }[] }}
 */
export function runSyncFalhasHistoricoToBrain() {
  const removed = [];

  pushRemoved(removed, deleteBrainCategoryByTitle(HISTORICO_FALHAS_BRAIN_CATEGORY_TITLE));

  if (!fs.existsSync(FALHAS_HISTORICO_ABS)) {
    const junk = purgeGarbageBrainCategoriesFromDb();
    for (const j of junk.removed) removed.push(j);
    return { ok: false, error: `Ficheiro não encontrado: ${FALHAS_HISTORICO_REL}`, count: 0, removed, results: [] };
  }
  let raw;
  try {
    raw = fs.readFileSync(FALHAS_HISTORICO_ABS, 'utf8');
  } catch (e) {
    const junk = purgeGarbageBrainCategoriesFromDb();
    for (const j of junk.removed) removed.push(j);
    return { ok: false, error: e?.message || String(e), count: 0, removed, results: [] };
  }

  const sectionTitles = parseFalhasHistoricoSections(raw);
  for (const { title } of sectionTitles) {
    if (!title) continue;
    pushRemoved(removed, deleteBrainCategoryByTitle(title));
  }

  const firstLine = String(raw || '')
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.length > 0);
  if (firstLine && /^Mais comuns\s*→/i.test(firstLine)) {
    pushRemoved(removed, deleteBrainCategoryByTitle(firstLine));
  }

  const junk = purgeGarbageBrainCategoriesFromDb();
  for (const j of junk.removed) removed.push(j);

  return { ok: true, count: removed.length, results: [], removed };
}

/** @deprecated Use `parseFalhasHistoricoSections`; mantido para compatibilidade. */
export const parseFalhasHistoricoFile = parseFalhasHistoricoSections;
