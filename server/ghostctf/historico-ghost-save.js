import path from 'path';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Raiz: …/GHOSTCTF/historicos/historicosGhost */
export const HISTORICO_GHOST_ROOT = path.resolve(__dirname, '..', '..', 'historicos', 'historicosGhost');

const MAX_FOLDER = 64;
const MAX_MD = 12 * 1024 * 1024;

/**
 * Nome seguro para pasta (sem path traversal, sem / \\).
 * @param {string} raw
 * @returns {string | null}
 */
export function sanitizeHistoricoFolderName(raw) {
  let s = String(raw || '')
    .trim()
    .toLowerCase()
    .replace(/[/\\]/g, '')
    .replace(/[^a-z0-9_-]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
    .slice(0, MAX_FOLDER);
  if (!s || s.includes('..')) return null;
  return s;
}

/**
 * @param {string} folderNameIn
 * @param {string} markdownBody
 */
export async function saveHistoricoGhostMarkdown(folderNameIn, markdownBody) {
  const folder = sanitizeHistoricoFolderName(folderNameIn);
  if (!folder) {
    return { ok: false, status: 400, error: 'Nome do histórico inválido (usa letras, números, - e _).' };
  }
  const md = String(markdownBody || '');
  if (md.length > MAX_MD) {
    return { ok: false, status: 400, error: 'Markdown excede o tamanho máximo permitido.' };
  }

  const baseResolved = path.resolve(HISTORICO_GHOST_ROOT);
  const dir = path.join(baseResolved, folder);
  const dirResolved = path.resolve(dir);
  if (!dirResolved.startsWith(baseResolved + path.sep) && dirResolved !== baseResolved) {
    return { ok: false, status: 400, error: 'Caminho da pasta inválido.' };
  }

  await mkdir(dirResolved, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fn = `recon_${stamp}.md`;
  const full = path.join(dirResolved, fn);
  await writeFile(full, md, 'utf8');

  const relativePath = path.join('historicos', 'historicosGhost', folder, fn).replace(/\\/g, '/');
  return { ok: true, relativePath, filename: fn };
}
