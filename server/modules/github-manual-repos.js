/**
 * Parse de URLs / `owner/repo` colados na UI (Shannon / bug bounty) para o formato usado em `cloneGithubReposForTarget`.
 */

const MAX_DEFAULT = 10;

/**
 * @param {unknown} raw — string multilinha, array de strings, ou vazio
 * @param {{ max?: number }} [opts]
 * @returns {{ full_name: string, clone_url: string, html_url: string }[]}
 */
export function parseGithubManualRepoList(raw, opts = {}) {
  const max = Math.min(Math.max(1, Number(opts.max) || MAX_DEFAULT), 20);
  const lines = [];
  if (Array.isArray(raw)) {
    for (const x of raw) {
      const t = String(x ?? '').trim();
      if (t) lines.push(t);
    }
  } else if (typeof raw === 'string') {
    for (const part of raw.split(/[\n\r,;]+/)) {
      const t = part.trim();
      if (t) lines.push(t);
    }
  } else if (raw != null && String(raw).trim() !== '') {
    lines.push(String(raw).trim());
  }

  const seen = new Set();
  const out = [];

  for (const line of lines) {
    if (out.length >= max) break;
    const row = parseOneGithubRepoLine(line);
    if (!row) continue;
    const key = row.full_name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}

/**
 * @param {string} line
 * @returns {{ full_name: string, clone_url: string, html_url: string } | null}
 */
export function parseOneGithubRepoLine(line) {
  const s = String(line || '').trim();
  if (!s) return null;

  let owner;
  let repo;

  const urlMatch = s.match(
    /^https?:\/\/(?:www\.)?github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+?)(?:\.git)?(?:\/|$|\?|#)/i,
  );
  if (urlMatch) {
    owner = urlMatch[1];
    repo = urlMatch[2];
  } else {
    const short = s.replace(/^@/, '').replace(/\.git$/i, '');
    const m = short.match(/^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/);
    if (!m) return null;
    owner = m[1];
    repo = m[2];
  }

  if (!owner || !repo || owner.length > 200 || repo.length > 200) return null;
  if (owner === 'settings' || owner === 'orgs' || owner === 'topics') return null;

  const full_name = `${owner}/${repo}`;
  return {
    full_name,
    clone_url: `https://github.com/${full_name}.git`,
    html_url: `https://github.com/${full_name}`,
  };
}
