/**
 * Cliente para o GHOST v3 (FastAPI + Ollama) — cópia embebida em `third_party/ghost-local-v5/`.
 * URL: `GHOSTCTF_GHOST_LOCAL_URL` (preferido) ou legado `GHOSTRECON_GHOST_BASE_URL`.
 * @see third_party/ghost-local-v5/ghost-local/backend/main.py — POST /v1/chat/completions (stream:false)
 */

function trimBase(raw) {
  const s = String(raw || '').trim().replace(/\/+$/, '');
  return s || 'http://127.0.0.1:8000';
}

export function resolveGhostLocalBaseUrl() {
  const u = process.env.GHOSTCTF_GHOST_LOCAL_URL?.trim() || process.env.GHOSTRECON_GHOST_BASE_URL?.trim();
  return trimBase(u);
}

export function resolveGhostLocalModel() {
  return (
    process.env.GHOSTCTF_GHOST_LOCAL_MODEL?.trim() ||
    process.env.GHOST_OPENAI_DEFAULT_MODEL?.trim() ||
    'ghost'
  );
}

/**
 * Contexto em Markdown (equivalente ao que o Python injeta via `ghostrecon_context` no /chat/stream).
 */
export function buildGhostreconMarkdownFromCtfPayload(payload, targetDomain) {
  const p = payload && typeof payload === 'object' ? payload : {};
  const domain = String(targetDomain || p.target || p.ip || '').trim() || 'alvo';
  const lines = ['\n\n## Dados GHOSTCTF (export do pipeline):\n', `**Alvo**: ${domain}`, `**Origem**: GHOSTCTF`];
  const findings = Array.isArray(p.findings) ? p.findings : [];
  if (findings.length) {
    lines.push(`\n### Findings (${findings.length}):`);
    for (const f of findings.slice(0, 45)) {
      const sev = f.prio ?? f.score ?? f.type ?? '?';
      const u = f.url || (typeof f.value === 'string' ? f.value : '') || '';
      lines.push(`- [${sev}] **${f.type || '?'}** — ${String(u).slice(0, 220)}`);
      if (f.meta) lines.push(`  Notas: ${String(f.meta).slice(0, 200)}`);
    }
  }
  if (p.correlation && typeof p.correlation === 'object') {
    const blob = JSON.stringify(p.correlation);
    lines.push(`\n### Correlação (resumo)\n\`\`\`json\n${blob.slice(0, 3500)}${blob.length > 3500 ? '\n…' : ''}\n\`\`\``);
  }
  return lines.join('\n');
}

export async function probeGhostLocalHealth(baseUrl, timeoutMs = 4000) {
  const base = trimBase(baseUrl);
  try {
    const r = await fetch(`${base}/health`, { signal: AbortSignal.timeout(Math.max(800, timeoutMs)) });
    const j = await r.json().catch(() => ({}));
    return { ok: r.ok, base, body: j };
  } catch (e) {
    return { ok: false, base, error: e?.message || String(e) };
  }
}

/**
 * @param {{ baseUrl?: string; model?: string; systemText: string; userText: string; maxTokens?: number; timeoutMs?: number }} opts
 */
export async function callGhostLocalChatCompletion(opts = {}) {
  const baseUrl = trimBase(opts.baseUrl || resolveGhostLocalBaseUrl());
  const model = String(opts.model || resolveGhostLocalModel() || 'ghost').trim() || 'ghost';
  const url = `${baseUrl}/v1/chat/completions`;
  const timeoutMs = Math.max(5000, Math.min(600_000, Number(opts.timeoutMs) || 300_000));
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: String(opts.systemText || '') },
        { role: 'user', content: String(opts.userText || '') },
      ],
      stream: false,
      max_tokens: Math.min(32_768, Math.max(256, Number(opts.maxTokens) || 8192)),
      temperature: Number.isFinite(Number(opts.temperature)) ? Number(opts.temperature) : 0.25,
      top_p: 0.9,
    }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err =
      data?.error?.message ||
      (typeof data?.detail === 'string' ? data.detail : JSON.stringify(data?.detail || data)).slice(0, 500);
    throw new Error(`GHOST local ${res.status}: ${err || res.statusText}`);
  }
  const content = data?.choices?.[0]?.message?.content;
  if (typeof content !== 'string' || !content.trim()) {
    throw new Error('GHOST local: resposta sem content (Ollama offline ou modelo inválido?)');
  }
  return content;
}
