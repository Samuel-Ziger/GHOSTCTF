/**
 * Notificação opcional pós-recon (Slack/Discord/custom) e relatório IA (Discord: embeds).
 */

function isDiscordWebhookUrl(url) {
  try {
    const u = new URL(String(url || '').trim());
    const h = u.hostname.toLowerCase();
    return (h === 'discord.com' || h === 'discordapp.com') && u.pathname.startsWith('/api/webhooks/');
  } catch {
    return false;
  }
}

async function readWebhookFailureBody(res) {
  try {
    const t = await res.text();
    if (!t) return '';
    return t.length > 400 ? `${t.slice(0, 400)}…` : t;
  } catch {
    return '';
  }
}

function logWebhookHttpError(res, detail) {
  console.warn(
    `[GHOSTRECON webhook] HTTP ${res.status} ${res.statusText || ''}${detail ? ` — ${detail}` : ''}`,
  );
}

/**
 * Resumo curto do recon — útil para Discord (JSON cru da API Discord não mostra mensagem).
 */
export async function postDiscordReconSummary(webhookUrl, payload) {
  const u = String(webhookUrl || '').trim();
  if (!u || !isDiscordWebhookUrl(u)) return;
  const { target, runId, stats, highCount, shannonSummary, pentestgptSummary } = payload;
  const lines = [
    '**GHOSTRECON** — recon gravado',
    `**Alvo:** \`${String(target || '').slice(0, 200)}\` · **run** #${runId}`,
  ];
  if (stats && typeof stats === 'object') {
    lines.push(
      `Alto: **${stats.high ?? 0}** · Subs: **${stats.subs ?? 0}** · Endpoints: **${stats.endpoints ?? 0}** · Params: **${stats.params ?? 0}** · Secrets: **${stats.secrets ?? 0}** · Dorks: **${stats.dorks ?? 0}**`,
    );
  }
  if (highCount != null) lines.push(`Achados **high**: **${highCount}**`);
  if (shannonSummary) {
    lines.push(`**Shannon:** ${String(shannonSummary).slice(0, 500)}${String(shannonSummary).length > 500 ? '…' : ''}`);
  }
  if (pentestgptSummary) {
    lines.push(
      `**PentestGPT:** ${String(pentestgptSummary).slice(0, 500)}${String(pentestgptSummary).length > 500 ? '…' : ''}`,
    );
  }
  let content = lines.join('\n');
  if (content.length > 1900) content = `${content.slice(0, 1890)}…`;

  try {
    const res = await fetch(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) logWebhookHttpError(res, await readWebhookFailureBody(res));
  } catch (e) {
    console.warn('[GHOSTRECON webhook]', e?.message || e);
  }
}

/**
 * Envia relatório + próximos passos (Markdown) — Discord: até 2 embeds; outros: JSON.
 */
export async function postAiReportWebhook(webhookUrl, payload) {
  const u = String(webhookUrl || '').trim();
  if (!u) return;

  const {
    target,
    runId,
    provider,
    relatorio,
    proximos_passos: proximos,
  } = payload;

  const rel = String(relatorio || '');
  const prox = String(proximos || '');
  const targetShort = String(target || '—').slice(0, 200);
  const runLine = runId != null ? `run #${runId}` : 'run (local)';

  try {
    if (isDiscordWebhookUrl(u)) {
      /* Discord: máx. ~6000 chars no total dos embeds por mensagem — uma mensagem por bloco. */
      const head = `**GHOSTRECON** · IA **${provider}** · \`${targetShort}\` · ${runLine}`;
      const postDiscord = async (body) => {
        const res = await fetch(u, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(20000),
        });
        if (!res.ok) logWebhookHttpError(res, await readWebhookFailureBody(res));
        return res.ok;
      };

      await postDiscord({
        content: head,
        embeds: [
          {
            title: `Relatório (${provider})`,
            description: rel.slice(0, 3900) || '_(vazio)_',
            color: 0x5865f2,
            footer: { text: `${targetShort} · ${runLine}`.slice(0, 2048) },
          },
        ],
      });
      if (prox) {
        await postDiscord({
          content: `**Próximos passos** · ${provider} · \`${targetShort}\``,
          embeds: [
            {
              title: 'Próximos passos',
              description: prox.slice(0, 3900),
              color: 0x3ba55d,
            },
          ],
        });
      }
      return;
    }

    const res = await fetch(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source: 'ghostrecon',
        kind: 'ai_report',
        provider,
        target: payload.target,
        runId: payload.runId ?? null,
        relatorio: rel,
        proximos_passos: prox,
      }),
      signal: AbortSignal.timeout(20000),
    });
    if (!res.ok) logWebhookHttpError(res, await readWebhookFailureBody(res));
  } catch (e) {
    console.warn('[GHOSTRECON webhook IA]', e?.message || e);
  }
}

/** Delta completo pós-IA: `GHOSTRECON_WEBHOOK_DELTA_FULL=0` desliga. */
export function webhookDeltaFullEnabled() {
  const v = String(process.env.GHOSTRECON_WEBHOOK_DELTA_FULL ?? '1').trim().toLowerCase();
  return !['0', 'false', 'no', 'off'].includes(v);
}

function deltaMaxFindings() {
  const n = Number(process.env.GHOSTRECON_WEBHOOK_DELTA_MAX_FINDINGS);
  if (Number.isFinite(n) && n > 0) return Math.min(50000, Math.floor(n));
  return 20000;
}

function formatFindingDeltaLine(f) {
  const t = String(f?.type || '?');
  const p = String(f?.prio || '—');
  const v = String(f?.value ?? '').replace(/\s+/g, ' ').trim().slice(0, 480);
  const url = f?.url ? String(f.url).replace(/\s+/g, ' ').trim().slice(0, 420) : '';
  const meta = f?.meta ? String(f.meta).replace(/\s+/g, ' ').trim().slice(0, 220) : '';
  let line = `• **${t}** · ${p} — ${v}`;
  if (url) line += `\n  ↳ \`${url}\``;
  if (meta) line += `\n  _${meta}_`;
  return line;
}

/** Parte texto em blocos ≤ maxLen (quebra linhas longas). */
function chunkTextBlocks(text, maxLen = 1850) {
  const raw = String(text || '');
  const lines = raw.split('\n');
  const blocks = [];
  let buf = '';
  const pushBuf = () => {
    if (buf) blocks.push(buf);
    buf = '';
  };
  for (const line of lines) {
    const pieces = line.length <= maxLen ? [line] : line.match(new RegExp(`.{1,${maxLen}}`, 'g')) || [line];
    for (const piece of pieces) {
      const add = buf ? `\n${piece}` : piece;
      if (buf.length + add.length > maxLen && buf) {
        pushBuf();
        buf = piece;
      } else {
        buf += add;
      }
    }
  }
  if (buf) blocks.push(buf);
  return blocks.length ? blocks : [''];
}

/**
 * Após relatório IA + próximos passos: envia **todos** os achados novos vs run anterior (`compareRuns` → `added`).
 * Discord: várias mensagens em sequência (limite de tamanho). JSON: um POST com array `added`.
 */
export async function postReconDeltaFullWebhook(webhookUrl, payload) {
  const u = String(webhookUrl || '').trim();
  if (!u || !webhookDeltaFullEnabled()) return;

  const {
    target,
    runId,
    baselineId,
    baselineCreatedAt,
    newerCreatedAt,
    added = [],
    removedCount = 0,
  } = payload;
  const maxF = deltaMaxFindings();
  const list = Array.isArray(added) ? added.slice(0, maxF) : [];
  const truncated = Array.isArray(added) && added.length > maxF;
  const targetShort = String(target || '—').slice(0, 200);

  try {
    if (isDiscordWebhookUrl(u)) {
      const head =
        `**GHOSTCTF — Novos vs recon anterior** · \`${targetShort}\` · run **#${runId}** · baseline **#${baselineId}**` +
        (newerCreatedAt ? ` · ${String(newerCreatedAt).slice(0, 24)}` : '');
      const sub =
        removedCount > 0
          ? `\n_Removidos vs anterior: **${removedCount}** (não listados)._`
          : '';
      const postOne = async (content) => {
        const res = await fetch(u, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: String(content).slice(0, 2000) }),
          signal: AbortSignal.timeout(25000),
        });
        if (!res.ok) logWebhookHttpError(res, await readWebhookFailureBody(res));
      };

      if (list.length === 0) {
        await postOne(`${head}\n**Novos:** nenhum (mesmos fingerprints que o run #${baselineId}).${sub}`);
        return;
      }

      const lines = list.map(formatFindingDeltaLine);
      const bodyText = lines.join('\n\n');
      const chunks = chunkTextBlocks(bodyText, 1750);
      const totalMsg = chunks.length + (truncated ? 1 : 0);
      await postOne(
        `${head}\n**Novos:** **${list.length}** achado(s)${truncated ? ` (truncado; máx. ${maxF})` : ''} · ${totalMsg} mensagem(ns)${sub}`,
      );
      for (let i = 0; i < chunks.length; i++) {
        await postOne(`**[${i + 1}/${chunks.length}]**\n${chunks[i]}`);
      }
      if (truncated) {
        await postOne(
          `**GHOSTCTF** · _(Lista truncada — defina GHOSTRECON_WEBHOOK_DELTA_MAX_FINDINGS ou veja a API /api/runs/${runId})_`,
        );
      }
      return;
    }

    const res = await fetch(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source: 'ghostctf',
        kind: 'recon_delta_full',
        target: payload.target,
        runId: runId ?? null,
        baselineId: baselineId ?? null,
        baselineCreatedAt: baselineCreatedAt ?? null,
        newerCreatedAt: newerCreatedAt ?? null,
        addedCount: list.length,
        addedTotalBeforeCap: Array.isArray(added) ? added.length : 0,
        removedCount,
        added: list,
      }),
      signal: AbortSignal.timeout(60000),
    });
    if (!res.ok) logWebhookHttpError(res, await readWebhookFailureBody(res));
  } catch (e) {
    console.warn('[GHOSTCTF webhook delta full]', e?.message || e);
  }
}

export async function postReconWebhook(webhookUrl, payload) {
  const u = String(webhookUrl || '').trim();
  if (!u) return;
  if (isDiscordWebhookUrl(u)) {
    await postDiscordReconSummary(u, {
      target: payload.target,
      runId: payload.runId,
      stats: payload.stats,
      highCount: payload.highCount,
      shannonSummary: payload.shannonSummary,
      pentestgptSummary: payload.pentestgptSummary,
    });
    return;
  }
  try {
    const res = await fetch(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source: 'ghostrecon',
        ...payload,
      }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) logWebhookHttpError(res, await readWebhookFailureBody(res));
  } catch (e) {
    console.warn('[GHOSTRECON webhook]', e?.message || e);
  }
}
