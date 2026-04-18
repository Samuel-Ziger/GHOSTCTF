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
