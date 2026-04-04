/**
 * Deteta indícios de upload em HTML estático (curl): input type=file / multipart.
 * Não envia ficheiros — só findings + metadados para o operador.
 */

function safeToString(v) {
  return v == null ? '' : String(v);
}

/**
 * @param {string} html
 * @param {string} pageUrl
 * @returns {{ method: string, action: string, rawAction: string, note?: string }[]}
 */
export function extractUploadFormHints(html, pageUrl) {
  const body = safeToString(html);
  if (!body) return [];

  const hasFileInput = /type\s*=\s*["']file["']/i.test(body);
  const hasMultipart = /enctype\s*=\s*["']multipart\/form-data["']/i.test(body);
  if (!hasFileInput && !hasMultipart) return [];

  const base = safeToString(pageUrl).trim();
  const hints = [];
  const formOpenRe = /<form\b([^>]*)>/gi;
  let m;
  while ((m = formOpenRe.exec(body)) !== null) {
    const attrs = m[1];
    const start = m.index;
    const closeIdx = body.toLowerCase().indexOf('</form>', start);
    const chunk = closeIdx === -1 ? body.slice(start) : body.slice(start, closeIdx);
    const chunkHasFile = /type\s*=\s*["']file["']/i.test(chunk);
    const chunkMultipart = /enctype\s*=\s*["']multipart\/form-data["']/i.test(chunk);
    if (!chunkHasFile && !chunkMultipart) continue;

    const actionM = /action\s*=\s*["']([^"']*)["']/i.exec(attrs) || /action\s*=\s*([^\s>]+)/i.exec(attrs);
    const methodM = /method\s*=\s*["']([^"']*)["']/i.exec(attrs);
    const rawAction = actionM ? actionM[1].trim() : '';
    const method = (methodM ? methodM[1] : 'get').toUpperCase();

    let actionAbs = base;
    if (base) {
      try {
        actionAbs = new URL(rawAction || '', base).href;
      } catch {
        actionAbs = rawAction || base;
      }
    } else {
      actionAbs = rawAction || '';
    }

    hints.push({
      method,
      action: actionAbs,
      rawAction,
    });
  }

  if (!hints.length) {
    hints.push({
      method: 'GET',
      action: base,
      rawAction: '',
      note: 'type=file ou multipart no corpo; <form> não parseado (JS ou HTML incomum)',
    });
  }

  return hints;
}

/**
 * @param {Array<{ url?: string, finalUrl?: string, bodyText?: string }>} webResponses
 */
export function runUploadSurfaceProbe(webResponses) {
  const findings = [];
  const seen = new Set();
  let pages = 0;
  let hints = 0;

  for (const r of webResponses || []) {
    const pageUrl = safeToString(r.finalUrl || r.url).trim();
    const bt = safeToString(r.bodyText);
    if (!pageUrl || !bt) continue;

    const extracted = extractUploadFormHints(bt, pageUrl);
    if (!extracted.length) continue;

    pages += 1;
    for (const h of extracted) {
      hints += 1;
      const key = `${pageUrl}|${h.action}|${h.method}|${h.rawAction}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const metaParts = [
        `method=${h.method}`,
        h.rawAction ? `action=${h.action}` : h.action ? `action=${h.action}` : '',
        h.note || '',
        'Sugestão: Wandenreich (payloads/) ou Msfvenom manual; upload manual (browser ou curl -F).',
      ].filter(Boolean);

      findings.push({
        type: 'endpoint',
        prio: 'high',
        score: 82,
        value: 'Possível upload de ficheiro (formulário em HTML)',
        meta: metaParts.join(' · '),
        url: pageUrl,
      });
    }
  }

  return { findings, pages, hints };
}
