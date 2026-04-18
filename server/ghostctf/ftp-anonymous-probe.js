import net from 'node:net';
import { detectFlagsWithDecoding } from './flag-detector.js';

/**
 * Portas FTP prováveis a partir do XML do nmap (21 ou serviço com nome "ftp").
 */
export function ftpPortsFromNmap(nmapRows) {
  const ports = new Set();
  for (const r of nmapRows || []) {
    if (String(r.proto || 'tcp').toLowerCase() !== 'tcp') continue;
    const p = Number(r.port);
    if (!Number.isFinite(p)) continue;
    const blob = `${r.name || ''} ${r.product || ''} ${r.extrainfo || ''}`.toLowerCase();
    if (p === 21 || /\bftp\b/.test(blob)) ports.add(p);
  }
  return [...ports].sort((a, b) => a - b);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Consome uma mensagem FTP completa do buffer (inclui continuações 220- ... 220 ).
 * @returns {{ code: number, lastLine: string, consumed: number } | null}
 */
function tryConsumeFtpMessage(buf) {
  if (!buf || !buf.length) return null;
  const firstCrlf = buf.indexOf('\r\n');
  if (firstCrlf < 0) return null;
  const line0 = buf.slice(0, firstCrlf);
  const m = line0.match(/^(\d{3})([- ])/) ;
  if (!m) return null;
  const code = m[1];
  const sep = m[2];
  if (sep === ' ') {
    return { code: Number(code), lastLine: line0, consumed: firstCrlf + 2 };
  }
  let pos = firstCrlf + 2;
  while (pos <= buf.length) {
    const next = buf.indexOf('\r\n', pos);
    if (next < 0) return null;
    const line = buf.slice(pos, next);
    pos = next + 2;
    if (line.startsWith(`${code} `)) {
      return { code: Number(code), lastLine: line, consumed: pos };
    }
  }
  return null;
}

async function nextFtpMessage(bufRef, sock, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const parsed = tryConsumeFtpMessage(bufRef.buf);
    if (parsed) {
      bufRef.buf = bufRef.buf.slice(parsed.consumed);
      return parsed;
    }
    if (sock.destroyed) throw new Error('socket closed');
    await delay(20);
  }
  throw new Error('resposta FTP timeout');
}

function sendCmd(sock, line) {
  sock.write(`${line}\r\n`, 'latin1');
}

function parsePasvEndpoint(line) {
  const m = String(line || '').match(/\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/);
  if (!m) return null;
  const host = `${m[1]}.${m[2]}.${m[3]}.${m[4]}`;
  const p1 = Number(m[5]);
  const p2 = Number(m[6]);
  if (!Number.isFinite(p1) || !Number.isFinite(p2)) return null;
  return { host, port: p1 * 256 + p2 };
}

async function fetchFtpListPasv({ host, ctrlSock, ctrlBufRef, timeoutMs, maxLines = 10 } = {}) {
  sendCmd(ctrlSock, 'PASV');
  const pasv = await nextFtpMessage(ctrlBufRef, ctrlSock, timeoutMs);
  if (pasv.code !== 227) return { ok: false, reason: `PASV ${pasv.code}` };
  const ep = parsePasvEndpoint(pasv.lastLine);
  if (!ep) return { ok: false, reason: 'PASV sem endpoint' };

  const dataHost = ep.host === '0.0.0.0' ? host : ep.host;
  const dataSock = net.createConnection({ host: dataHost, port: ep.port });
  let dataBuf = '';
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      try {
        dataSock.destroy();
      } catch {
        /* */
      }
      reject(new Error('data connect timeout'));
    }, Math.min(timeoutMs, 10000));
    dataSock.once('connect', () => {
      clearTimeout(t);
      resolve();
    });
    dataSock.once('error', (e) => {
      clearTimeout(t);
      reject(e);
    });
  });

  dataSock.on('data', (chunk) => {
    dataBuf += chunk.toString('latin1');
  });

  sendCmd(ctrlSock, 'LIST -la');
  const pre = await nextFtpMessage(ctrlBufRef, ctrlSock, timeoutMs);
  if (![125, 150].includes(pre.code)) {
    try {
      dataSock.destroy();
    } catch {
      /* */
    }
    return { ok: false, reason: `LIST ${pre.code}` };
  }

  await new Promise((resolve) => {
    const t = setTimeout(() => {
      try {
        dataSock.destroy();
      } catch {
        /* */
      }
      resolve();
    }, Math.min(timeoutMs, 10000));
    dataSock.once('close', () => {
      clearTimeout(t);
      resolve();
    });
    dataSock.once('error', () => {
      clearTimeout(t);
      resolve();
    });
  });

  const post = await nextFtpMessage(ctrlBufRef, ctrlSock, timeoutMs);
  if (![226, 250].includes(post.code)) return { ok: false, reason: `LIST fim ${post.code}` };

  const ml = Math.max(1, Math.min(80, Number(maxLines) || 10));
  const lines = dataBuf
    .split(/\r?\n/)
    .map((x) => String(x || '').trim())
    .filter(Boolean)
    .slice(0, ml);

  const maxRaw = 48_000;
  const raw =
    dataBuf.length > maxRaw ? dataBuf.slice(0, maxRaw) : dataBuf;

  return { ok: true, lines, raw };
}

/**
 * Descarrega um ficheiro via PASV + RETR (modo texto).
 * @returns {Promise<{ ok: boolean, body?: string, bytes?: number, reason?: string, ftpLine?: string }>}
 */
async function fetchFtpRetrPasv({
  host,
  ctrlSock,
  ctrlBufRef,
  remotePath,
  timeoutMs,
  maxBytes = 98_304,
} = {}) {
  const path = String(remotePath || '').trim();
  if (!path) return { ok: false, reason: 'path vazio' };

  sendCmd(ctrlSock, 'PASV');
  const pasv = await nextFtpMessage(ctrlBufRef, ctrlSock, timeoutMs);
  if (pasv.code !== 227) return { ok: false, reason: `PASV ${pasv.code}` };
  const ep = parsePasvEndpoint(pasv.lastLine);
  if (!ep) return { ok: false, reason: 'PASV sem endpoint' };

  const dataHost = ep.host === '0.0.0.0' ? host : ep.host;
  const dataSock = net.createConnection({ host: dataHost, port: ep.port });

  try {
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('data connect timeout')), Math.min(timeoutMs, 12_000));
      dataSock.once('connect', () => {
        clearTimeout(t);
        resolve();
      });
      dataSock.once('error', (e) => {
        clearTimeout(t);
        reject(e);
      });
    });
  } catch (e) {
    try {
      dataSock.destroy();
    } catch {
      /* */
    }
    return { ok: false, reason: e?.message || String(e) };
  }

  const chunks = [];
  let total = 0;
  dataSock.on('data', (chunk) => {
    if (total >= maxBytes) return;
    const take = Math.min(chunk.length, maxBytes - total);
    chunks.push(chunk.subarray(0, take));
    total += take;
  });

  sendCmd(ctrlSock, `RETR ${path}`);
  let pre;
  try {
    pre = await nextFtpMessage(ctrlBufRef, ctrlSock, timeoutMs);
  } catch (e) {
    try {
      dataSock.destroy();
    } catch {
      /* */
    }
    return { ok: false, reason: e?.message || String(e) };
  }

  if (![125, 150].includes(pre.code)) {
    try {
      dataSock.destroy();
    } catch {
      /* */
    }
    return { ok: false, reason: `RETR ${pre.code}`, ftpLine: pre.lastLine };
  }

  await new Promise((resolve) => {
    const t = setTimeout(() => {
      try {
        dataSock.destroy();
      } catch {
        /* */
      }
      resolve();
    }, Math.min(timeoutMs, 18_000));
    dataSock.once('close', () => {
      clearTimeout(t);
      resolve();
    });
    dataSock.once('end', () => {
      clearTimeout(t);
      resolve();
    });
    dataSock.once('error', () => {
      clearTimeout(t);
      resolve();
    });
  });

  let post;
  try {
    post = await nextFtpMessage(ctrlBufRef, ctrlSock, timeoutMs);
  } catch (e) {
    const buf = Buffer.concat(chunks);
    return {
      ok: false,
      reason: `RETR fim: ${e?.message || String(e)}`,
      partialBytes: buf.length,
    };
  }

  const buf = Buffer.concat(chunks);
  let body = '';
  try {
    body = buf.toString('utf8');
  } catch {
    body = buf.toString('latin1');
  }

  const ok = post.code === 226 || post.code === 250;
  return { ok, body, bytes: buf.length, postCode: post.code, ftpLine: post.lastLine };
}

function collectGrepFlagHintsFromHaystack(haystack, max = 20) {
  const hay = String(haystack || '');
  if (!hay) return [];
  const out = [];
  const seen = new Set();
  const re = /\.flag\.txt|flag\.txt|solyd/gi;
  let m;
  while ((m = re.exec(hay)) !== null && out.length < max) {
    const term = m[0];
    const i = m.index;
    const snippet = hay
      .slice(Math.max(0, i - 28), Math.min(hay.length, i + term.length + 96))
      .replace(/\s+/g, ' ')
      .trim();
    const key = `${term.toLowerCase()}|${snippet.slice(0, 100)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ term, snippet, where: 'grep' });
  }
  return out;
}

function collectRetrCandidatePaths(listLines) {
  const set = new Set(['flag.txt', '.flag.txt']);
  for (const line of listLines || []) {
    const s = String(line);
    for (const tok of s.split(/\s+/)) {
      const t = tok.replace(/^\.\//, '').trim();
      if (!t) continue;
      if (/^\.?flag\.txt$/i.test(t)) set.add(t);
      if (t.toLowerCase().endsWith('flag.txt') && t.length < 200) set.add(t);
    }
  }
  return [...set].slice(0, 14);
}

/**
 * Após login anonymous: grep estilo em LIST/RAW por `flag.txt`, `.flag.txt`, `Solyd`;
 * tenta RETR em candidatos e corre `detectFlagsWithDecoding` no corpo.
 */
async function harvestAnonymousFtpFlags({
  host,
  ctrlSock,
  ctrlBufRef,
  timeoutMs,
  listLines = [],
  listRaw = '',
  platformId = 'solyd',
} = {}) {
  const rawList = String(listRaw || '');
  const joinedLines = (listLines || []).join('\n');
  const haystack = [rawList, joinedLines].filter(Boolean).join('\n---\n');

  const grepMatches = collectGrepFlagHintsFromHaystack(haystack, 22);

  const detectorFlags = [];
  const seenFlag = new Set();
  const pushDetector = (hits, ftpPath) => {
    for (const h of hits || []) {
      if (!h?.flag || seenFlag.has(h.flag)) continue;
      seenFlag.add(h.flag);
      detectorFlags.push({
        flag: h.flag,
        evidence: h.evidence || 'ftp-anon',
        decodedFrom: h.decodedFrom || '',
        ftpPath: ftpPath || '',
      });
    }
  };

  try {
    const listHits = detectFlagsWithDecoding({ rawText: haystack, platformId });
    pushDetector(listHits, 'LIST');
  } catch {
    /* */
  }

  const retrTried = [];
  const tmo = Math.min(Number(timeoutMs) || 12000, 16_000);
  const paths = collectRetrCandidatePaths(listLines);
  for (const p of paths) {
    if (retrTried.length >= 10) break;
    retrTried.push(p);
    try {
      const r = await fetchFtpRetrPasv({
        host,
        ctrlSock,
        ctrlBufRef,
        remotePath: p,
        timeoutMs: tmo,
        maxBytes: 98_304,
      });
      if (!r.ok || !r.body) continue;
      for (const gm of collectGrepFlagHintsFromHaystack(r.body, 12)) {
        grepMatches.push({ ...gm, where: `RETR:${p}` });
      }
      try {
        const dh = detectFlagsWithDecoding({ rawText: r.body, platformId });
        pushDetector(dh, p);
      } catch {
        /* */
      }
    } catch {
      /* */
    }
  }

  const uniqGrep = [];
  const gseen = new Set();
  for (const g of grepMatches) {
    const k = `${g.term}|${g.snippet}|${g.where || ''}`;
    if (gseen.has(k)) continue;
    gseen.add(k);
    uniqGrep.push(g);
    if (uniqGrep.length > 28) break;
  }

  return { grepMatches: uniqGrep, detectorFlags, retrTried };
}

/**
 * Tenta USER anonymous + PASS anonymous@ (RFC 1630 estilo).
 * Com `anonymousOk`, inclui `flagHarvest` (grep em LIST por `flag.txt`, `.flag.txt`, `Solyd` + RETR + detecção de flags).
 * @returns {Promise<{ anonymousOk: boolean, code?: number, lastLine?: string, stages: string[], error?: string, listPreview?: string[], flagHarvest?: object }>}
 */
export async function probeFtpAnonymous({ host, port = 21, timeoutMs = 12000, platformId = 'solyd' } = {}) {
  const stages = [];
  const bufRef = { buf: '' };

  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port });

    const finish = (out) => {
      try {
        if (!sock.destroyed) {
          try {
            sendCmd(sock, 'QUIT');
          } catch {
            /* */
          }
        }
        sock.destroy();
      } catch {
        /* */
      }
      resolve(out);
    };

    let finished = false;
    const done = (out) => {
      if (finished) return;
      finished = true;
      finish(out);
    };

    const connTimer = setTimeout(() => {
      try {
        sock.destroy();
      } catch {
        /* */
      }
      done({ anonymousOk: false, stages, error: 'connect timeout', summary: 'timeout' });
    }, Math.min(timeoutMs, 15000));

    sock.once('connect', async () => {
      clearTimeout(connTimer);
      try {
        sock.on('data', (chunk) => {
          bufRef.buf += chunk.toString('latin1');
        });

        const banner = await nextFtpMessage(bufRef, sock, timeoutMs);
        stages.push(`banner ${banner.code}`);
        if (banner.code !== 220) {
          return done({
            anonymousOk: false,
            stages,
            code: banner.code,
            summary: `banner inesperado (${banner.code})`,
          });
        }

        sendCmd(sock, 'USER anonymous');
        const userRep = await nextFtpMessage(bufRef, sock, timeoutMs);
        stages.push(`USER ${userRep.code}`);
        if (userRep.code === 230) {
          let listPreview = [];
          let listRaw = '';
          try {
            const list = await fetchFtpListPasv({
              host,
              ctrlSock: sock,
              ctrlBufRef: bufRef,
              timeoutMs: Math.min(timeoutMs, 10_000),
              maxLines: 48,
            });
            if (list.ok && Array.isArray(list.lines)) {
              listPreview = list.lines;
              listRaw = String(list.raw || '');
              stages.push(`LIST ok (${list.lines.length})`);
            } else if (list.reason) {
              stages.push(`LIST skip (${list.reason})`);
            }
          } catch (e) {
            stages.push(`LIST erro (${e?.message || String(e)})`);
          }
          let flagHarvest = { grepMatches: [], detectorFlags: [], retrTried: [] };
          try {
            flagHarvest = await harvestAnonymousFtpFlags({
              host,
              ctrlSock: sock,
              ctrlBufRef: bufRef,
              timeoutMs: Math.min(timeoutMs, 16_000),
              listLines: listPreview,
              listRaw,
              platformId,
            });
            stages.push(
              `flag-harvest retr=${(flagHarvest.retrTried || []).length} grep=${(flagHarvest.grepMatches || []).length} flags=${(flagHarvest.detectorFlags || []).length}`,
            );
          } catch (e) {
            stages.push(`flag-harvest erro (${e?.message || String(e)})`);
          }
          return done({
            anonymousOk: true,
            stages,
            code: 230,
            lastLine: userRep.lastLine,
            summary: '230 sem PASS',
            listPreview,
            flagHarvest,
          });
        }
        if (userRep.code !== 331 && userRep.code !== 332) {
          return done({
            anonymousOk: false,
            stages,
            code: userRep.code,
            summary: `USER recusado (${userRep.code})`,
          });
        }

        sendCmd(sock, 'PASS anonymous@');
        const passRep = await nextFtpMessage(bufRef, sock, timeoutMs);
        stages.push(`PASS ${passRep.code}`);
        if (passRep.code === 230) {
          let listPreview = [];
          let listRaw = '';
          try {
            const list = await fetchFtpListPasv({
              host,
              ctrlSock: sock,
              ctrlBufRef: bufRef,
              timeoutMs: Math.min(timeoutMs, 10_000),
              maxLines: 48,
            });
            if (list.ok && Array.isArray(list.lines)) {
              listPreview = list.lines;
              listRaw = String(list.raw || '');
              stages.push(`LIST ok (${list.lines.length})`);
            } else if (list.reason) {
              stages.push(`LIST skip (${list.reason})`);
            }
          } catch (e) {
            stages.push(`LIST erro (${e?.message || String(e)})`);
          }
          let flagHarvest = { grepMatches: [], detectorFlags: [], retrTried: [] };
          try {
            flagHarvest = await harvestAnonymousFtpFlags({
              host,
              ctrlSock: sock,
              ctrlBufRef: bufRef,
              timeoutMs: Math.min(timeoutMs, 16_000),
              listLines: listPreview,
              listRaw,
              platformId,
            });
            stages.push(
              `flag-harvest retr=${(flagHarvest.retrTried || []).length} grep=${(flagHarvest.grepMatches || []).length} flags=${(flagHarvest.detectorFlags || []).length}`,
            );
          } catch (e) {
            stages.push(`flag-harvest erro (${e?.message || String(e)})`);
          }
          return done({
            anonymousOk: true,
            stages,
            code: 230,
            lastLine: passRep.lastLine,
            summary: '230 Login successful',
            listPreview,
            flagHarvest,
          });
        }
        return done({
          anonymousOk: false,
          stages,
          code: passRep.code,
          lastLine: passRep.lastLine,
          summary: `anonymous negado (${passRep.code})`,
        });
      } catch (e) {
        done({
          anonymousOk: false,
          stages,
          error: e?.message || String(e),
          summary: e?.message || 'erro',
        });
      }
    });

    sock.once('error', (e) => {
      clearTimeout(connTimer);
      done({ anonymousOk: false, stages, error: e?.message || String(e), summary: 'erro de rede' });
    });
  });
}

export async function probeFtpCredentials({
  host,
  port = 21,
  username,
  password,
  timeoutMs = 12000,
} = {}) {
  const user = String(username || '').trim();
  const pass = String(password || '');
  if (!user) return { ok: false, summary: 'username vazio' };
  const stages = [];
  const bufRef = { buf: '' };

  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port });
    let doneFlag = false;
    const done = (out) => {
      if (doneFlag) return;
      doneFlag = true;
      try {
        if (!sock.destroyed) {
          try {
            sendCmd(sock, 'QUIT');
          } catch {
            /* */
          }
          sock.destroy();
        }
      } catch {
        /* */
      }
      resolve(out);
    };

    const timer = setTimeout(() => {
      try {
        sock.destroy();
      } catch {
        /* */
      }
      done({ ok: false, summary: 'timeout', stages });
    }, Math.min(timeoutMs, 15000));

    sock.once('connect', async () => {
      clearTimeout(timer);
      try {
        sock.on('data', (chunk) => {
          bufRef.buf += chunk.toString('latin1');
        });
        const banner = await nextFtpMessage(bufRef, sock, timeoutMs);
        stages.push(`banner ${banner.code}`);
        if (banner.code !== 220) return done({ ok: false, summary: `banner ${banner.code}`, stages });
        sendCmd(sock, `USER ${user}`);
        const userRep = await nextFtpMessage(bufRef, sock, timeoutMs);
        stages.push(`USER ${userRep.code}`);
        if (userRep.code === 230) return done({ ok: true, summary: '230 sem PASS', stages });
        if (userRep.code !== 331 && userRep.code !== 332) return done({ ok: false, summary: `USER ${userRep.code}`, stages });
        sendCmd(sock, `PASS ${pass}`);
        const passRep = await nextFtpMessage(bufRef, sock, timeoutMs);
        stages.push(`PASS ${passRep.code}`);
        if (passRep.code === 230) return done({ ok: true, summary: '230 Login successful', stages });
        return done({ ok: false, summary: `PASS ${passRep.code}`, stages });
      } catch (e) {
        done({ ok: false, summary: e?.message || String(e), stages });
      }
    });

    sock.once('error', (e) => {
      clearTimeout(timer);
      done({ ok: false, summary: e?.message || String(e), stages });
    });
  });
}
