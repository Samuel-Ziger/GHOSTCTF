import { spawn } from 'node:child_process';

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Base da API web local do ngrok (não aceitar URL vinda do cliente). */
export function getNgrokApiBase() {
  return String(process.env.GHOSTCTF_NGROK_API || 'http://127.0.0.1:4040').replace(/\/$/, '');
}

/**
 * Lê /api/tunnels e devolve host:porta públicos do túnel TCP que encaminha para localPort.
 * @param {number} localPort — porta onde o nc escuta (ex.: 4444)
 */
export async function resolveNgrokTcpForLocalPort(localPort) {
  const base = getNgrokApiBase();
  const want = Number(localPort);
  if (!Number.isInteger(want) || want < 1 || want > 65535) {
    return { ok: false, error: 'localPort inválido (1–65535)' };
  }

  let res;
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 6000);
    res = await fetch(`${base}/api/tunnels`, { signal: ac.signal });
    clearTimeout(t);
  } catch (e) {
    return {
      ok: false,
      error: `API ngrok inacessível em ${base}. Corre \`ngrok tcp ${want}\` (ou inicia o agente) e tenta de novo.`,
    };
  }

  if (!res.ok) {
    return { ok: false, error: `ngrok API HTTP ${res.status}` };
  }

  const data = await res.json();
  const tunnels = Array.isArray(data.tunnels) ? data.tunnels : [];

  for (const t of tunnels) {
    if (String(t.proto || '').toLowerCase() !== 'tcp') continue;
    const pub = String(t.public_url || '');
    if (!pub.toLowerCase().startsWith('tcp://')) continue;

    const addr = String(t.config?.addr ?? t.config?.Addr ?? '');
    const m = addr.match(/:(\d+)\s*$/);
    const fwd = m ? Number(m[1]) : 0;
    if (fwd !== want) continue;

    const rest = pub.slice('tcp://'.length);
    const idx = rest.lastIndexOf(':');
    if (idx === -1) continue;
    const host = rest.slice(0, idx).trim();
    const port = Number(rest.slice(idx + 1));
    if (!host || !Number.isFinite(port) || port < 1 || port > 65535) continue;

    return {
      ok: true,
      ngrokHost: host,
      ngrokPort: port,
      publicUrl: pub,
      localPort: want,
      apiBase: base,
    };
  }

  return {
    ok: false,
    error: `Nenhum túnel TCP no ngrok a encaminhar para localhost:${want}. Dashboard: ${base}`,
  };
}

/**
 * Tenta `ngrok tcp <localPort>` em background e faz poll à API até aparecer o túnel.
 */
export async function startNgrokTcpAndResolve(localPort, { maxWaitMs = 14000, pollMs = 450 } = {}) {
  const want = Number(localPort);
  if (!Number.isInteger(want) || want < 1 || want > 65535) {
    return { ok: false, error: 'localPort inválido (1–65535)' };
  }

  const pre = await resolveNgrokTcpForLocalPort(want);
  if (pre.ok) return { ...pre, started: false };

  const child = spawn('ngrok', ['tcp', String(want)], {
    detached: true,
    stdio: 'ignore',
  });
  child.unref();

  let missingNgrok = false;
  child.once('error', (e) => {
    if (e && e.code === 'ENOENT') missingNgrok = true;
  });
  await sleep(250);
  if (missingNgrok) {
    return { ok: false, error: 'Comando `ngrok` não encontrado no PATH.' };
  }

  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    await sleep(pollMs);
    const r = await resolveNgrokTcpForLocalPort(want);
    if (r.ok) return { ...r, started: true };
  }

  return {
    ok: false,
    error:
      'Timeout: ngrok não expôs túnel TCP. Confirma `ngrok config add-authtoken …`, PATH, e que não há outro processo a bloquear a API (4040).',
  };
}
