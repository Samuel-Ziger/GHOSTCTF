import net from 'node:net';

const JDWP_HANDSHAKE = 'JDWP-Handshake';

export function jdwpPortsFromNmap(nmapRows) {
  const ports = new Set();
  for (const r of nmapRows || []) {
    if (String(r?.proto || '').toLowerCase() !== 'tcp') continue;
    const p = Number(r?.port);
    if (!Number.isFinite(p)) continue;
    const blob = `${r?.name || ''} ${r?.product || ''} ${r?.version || ''} ${r?.extrainfo || ''}`.toLowerCase();
    if (p === 5005 || /\bjdwp\b|\bjava debug wire protocol\b/.test(blob)) ports.add(p);
  }
  return [...ports].sort((a, b) => a - b);
}

function probeJdwpHandshake({ host, port, timeoutMs = 7000 } = {}) {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port });
    let done = false;
    let data = Buffer.alloc(0);

    const finish = (out) => {
      if (done) return;
      done = true;
      try {
        sock.destroy();
      } catch {
        // ignore
      }
      resolve(out);
    };

    const t = setTimeout(() => finish({ ok: false, error: 'timeout' }), Math.max(2500, timeoutMs));

    sock.once('connect', () => {
      try {
        sock.write(JDWP_HANDSHAKE, 'ascii');
      } catch (e) {
        clearTimeout(t);
        finish({ ok: false, error: e?.message || String(e) });
      }
    });

    sock.on('data', (chunk) => {
      data = Buffer.concat([data, chunk]);
      if (data.length >= JDWP_HANDSHAKE.length) {
        const got = data.slice(0, JDWP_HANDSHAKE.length).toString('ascii');
        if (got === JDWP_HANDSHAKE) {
          clearTimeout(t);
          return finish({ ok: true });
        }
        clearTimeout(t);
        return finish({ ok: false, error: `resposta inesperada: ${got}` });
      }
      return undefined;
    });

    sock.once('error', (e) => {
      clearTimeout(t);
      finish({ ok: false, error: e?.message || String(e) });
    });

    sock.once('close', () => {
      if (done) return;
      clearTimeout(t);
      finish({ ok: false, error: 'socket closed' });
    });
  });
}

export async function runJdwpProbe({ ip, nmapRows, log, timeoutMs = 7000 } = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const ports = jdwpPortsFromNmap(nmapRows);
  const hits = [];
  const errors = [];

  if (!ip || !ports.length) return { tried: 0, ports, hits, errors };

  for (const port of ports.slice(0, 4)) {
    try {
      logger(`[jdwp] handshake em ${ip}:${port}`, 'info');
      const r = await probeJdwpHandshake({ host: ip, port, timeoutMs });
      if (r.ok) {
        hits.push({
          port,
          evidence: 'JDWP handshake aceite (JDWP-Handshake echo).',
          intel:
            `JDWP exposto em ${ip}:${port} — risco de execução remota/debug attach. ` +
            'Mitigar com bind local, ACL/rede interna e desativar debug em produção.',
        });
        logger(`[jdwp] exposto em ${ip}:${port}`, 'success');
      } else {
        errors.push(`${port}:${r.error || 'sem handshake'}`);
        logger(`[jdwp] sem confirmação em ${ip}:${port} (${r.error || 'sem handshake'})`, 'info');
      }
    } catch (e) {
      const msg = e?.message || String(e);
      errors.push(`${port}:${msg}`);
      logger(`[jdwp] erro ${ip}:${port} (${msg})`, 'warn');
    }
  }

  return { tried: Math.min(ports.length, 4), ports, hits, errors };
}
