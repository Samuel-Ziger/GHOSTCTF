import net from 'node:net';
import { spawn } from 'node:child_process';

function whichCmd(cmd) {
  return new Promise((resolve) => {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const p = spawn(finder, [cmd], { stdio: ['ignore', 'pipe', 'pipe'] });
    p.on('error', () => resolve(false));
    p.on('close', (c) => resolve(c === 0));
  });
}

/** Portas TCP abertas no nmap que parecem mail ou estão nas portas clássicas. */
export function mailRelatedPortsFromNmap(nmapRows) {
  const out = [];
  const seen = new Set();
  for (const r of nmapRows || []) {
    if (String(r.proto || '').toLowerCase() !== 'tcp') continue;
    const p = Number(r.port);
    if (!Number.isFinite(p)) continue;
    const blob = `${r.name || ''} ${r.product || ''}`.toLowerCase();
    const classic = [25, 110, 143, 465, 587, 993, 995].includes(p);
    const named = /\b(pop3|imap|smtp|dovecot|mail)\b/.test(blob);
    if (!classic && !named) continue;
    if (seen.has(p)) continue;
    seen.add(p);
    out.push({ port: p, name: r.name || '', product: r.product || '' });
  }
  return out.sort((a, b) => a.port - b.port);
}

function tcpReadWrite({ host, port, scheduleWrites = [], timeoutMs = 8000 }) {
  return new Promise((resolve) => {
    let buf = '';
    const sock = net.createConnection({ host, port });
    let done = false;
    const timers = [];

    const finish = (out) => {
      if (done) return;
      done = true;
      for (const t of timers) clearTimeout(t);
      try {
        sock.destroy();
      } catch {
        /* */
      }
      resolve(out);
    };

    const hardStop = setTimeout(() => finish({ ok: true, transcript: buf.slice(0, 32000) }), timeoutMs);
    timers.push(hardStop);

    sock.setEncoding('utf8');
    sock.on('data', (d) => {
      buf += d;
      if (buf.length > 32000) finish({ ok: true, transcript: buf.slice(0, 32000) });
    });
    sock.on('error', (e) => finish({ ok: false, error: e.message, transcript: buf }));

    sock.on('connect', () => {
      for (const { delayMs, line } of scheduleWrites) {
        const t = setTimeout(() => {
          try {
            const l = String(line);
            sock.write(l.endsWith('\r\n') ? l : `${l}\r\n`);
          } catch {
            /* */
          }
        }, delayMs);
        timers.push(t);
      }
    });
  });
}

/**
 * POP3: greeting + CAPA + QUIT
 * IMAP: banner + CAPABILITY + LOGOUT
 * SMTP: EHLO (porta 25/587)
 */
export async function probeMailPort({ host, port, timeoutMs = 9000 }) {
  const p = Number(port);
  if (p === 110 || p === 995) {
    const r = await tcpReadWrite({
      host,
      port: p,
      scheduleWrites: [
        { delayMs: 400, line: 'CAPA' },
        { delayMs: 2200, line: 'QUIT' },
      ],
      timeoutMs,
    });
    return { kind: 'pop3', port: p, ...r };
  }
  if (p === 143 || p === 993) {
    const r = await tcpReadWrite({
      host,
      port: p,
      scheduleWrites: [
        { delayMs: 400, line: 'a001 CAPABILITY' },
        { delayMs: 2200, line: 'a002 LOGOUT' },
      ],
      timeoutMs,
    });
    return { kind: 'imap', port: p, ...r };
  }
  if (p === 25 || p === 587 || p === 465) {
    const r = await tcpReadWrite({
      host,
      port: p,
      scheduleWrites: [{ delayMs: 400, line: 'EHLO ghostctf.local' }],
      timeoutMs,
    });
    return { kind: 'smtp', port: p, ...r };
  }
  const r = await tcpReadWrite({ host, port: p, scheduleWrites: [], timeoutMs });
  return { kind: 'tcp', port: p, ...r };
}

/**
 * POP3S (995) / IMAPS (993) — TLS via openssl s_client + comandos em claro dentro do túnel.
 */
export async function probeMailTlsOpenSsl({ host, port, kind, timeoutMs = 12000 } = {}) {
  const opensslOk = await whichCmd('openssl');
  if (!opensslOk) {
    return { ok: false, error: 'openssl não está no PATH', kind: `tls-${kind}`, port, transcript: '' };
  }
  const p = Number(port);
  const h = String(host || '').replace(/[^a-zA-Z0-9.:[\]-]/g, '') || '127.0.0.1';
  const inner =
    kind === 'pop3'
      ? "sleep 0.5; printf 'CAPA\\r\\n'; sleep 0.7; printf 'QUIT\\r\\n'; sleep 0.4"
      : "sleep 0.5; printf 'a001 CAPABILITY\\r\\n'; sleep 0.7; printf 'a002 LOGOUT\\r\\n'; sleep 0.4";
  const bash = `{ ${inner} | openssl s_client -connect ${h}:${p} -crlf -quiet -servername ${h} 2>/dev/null; }`;

  return await new Promise((resolve) => {
    let out = '';
    const child = spawn('bash', ['-c', bash], { stdio: ['ignore', 'pipe', 'pipe'] });
    const t = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        /* */
      }
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      out += d.toString('utf8');
      if (out.length > 32000) out = out.slice(0, 32000);
    });
    child.stderr.on('data', () => {});
    child.on('error', (e) => {
      clearTimeout(t);
      resolve({ ok: false, error: e.message, kind: `tls-${kind}`, port: p, transcript: out });
    });
    child.on('close', () => {
      clearTimeout(t);
      resolve({
        ok: true,
        kind: `tls-${kind}`,
        port: p,
        transcript: out,
      });
    });
  });
}

export function smbLikelyFromNmap(nmapRows) {
  for (const r of nmapRows || []) {
    if (String(r.proto || '').toLowerCase() !== 'tcp') continue;
    const p = Number(r.port);
    const blob = `${r.name || ''} ${r.product || ''} ${r.extrainfo || ''}`.toLowerCase();
    if (p === 445 || p === 139) return true;
    if (/\b(smb|microsoft-ds|netbios-ssn)\b/.test(blob)) return true;
  }
  return false;
}

export async function runSmbclientList({ ip, timeoutMs = 20000 }) {
  const ok = await whichCmd('smbclient');
  if (!ok) return { ok: false, error: 'smbclient não está no PATH', stdout: '', stderr: '' };

  return await new Promise((resolve) => {
    const child = spawn('smbclient', ['-L', `//${ip}`, '-N'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const t = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {
        /* */
      }
    }, timeoutMs);
    child.stdout.on('data', (d) => {
      stdout += d.toString('utf8');
      if (stdout.length > 120000) stdout = stdout.slice(0, 120000);
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString('utf8');
    });
    child.on('error', (e) => {
      clearTimeout(t);
      resolve({ ok: false, error: e.message, stdout, stderr });
    });
    child.on('close', (code) => {
      clearTimeout(t);
      const interesting =
        /Sharename|Disk|IPC\$|print\$|ADMIN\$/i.test(stdout) ||
        (stdout.length > 80 && !/Connection refused/i.test(stderr));
      resolve({
        ok: true,
        code,
        stdout: stdout.slice(0, 8000),
        stderr: stderr.slice(0, 2000),
        interesting,
      });
    });
  });
}

/**
 * Cobre lacunas tipo CTF4 (POP3/IMAP/SMB): banners/transcrições seguras + listagem SMB se smbclient existir.
 */
export async function runExtendedServiceProbe({ ip, nmapRows, log, mailTimeoutMs = 9000, smbTimeoutMs = 20000 } = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const mailPorts = mailRelatedPortsFromNmap(nmapRows);
  const mailResults = [];

  if (!mailPorts.length) {
    logger('Extended services: nenhuma porta mail/SMTP relevante no nmap — skip mail.', 'info');
  } else {
    logger(`Extended services: mail — a sondar ${mailPorts.length} porta(s) em ${ip}...`, 'info');
    for (const mp of mailPorts.slice(0, 8)) {
      try {
        let r;
        if (mp.port === 993) {
          logger(`[mail:${mp.port}] IMAPS — openssl s_client...`, 'info');
          r = await probeMailTlsOpenSsl({ host: ip, port: 993, kind: 'imap', timeoutMs: mailTimeoutMs + 2000 });
        } else if (mp.port === 995) {
          logger(`[mail:${mp.port}] POP3S — openssl s_client...`, 'info');
          r = await probeMailTlsOpenSsl({ host: ip, port: 995, kind: 'pop3', timeoutMs: mailTimeoutMs + 2000 });
        } else {
          r = await probeMailPort({ host: ip, port: mp.port, timeoutMs: mailTimeoutMs });
        }
        mailResults.push(r);
        const snippet = String(r.transcript || '')
          .replace(/\r/g, '')
          .split('\n')
          .slice(0, 8)
          .join(' | ');
        logger(`[mail:${mp.port}] ${r.kind} · ${snippet.slice(0, 220)}`, r.ok !== false ? 'info' : 'warn');
      } catch (e) {
        mailResults.push({ port: mp.port, ok: false, error: e?.message || String(e) });
        logger(`[mail:${mp.port}] erro: ${e?.message || String(e)}`, 'warn');
      }
    }
  }

  let smb = { attempted: false, ok: false };
  if (smbLikelyFromNmap(nmapRows)) {
    smb.attempted = true;
    logger(`Extended services: SMB — smbclient -L //${ip} -N ...`, 'info');
    smb = { attempted: true, ...(await runSmbclientList({ ip, timeoutMs: smbTimeoutMs })) };
    if (!smb.ok && smb.error) logger(`SMB: ${smb.error}`, 'warn');
    else if (smb.stdout) logger(`SMB list (trecho): ${String(smb.stdout).slice(0, 400).replace(/\s+/g, ' ')}`, 'info');
  } else {
    logger('Extended services: SMB não indicado no nmap — skip smbclient.', 'info');
  }

  return { mailResults, smb };
}
