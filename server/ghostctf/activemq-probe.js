import net from 'node:net';
import { spawn } from 'node:child_process';

function runCurl(url, timeoutMs) {
  const sec = String(Math.max(2, Math.floor(timeoutMs / 1000)));
  const args = ['-k', '-sS', '-i', '--max-time', sec, '--connect-timeout', sec, url];
  return new Promise((resolve, reject) => {
    const child = spawn('curl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    child.stdout.on('data', (d) => out.push(d));
    child.on('error', reject);
    child.on('close', () => {
      resolve(Buffer.concat(out).toString('utf8').slice(0, 12000));
    });
  });
}

function activeMqPortsFromNmap(nmapRows) {
  const ports = new Set();
  for (const r of nmapRows || []) {
    if (String(r?.proto || '').toLowerCase() !== 'tcp') continue;
    const p = Number(r?.port);
    if (!Number.isFinite(p)) continue;
    const blob = `${r?.name || ''} ${r?.product || ''} ${r?.version || ''} ${r?.extrainfo || ''}`.toLowerCase();
    if (
      [8161, 61616, 61613, 61614, 5672, 1883].includes(p) ||
      /\bactivemq\b|\bartemis\b|\bopenwire\b|\bstomp\b|\bamqp\b|\bmqtt\b/.test(blob)
    ) {
      ports.add(p);
    }
  }
  return [...ports].sort((a, b) => a - b);
}

function tcpProbe({ host, port, payload = '', timeoutMs = 7000 } = {}) {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port });
    let done = false;
    const chunks = [];

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

    const t = setTimeout(() => finish({ ok: false, error: 'timeout', data: '' }), Math.max(2000, timeoutMs));

    sock.once('connect', () => {
      try {
        if (payload) sock.write(payload, 'utf8');
      } catch (e) {
        clearTimeout(t);
        finish({ ok: false, error: e?.message || String(e), data: '' });
      }
    });
    sock.on('data', (d) => {
      chunks.push(d);
      const size = chunks.reduce((n, x) => n + x.length, 0);
      if (size >= 2048) {
        clearTimeout(t);
        finish({ ok: true, data: Buffer.concat(chunks).toString('utf8') });
      }
    });
    sock.once('error', (e) => {
      clearTimeout(t);
      finish({ ok: false, error: e?.message || String(e), data: Buffer.concat(chunks).toString('utf8') });
    });
    sock.once('close', () => {
      if (done) return;
      clearTimeout(t);
      finish({ ok: true, data: Buffer.concat(chunks).toString('utf8') });
    });
  });
}

/**
 * Deteta ActiveMQ em HTTP (:8161) e transportes típicos (61616/61613/5672/1883).
 */
export async function runActiveMqProbe({ ip, nmapRows, log, timeoutMs = 8000 } = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const hits = [];

  if (ip) {
    const url = `http://${ip}:8161/`;
    try {
      logger(`[activemq] GET ${url}`, 'info');
      const raw = await runCurl(url, timeoutMs);
      const low = raw.toLowerCase();
      if (
        low.includes('activemq') ||
        low.includes('apache activemq') ||
        low.includes('artemis') ||
        (low.includes('active') && low.includes('mq') && low.includes('welcome'))
      ) {
        hits.push({
          url,
          evidence: 'HTTP 8161 com indícios ActiveMQ/Artemis',
          intel: `Túnel SSH típico: ssh -L 8162:127.0.0.1:8161 user@${ip} depois abrir http://127.0.0.1:8162/ — CVE-2023-46604 (OpenWire) e outras; validar versão no banner.`,
        });
        logger(`[activemq] possível painel @ ${url}`, 'success');
      }
    } catch (e) {
      logger(`[activemq] ${e?.message || String(e)}`, 'warn');
    }
  }

  const ports = activeMqPortsFromNmap(nmapRows);
  for (const p of ports.slice(0, 8)) {
    if (p === 8161) continue;
    try {
      let probe;
      if (p === 61613) {
        const stompConnect = 'CONNECT\naccept-version:1.2\nhost:localhost\n\n\0';
        probe = await tcpProbe({ host: ip, port: p, payload: stompConnect, timeoutMs });
        const low = String(probe.data || '').toLowerCase();
        if (probe.ok && (low.includes('connected') || low.includes('stomp') || low.includes('activemq'))) {
          hits.push({
            url: null,
            evidence: `STOMP em ${ip}:${p} respondeu a CONNECT (${String(probe.data || '').slice(0, 180).replace(/\s+/g, ' ')})`,
            intel: `STOMP exposto em ${ip}:${p}. Validar autenticação e ACLs de tópicos/queues no broker ActiveMQ.`,
          });
          continue;
        }
      } else if (p === 5672) {
        probe = await tcpProbe({ host: ip, port: p, payload: 'AMQP\x00\x00\x09\x01', timeoutMs });
        const low = String(probe.data || '').toLowerCase();
        if (probe.ok && (low.includes('amqp') || low.includes('handshake'))) {
          hits.push({
            url: null,
            evidence: `AMQP em ${ip}:${p} com resposta de handshake.`,
            intel: `AMQP exposto em ${ip}:${p}. Rever autenticação, vhosts e acesso por rede.`,
          });
          continue;
        }
      } else {
        probe = await tcpProbe({ host: ip, port: p, payload: '', timeoutMs });
      }

      if (probe?.ok) {
        hits.push({
          url: null,
          evidence: `Transporte ActiveMQ/mensageria acessível em ${ip}:${p}${probe.data ? ` (${String(probe.data).slice(0, 120).replace(/\s+/g, ' ')})` : ''}`,
          intel: `Serviço de broker exposto em ${ip}:${p}. Confirmar necessidade de exposição pública e enforcement de autenticação.`,
        });
      }
    } catch (e) {
      logger(`[activemq] tcp ${ip}:${p} -> ${e?.message || String(e)}`, 'warn');
    }
  }

  return { hits };
}
