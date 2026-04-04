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

/**
 * Deteta consola web ActiveMQ (8161) ou indícios em corpo HTTP.
 */
export async function runActiveMqProbe({ ip, log, timeoutMs = 8000 } = {}) {
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

  return { hits };
}
