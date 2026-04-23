/**
 * Após login FTP anónimo bem-sucedido, testa se o servidor aceita STOR (upload).
 * Usa modo passivo (PASV / EPSV) e corrige IP privado na resposta PASV (usa host do controlo).
 */
import net from 'net';
import { randomBytes } from 'crypto';

function ftpWriteProbeEnabled() {
  const v = String(process.env.GHOSTRECON_FTP_WRITE_PROBE ?? '1').trim().toLowerCase();
  return !['0', 'false', 'no', 'off'].includes(v);
}

function isPrivateIPv4(h) {
  const p = String(h || '')
    .split('.')
    .map((x) => Number(x));
  if (p.length !== 4 || p.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return false;
  const [a, b] = p;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  return false;
}

function parsePasv227(text, controlHost) {
  const m = String(text).match(/\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/);
  if (!m) return null;
  let host = `${m[1]}.${m[2]}.${m[3]}.${m[4]}`;
  const port = Number(m[5]) * 256 + Number(m[6]);
  if (isPrivateIPv4(host)) host = controlHost;
  return { host, port };
}

function parseEpsv229(text, controlHost) {
  const m = String(text).match(/\(\|\|\|(\d+)\|\)/);
  if (!m) return null;
  return { host: controlHost, port: Number(m[1]) };
}

function collectUntilFinalLine(sock, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buf = '';
    const t = setTimeout(() => {
      cleanup();
      reject(new Error(`FTP read timeout ${timeoutMs}ms`));
    }, timeoutMs);
    function cleanup() {
      clearTimeout(t);
      sock.removeListener('data', onData);
      sock.removeListener('error', onErr);
      sock.removeListener('close', onClose);
    }
    function onErr(e) {
      cleanup();
      reject(e);
    }
    function onClose() {
      cleanup();
      reject(new Error('FTP connection closed'));
    }
    function onData(chunk) {
      buf += chunk.toString('utf8');
      const lines = buf.split(/\r?\n/);
      buf = lines.pop() || '';
      for (const line of lines) {
        const fm = line.match(/^(\d{3})\s(.*)$/);
        if (fm) {
          cleanup();
          resolve({ code: Number(fm[1]), line: line.trim(), text: fm[2] });
          return;
        }
      }
    }
    sock.on('data', onData);
    sock.on('error', onErr);
    sock.on('close', onClose);
  });
}

function writeCmd(sock, cmd) {
  sock.write(`${cmd}\r\n`);
}

/**
 * @returns {Promise<{ writable: boolean, probeFile?: string, detail?: string, error?: string }>}
 */
export async function probeFtpAnonymousWritable({ host, port = 21, timeoutMs = 15000 }) {
  if (!ftpWriteProbeEnabled()) {
    return { writable: false, detail: 'probe_disabled' };
  }
  const t = Math.max(8000, Number(timeoutMs) || 15000);
  const probeFile = `.ghr_w_${Date.now()}_${randomBytes(4).toString('hex')}.txt`;
  const payload = Buffer.from('GHOSTRECON write probe — safe to delete\n', 'utf8');

  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port: Number(port) || 21 });
    sock.setEncoding('utf8');

    const finish = (out) => {
      try {
        sock.destroy();
      } catch {
        /* ignore */
      }
      resolve(out);
    };

    let phase = 'banner';
    let dataSock = null;

    const fail = (error, detail) => finish({ writable: false, error, detail });

    sock.setTimeout(t + 5000, () => fail('timeout', phase));

    sock.once('error', (e) => fail(e?.message || 'socket_error', phase));

    sock.once('connect', () => {
      void (async () => {
        let pasvEndpoint = null;
        try {
        let r = await collectUntilFinalLine(sock, t);
        if (r.code !== 220) {
          fail(`banner_${r.code}`, r.line);
          return;
        }
        writeCmd(sock, 'USER anonymous');
        r = await collectUntilFinalLine(sock, t);
        if (r.code === 530) {
          fail('user_denied', r.line);
          return;
        }
        if (r.code !== 331 && r.code !== 230) {
          fail(`user_${r.code}`, r.line);
          return;
        }
        if (r.code === 331) {
          writeCmd(sock, 'PASS anonymous@ghostrecon.local');
          r = await collectUntilFinalLine(sock, t);
        }
        if (r.code !== 230) {
          fail(`pass_${r.code}`, r.line);
          return;
        }

        writeCmd(sock, 'TYPE I');
        r = await collectUntilFinalLine(sock, t);
        if (r.code !== 200 && r.code !== 250) {
          fail(`type_${r.code}`, r.line);
          return;
        }

        writeCmd(sock, 'PASV');
        r = await collectUntilFinalLine(sock, t);
        if (r.code === 227) {
          pasvEndpoint = parsePasv227(r.line, host);
        }
        if (!pasvEndpoint && r.code === 229) {
          pasvEndpoint = parseEpsv229(`${r.text} ${r.line}`, host);
        }
        if (!pasvEndpoint) {
          writeCmd(sock, 'EPSV');
          r = await collectUntilFinalLine(sock, t);
          if (r.code === 229) pasvEndpoint = parseEpsv229(`${r.text} ${r.line}`, host);
        }
        if (!pasvEndpoint) {
          fail('pasv_parse', r.line);
          return;
        }

        dataSock = net.createConnection({ host: pasvEndpoint.host, port: pasvEndpoint.port });
        await new Promise((res, rej) => {
          dataSock.once('connect', res);
          dataSock.once('error', rej);
          dataSock.setTimeout(t, () => rej(new Error('data connect timeout')));
        });

        writeCmd(sock, `STOR ${probeFile}`);
        r = await collectUntilFinalLine(sock, t);
        if (r.code === 550 || r.code === 553 || r.code === 532) {
          try {
            dataSock.destroy();
          } catch {
            /* ignore */
          }
          writeCmd(sock, 'QUIT');
          finish({ writable: false, detail: `stor_denied_${r.code}`, probeFile });
          return;
        }
        if (r.code !== 150 && r.code !== 125) {
          try {
            dataSock.destroy();
          } catch {
            /* ignore */
          }
          fail(`stor_${r.code}`, r.line);
          return;
        }

        await new Promise((res, rej) => {
          dataSock.write(payload, (e) => (e ? rej(e) : res()));
        });
        dataSock.end();

        r = await collectUntilFinalLine(sock, t);
        if (r.code !== 226 && r.code !== 250) {
          fail(`after_upload_${r.code}`, r.line);
          return;
        }

        writeCmd(sock, `DELE ${probeFile}`);
        try {
          await collectUntilFinalLine(sock, 8000);
        } catch {
          /* ignore cleanup errors */
        }
        writeCmd(sock, 'QUIT');
        finish({ writable: true, probeFile, detail: 'stor_ok' });
      } catch (e) {
        try {
          if (dataSock) dataSock.destroy();
        } catch {
          /* ignore */
        }
        fail(e?.message || String(e), phase);
      }
      })();
    });
  });
}

export { ftpWriteProbeEnabled };
