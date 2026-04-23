import { spawn } from 'node:child_process';
import net from 'node:net';
import { hostLiteralForUrl } from './recon-target.js';

function stripAnsi(text) {
  return String(text || '').replace(/\x1b\[[0-9;]*m/g, '');
}

function truncate(text, max = 6000) {
  const s = stripAnsi(String(text || '')).replace(/\r\n/g, '\n').trim();
  if (s.length <= max) return s;
  return `${s.slice(0, max)}\n… [truncado ${s.length - max} chars]`;
}

function runProc(cmd, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let killed = false;
    const t = setTimeout(() => {
      killed = true;
      try {
        child.kill('SIGKILL');
      } catch {
        /* ignore */
      }
      reject(new Error(`${cmd} timeout (${timeoutMs}ms)`));
    }, timeoutMs);
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => err.push(d));
    child.on('error', (e) => {
      clearTimeout(t);
      reject(e);
    });
    child.on('close', (code) => {
      clearTimeout(t);
      if (killed) return;
      resolve({
        code,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
      });
    });
  });
}

/**
 * Hosts únicos com 139/tcp ou 445/tcp abertos (resultado parseNmapXml).
 * @param {Array<{ host?: string, port?: string, proto?: string }>} rows
 * @returns {string[]}
 */
export function uniqHostsWithSmbPorts(rows) {
  const seen = new Set();
  const out = [];
  for (const row of rows || []) {
    if (!row) continue;
    if (String(row.proto || 'tcp').toLowerCase() !== 'tcp') continue;
    const p = String(row.port || '');
    if (p !== '139' && p !== '445') continue;
    const h = String(row.host || '').trim();
    if (!h || h.toLowerCase() === 'unknown') continue;
    const k = h.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(h);
  }
  return out;
}

function rpcTargetArg(host) {
  const h = String(host || '').trim();
  if (net.isIPv6(h)) return h;
  return hostLiteralForUrl(h);
}

/**
 * Após nmap: `smbclient -L //HOST -N` e `rpcclient -U '' -N HOST -c 'enumdomusers'`.
 * Só para alvos autorizados (bug bounty / pentest).
 *
 * @param {string} host hostname ou IP (como no XML nmap)
 * @param {{ log?: function, addFinding?: function, timeoutMs?: number, tools?: { smbclient?: boolean, rpcclient?: boolean } }} opts
 */
export async function runSmbNullProbesForHost(host, opts = {}) {
  const {
    log,
    addFinding,
    tools = {},
    timeoutMs = Math.max(8000, Number(process.env.GHOSTRECON_SMB_NULL_TIMEOUT_MS || 28000)),
  } = opts;
  const hl = hostLiteralForUrl(host);
  const unc = `//${hl}`;
  const doLog = typeof log === 'function' ? log : () => {};
  const doFinding = typeof addFinding === 'function' ? addFinding : () => {};

  const runSmbclient = Boolean(tools.smbclient);
  const runRpc = Boolean(tools.rpcclient);

  if (!runSmbclient && !runRpc) return;

  if (runSmbclient) {
    try {
      doLog(`[SMB] smbclient -L ${unc} -N`, 'info');
      const r = await runProc('smbclient', ['-L', unc, '-N'], timeoutMs);
      const combined = [r.stdout, r.stderr].filter(Boolean).join('\n').trim();
      const snippet = truncate(combined, 4500);
      if (snippet) {
        doLog(`[SMB] smbclient ${unc} exit=${r.code}\n${snippet}`, 'info');
        doFinding({
          type: 'intel',
          prio: 'med',
          score: /Sharename|IPC\$|Disk\s/i.test(combined) ? 68 : 58,
          value: `SMB enumeração anónima/null: smbclient -L ${unc} -N`,
          meta: [
            'tool=smbclient',
            `exit=${r.code}`,
            `cmd=smbclient -L ${unc} -N`,
            `output=${snippet.replace(/\s+/g, ' ').slice(0, 3800)}`,
          ].join(' · '),
          url: null,
        });
      } else {
        doLog(`[SMB] smbclient ${unc}: saída vazia (exit ${r.code})`, 'info');
      }
    } catch (e) {
      doLog(`[SMB] smbclient ${unc}: ${e?.message || e}`, 'warn');
    }
  }

  if (runRpc) {
    try {
      const target = rpcTargetArg(host);
      doLog(`[SMB] rpcclient -U '' -N ${target} -c 'enumdomusers'`, 'info');
      const r = await runProc('rpcclient', ['-U', '', '-N', target, '-c', 'enumdomusers'], timeoutMs);
      const combined = [r.stdout, r.stderr].filter(Boolean).join('\n').trim();
      const snippet = truncate(combined, 4500);
      if (snippet) {
        doLog(`[SMB] rpcclient enumdomusers @ ${target} exit=${r.code}\n${snippet}`, 'info');
        doFinding({
          type: 'intel',
          prio: /user:\[/i.test(combined) ? 'high' : 'med',
          score: /user:\[/i.test(combined) ? 78 : 60,
          value: `SMB/RPC: rpcclient enumdomusers @ ${target} (guest/null)`,
          meta: [
            'tool=rpcclient',
            `exit=${r.code}`,
            `cmd=rpcclient -U '' -N ${target} -c 'enumdomusers'`,
            `output=${snippet.replace(/\s+/g, ' ').slice(0, 3800)}`,
          ].join(' · '),
          url: null,
        });
      } else {
        doLog(`[SMB] rpcclient @ ${target}: saída vazia (exit ${r.code})`, 'info');
      }
    } catch (e) {
      doLog(`[SMB] rpcclient @ ${host}: ${e?.message || e}`, 'warn');
    }
  }
}
