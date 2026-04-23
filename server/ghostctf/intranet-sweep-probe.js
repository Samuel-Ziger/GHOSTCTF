import net from 'node:net';

function ipv4ToInt(ip) {
  const p = String(ip || '')
    .trim()
    .split('.')
    .map((x) => Number(x));
  if (p.length !== 4 || p.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  return (((p[0] << 24) >>> 0) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
}

function intToIpv4(n) {
  const x = Number(n) >>> 0;
  return `${(x >>> 24) & 255}.${(x >>> 16) & 255}.${(x >>> 8) & 255}.${x & 255}`;
}

export function isValidIpv4ForSweep(ip) {
  return ipv4ToInt(ip) != null;
}

export function normalizeIntranetSweepPorts(raw, fallback = [22, 80, 443, 5005, 7575, 61613, 61616]) {
  const src = String(raw || '')
    .split(/[,\s]+/)
    .map((x) => Number(x))
    .filter((n) => Number.isFinite(n) && n >= 1 && n <= 65535);
  const ports = [...new Set(src.length ? src : fallback)];
  return ports.slice(0, 24).sort((a, b) => a - b);
}

export function expandIntranetSweepTargets(rawTargets, maxHosts = 48) {
  const out = [];
  const seen = new Set();
  const add = (ip) => {
    const s = String(ip || '').trim();
    if (!isValidIpv4ForSweep(s) || seen.has(s)) return;
    seen.add(s);
    out.push(s);
  };

  const tokens = String(rawTargets || '')
    .split(/[\n,;\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  for (const t of tokens) {
    if (out.length >= maxHosts) break;
    if (isValidIpv4ForSweep(t)) {
      add(t);
      continue;
    }
    const m = t.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (!m) continue;
    const baseIp = m[1];
    const prefix = Number(m[2]);
    if (!isValidIpv4ForSweep(baseIp) || !Number.isFinite(prefix) || prefix < 16 || prefix > 30) continue;
    const ipInt = ipv4ToInt(baseIp);
    if (ipInt == null) continue;
    const hostBits = 32 - prefix;
    const size = 2 ** hostBits;
    const mask = (0xffffffff << hostBits) >>> 0;
    const netAddr = ipInt & mask;
    const first = size > 2 ? netAddr + 1 : netAddr;
    const last = size > 2 ? netAddr + size - 2 : netAddr + size - 1;
    for (let cur = first; cur <= last && out.length < maxHosts; cur += 1) {
      add(intToIpv4(cur >>> 0));
    }
  }
  return out.slice(0, maxHosts);
}

function tryTcpConnect({ host, port, timeoutMs = 1200 } = {}) {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port });
    let done = false;
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
    const t = setTimeout(() => finish({ ok: false, host, port, reason: 'timeout' }), Math.max(250, timeoutMs));
    sock.once('connect', () => {
      clearTimeout(t);
      finish({ ok: true, host, port });
    });
    sock.once('error', (e) => {
      clearTimeout(t);
      finish({ ok: false, host, port, reason: e?.code || e?.message || 'error' });
    });
    sock.once('close', () => {
      if (done) return;
      clearTimeout(t);
      finish({ ok: false, host, port, reason: 'closed' });
    });
  });
}

export async function runIntranetSweepProbe({
  targetsRaw = '',
  portsRaw = '',
  maxHosts = 48,
  timeoutMs = 1200,
  log,
} = {}) {
  const logger = typeof log === 'function' ? log : () => {};
  const hosts = expandIntranetSweepTargets(targetsRaw, Math.max(1, Math.min(512, Number(maxHosts) || 48)));
  const ports = normalizeIntranetSweepPorts(portsRaw);
  const jobs = [];
  for (const h of hosts) {
    for (const p of ports) jobs.push({ host: h, port: p });
  }

  const concurrency = Math.max(4, Math.min(96, Number(process.env.GHOSTCTF_INTRASWEEP_CONCURRENCY) || 32));
  let idx = 0;
  const hits = [];
  const errors = [];
  const runWorker = async () => {
    while (idx < jobs.length) {
      const cur = idx;
      idx += 1;
      const j = jobs[cur];
      try {
        const r = await tryTcpConnect({ host: j.host, port: j.port, timeoutMs });
        if (r.ok) {
          hits.push(r);
          logger(`[intranet-sweep] open ${r.host}:${r.port}`, 'success');
        } else if (errors.length < 120) {
          errors.push(`${j.host}:${j.port}:${r.reason}`);
        }
      } catch (e) {
        if (errors.length < 120) errors.push(`${j.host}:${j.port}:${e?.message || String(e)}`);
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, jobs.length)) }, () => runWorker()));

  const byHost = new Map();
  for (const h of hits) {
    const arr = byHost.get(h.host) || [];
    arr.push(h.port);
    byHost.set(h.host, arr);
  }
  const summary = [...byHost.entries()]
    .map(([host, pp]) => ({ host, ports: [...new Set(pp)].sort((a, b) => a - b) }))
    .sort((a, b) => b.ports.length - a.ports.length)
    .slice(0, 32);

  return {
    hostsScanned: hosts.length,
    portsScanned: ports.length,
    attempts: jobs.length,
    openHits: hits.length,
    summary,
    errors,
  };
}
