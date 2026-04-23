import test from 'node:test';
import assert from 'node:assert/strict';
import { detectFlagsWithDecoding } from '../ghostctf/flag-detector.js';
import { extractNmapScriptOutputBlob } from '../ghostctf/nmap-scan.js';
import { parseNmapXml } from '../modules/kali-scan.js';
import { ghostctfPositiveIntEnv } from '../ghostctf/env-budgets.js';
import { ghostctfHttpCookieAls, getPipelineHttpCookie } from '../ghostctf/http-cookie-context.js';
import {
  envGhostctfThenRecon,
  ghostctfAiPolicyDisableGemini,
  normalizeAiPrimaryCloud,
  lmStudioExplicitlyEnabledForGhostctf,
} from '../modules/ai-dual-report.js';
import { parseEtcHostsContentForTarget } from '../ghostctf/local-etc-hosts.js';
import { isFalhasHistoricoDecorativeLine, parseFalhasHistoricoSections } from '../ghostctf/brain-sync-falhas-historico.js';
import { jdwpPortsFromNmap } from '../ghostctf/jdwp-probe.js';
import {
  expandIntranetSweepTargets,
  normalizeIntranetSweepPorts,
  isValidIpv4ForSweep,
} from '../ghostctf/intranet-sweep-probe.js';
import {
  parsePostFormTargetUrl,
  htmlAttr,
  extractPostCodeFormsFromHtml,
  inferHydraFailFromBodies,
} from '../ghostctf/hydra-form-code-probe.js';
import { buildGhostreconMarkdownFromCtfPayload } from '../modules/ghost-local-ai.js';

test('detectFlagsWithDecoding: directo + base64', () => {
  const direct = detectFlagsWithDecoding({
    rawText: 'noise Solyd{direct_flag} tail',
    platformId: 'solyd',
  });
  assert.ok(direct.some((h) => h.flag === 'Solyd{direct_flag}' && h.evidence === 'direct'));
  const b64 = Buffer.from('Solyd{from_b64}', 'utf8').toString('base64');
  const decoded = detectFlagsWithDecoding({
    rawText: `x=${b64} y`,
    platformId: 'solyd',
  });
  assert.ok(decoded.some((h) => h.flag === 'Solyd{from_b64}' && h.evidence === 'base64'));
});

test('extractNmapScriptOutputBlob: output= e entidades XML', () => {
  const xml = '<script id="x" output="Solyd&amp;quot;test&quot;"/>';
  const blob = extractNmapScriptOutputBlob(xml);
  assert.match(blob, /Solyd/);
});

test('parseNmapXml: porta aberta com service fechado e script', () => {
  const xml = `<?xml version="1.0"?>
<nmaprun>
<host>
<address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.18"></service>
<script id="http-title" output="Solyd{nmap_script}"/>
</port>
</ports>
</host>
</nmaprun>`;
  const rows = parseNmapXml(xml);
  const r80 = rows.find((r) => r.port === '80' && r.proto === 'tcp');
  assert.ok(r80);
  assert.equal(r80.name, 'http');
  assert.equal(r80.product, 'nginx');
  assert.match(String(r80.extrainfo || ''), /scripts:/);
  assert.match(String(r80.extrainfo || ''), /Solyd\{nmap_script\}/);
});

test('ghostctfPositiveIntEnv', () => {
  const k = 'GHOSTCTF_TEST_POS_INT_XYZ';
  const prev = process.env[k];
  delete process.env[k];
  assert.equal(ghostctfPositiveIntEnv(k, 7), 7);
  process.env[k] = '12';
  assert.equal(ghostctfPositiveIntEnv(k, 7), 12);
  process.env[k] = '0';
  assert.equal(ghostctfPositiveIntEnv(k, 7), 7);
  if (prev === undefined) delete process.env[k];
  else process.env[k] = prev;
});

test('getPipelineHttpCookie: contexto do pedido prevalece sobre env', async () => {
  const k = 'GHOSTCTF_HTTP_COOKIE';
  const prev = process.env[k];
  process.env[k] = 'envcookie=1';
  try {
    await new Promise((resolve, reject) => {
      ghostctfHttpCookieAls.run({ cookie: 'reqcookie=2' }, () => {
        try {
          assert.equal(getPipelineHttpCookie(), 'reqcookie=2');
          resolve();
        } catch (e) {
          reject(e);
        }
      });
    });
    assert.equal(getPipelineHttpCookie(), 'envcookie=1');
  } finally {
    if (prev === undefined) delete process.env[k];
    else process.env[k] = prev;
  }
});

test('envGhostctfThenRecon: GHOSTCTF_* ganha a GHOSTRECON_*', () => {
  const a = 'GHOSTCTF_TEST_ENV_PAIR_A';
  const b = 'GHOSTRECON_TEST_ENV_PAIR_B';
  const pa = process.env[a];
  const pb = process.env[b];
  delete process.env[a];
  process.env[b] = 'recon-val';
  assert.equal(envGhostctfThenRecon(a, b), 'recon-val');
  process.env[a] = 'ctf-val';
  assert.equal(envGhostctfThenRecon(a, b), 'ctf-val');
  if (pa === undefined) delete process.env[a];
  else process.env[a] = pa;
  if (pb === undefined) delete process.env[b];
  else process.env[b] = pb;
});

test('parseEtcHostsContentForTarget: IP alvo e comentários', () => {
  const content = `# head
127.0.0.1 localhost
44.211.59.106 challenge.ctf app.ctf
44.211.59.106 dup.ctf # trailing
1.1.1.1 other.com
`;
  const got = parseEtcHostsContentForTarget(content, '44.211.59.106');
  assert.deepEqual(got, ['challenge.ctf', 'app.ctf', 'dup.ctf']);
});

test('isFalhasHistoricoDecorativeLine: separador ───', () => {
  assert.equal(isFalhasHistoricoDecorativeLine('────────────────────────────────────────────────────────────'), true);
  assert.equal(isFalhasHistoricoDecorativeLine('1. Divulgação de informação (baixa)'), false);
});

test('isFalhasHistoricoDecorativeLine: prefixo de log «· ───»', () => {
  assert.equal(
    isFalhasHistoricoDecorativeLine('· ────────────────────────────────────────────────────────────'),
    true,
  );
  assert.equal(isFalhasHistoricoDecorativeLine('• ───────────────────────────'), true);
});

test('parseFalhasHistoricoSections: título após «Mais comuns» não é a linha ───', () => {
  const raw = `Mais comuns → menos comuns (teste)

────────────────────────────────────────────────────────────
1. Divulgação de informação (título real)
────────────────────────────────────────────────────────────
   • bullet um

────────────────────────────────────────────────────────────
2. Segunda secção
────────────────────────────────────────────────────────────
   • dois`;
  const items = parseFalhasHistoricoSections(raw);
  assert.ok(items.length >= 2);
  assert.match(items[0].title, /Divulgação/);
  assert.ok(!isFalhasHistoricoDecorativeLine(items[0].title));
  assert.match(items[1].title, /Segunda secção/);
});

test('parseEtcHostsContentForTarget: ::ffff:IPv4', () => {
  const content = '::ffff:10.0.0.5 v6wrap.test\n';
  const got = parseEtcHostsContentForTarget(content, '10.0.0.5');
  assert.deepEqual(got, ['v6wrap.test']);
});

test('ghostctfAiPolicyDisableGemini', () => {
  const k = 'GHOSTCTF_AI_ALLOW_GEMINI';
  const prev = process.env[k];
  delete process.env[k];
  assert.equal(ghostctfAiPolicyDisableGemini(), true);
  process.env[k] = '1';
  assert.equal(ghostctfAiPolicyDisableGemini(), false);
  if (prev === undefined) delete process.env[k];
  else process.env[k] = prev;
});

test('jdwpPortsFromNmap: identifica 5005 e serviço jdwp', () => {
  const rows = [
    { proto: 'tcp', port: '22', name: 'ssh', product: 'OpenSSH' },
    { proto: 'tcp', port: '5005', name: 'unknown', product: '' },
    { proto: 'tcp', port: '7001', name: 'tcp', product: 'Java Debug Wire Protocol' },
    { proto: 'udp', port: '5005', name: 'ignored', product: 'jdwp' },
  ];
  const got = jdwpPortsFromNmap(rows);
  assert.deepEqual(got, [5005, 7001]);
});

test('intranet sweep helpers: parse CIDR + portas e valida IPv4', () => {
  assert.equal(isValidIpv4ForSweep('10.15.38.36'), true);
  assert.equal(isValidIpv4ForSweep('999.15.38.36'), false);
  const tg = expandIntranetSweepTargets('10.15.38.36,10.15.38.0/30', 10);
  // /30 => .1 e .2 (sem network/broadcast), mais ip explícito
  assert.deepEqual(tg, ['10.15.38.36', '10.15.38.1', '10.15.38.2']);
  const ports = normalizeIntranetSweepPorts('22,5005,61616,22,99999');
  assert.deepEqual(ports, [22, 5005, 61616]);
});

test('parsePostFormTargetUrl: http e https default ports', () => {
  const h = parsePostFormTargetUrl('http://imobiliarians.solyd:8081/cadastro.php');
  assert.equal(h.host, 'imobiliarians.solyd');
  assert.equal(h.port, 8081);
  assert.equal(h.module, 'http-post-form');
  assert.equal(h.path, '/cadastro.php');
  const s = parsePostFormTargetUrl('https://x.example/path');
  assert.equal(s.port, 443);
  assert.equal(s.module, 'https-post-form');
});

test('htmlAttr: aspas duplas e simples', () => {
  assert.equal(htmlAttr(' name="code" type=\'password\' ', 'name'), 'code');
  assert.equal(htmlAttr(' type=password name=token ', 'name'), 'token');
});

test('extractPostCodeFormsFromHtml: cadastro-like', () => {
  const html = `<div><form method="post" role="form">
    <input class="x" name="code" type="password" placeholder="Insira">
    <button type="submit" name="validar" value="validar">OK</button>
  </form></div>`;
  const rows = extractPostCodeFormsFromHtml(html, 'http://host/cadastro.php');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].fieldName, 'code');
  assert.match(rows[0].extraPost, /validar=validar/);
  assert.equal(rows[0].postUrl, 'http://host/cadastro.php');
});

test('inferHydraFailFromBodies: token novo no POST', () => {
  const getH = '<html><body><p>login</p></body></html>';
  const postH = '<html><body><p>login</p><div class="err">Código inválido</div></body></html>';
  const got = inferHydraFailFromBodies(getH, postH);
  assert.equal(got, 'inválido');
});

test('normalizeAiPrimaryCloud: ghost_local', () => {
  assert.equal(normalizeAiPrimaryCloud('ghost_local', false), 'ghost_local');
  assert.equal(normalizeAiPrimaryCloud('GHOST', false), 'ghost_local');
});

test('lmStudioExplicitlyEnabledForGhostctf: só MODEL não activa', () => {
  const k = [
    'GHOSTCTF_LMSTUDIO_ENABLED',
    'GHOSTRECON_LMSTUDIO_ENABLED',
    'GHOSTCTF_LMSTUDIO_MODEL',
    'GHOSTRECON_LMSTUDIO_MODEL',
  ];
  const snap = Object.fromEntries(k.map((x) => [x, process.env[x]]));
  try {
    for (const x of k) delete process.env[x];
    process.env.GHOSTRECON_LMSTUDIO_MODEL = 'qwen';
    assert.equal(lmStudioExplicitlyEnabledForGhostctf(), false);
    process.env.GHOSTRECON_LMSTUDIO_ENABLED = '1';
    assert.equal(lmStudioExplicitlyEnabledForGhostctf(), true);
    process.env.GHOSTCTF_LMSTUDIO_ENABLED = '0';
    assert.equal(lmStudioExplicitlyEnabledForGhostctf(), false);
  } finally {
    for (const x of k) {
      if (snap[x] === undefined) delete process.env[x];
      else process.env[x] = snap[x];
    }
  }
});

test('buildGhostreconMarkdownFromCtfPayload: inclui findings', () => {
  const md = buildGhostreconMarkdownFromCtfPayload(
    { findings: [{ type: 'endpoint', prio: 'med', url: 'http://x/a' }] },
    'x.test',
  );
  assert.match(md, /GHOSTCTF/);
  assert.match(md, /endpoint/);
});
