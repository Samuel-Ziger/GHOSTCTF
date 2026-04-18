import test from 'node:test';
import assert from 'node:assert/strict';
import { detectFlagsWithDecoding } from '../ghostctf/flag-detector.js';
import { extractNmapScriptOutputBlob } from '../ghostctf/nmap-scan.js';
import { parseNmapXml } from '../modules/kali-scan.js';
import { ghostctfPositiveIntEnv } from '../ghostctf/env-budgets.js';
import { ghostctfHttpCookieAls, getPipelineHttpCookie } from '../ghostctf/http-cookie-context.js';
import { envGhostctfThenRecon, ghostctfAiPolicyDisableGemini } from '../modules/ai-dual-report.js';
import { parseEtcHostsContentForTarget } from '../ghostctf/local-etc-hosts.js';
import { isFalhasHistoricoDecorativeLine, parseFalhasHistoricoSections } from '../ghostctf/brain-sync-falhas-historico.js';

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
