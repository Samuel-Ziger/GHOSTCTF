import test from 'node:test';
import assert from 'node:assert/strict';
import { inferOwaspTags, applyOwaspTagsToFindings, OWASP_TOP10_2025 } from '../modules/owasp-top10.js';

test('OWASP catálogo 2025 tem 10 entradas', () => {
  assert.equal(Object.keys(OWASP_TOP10_2025).length, 10);
});

test('XSS / SQLi → A05 Injection', () => {
  const x = inferOwaspTags({ type: 'xss', value: 'x', meta: '' });
  assert.ok(x.some((t) => t.id === 'A05'));
  const s = inferOwaspTags({ type: 'sqli', value: 'x', meta: '' });
  assert.ok(s.some((t) => t.id === 'A05'));
});

test('IDOR verify → A01', () => {
  const t = inferOwaspTags({ type: 'idor', value: 'v', meta: 'verify=idor' });
  assert.ok(t.some((x) => x.id === 'A01'));
});

test('open_redirect → A01 e A06', () => {
  const t = inferOwaspTags({ type: 'open_redirect', value: 'v', meta: '' });
  assert.ok(t.some((x) => x.id === 'A01'));
  assert.ok(t.some((x) => x.id === 'A06'));
});

test('security headers → A02', () => {
  const t = inferOwaspTags({ type: 'security', value: 'no HSTS', meta: 'hsts' });
  assert.ok(t.some((x) => x.id === 'A02'));
});

test('applyOwaspTagsToFindings muta owasp', () => {
  const findings = [{ type: 'dalfox', value: 'hit', meta: '' }];
  applyOwaspTagsToFindings(findings);
  assert.ok(findings[0].owasp);
  assert.ok(findings[0].owasp.some((x) => x.id === 'A05'));
});
