import test from 'node:test';
import assert from 'node:assert/strict';
import {
  inferMitreTechniqueIds,
  inferMitreTags,
  applyMitreTagsToFindings,
  __setMitreReconBundleForTests,
  __resetMitreReconBundleCache,
} from '../modules/mitre-recon.js';

const miniBundle = {
  schemaVersion: 1,
  techniques: [
    { id: 'T1595', name: 'Active Scanning', phases: ['reconnaissance'], url: 'https://attack.mitre.org/techniques/T1595/' },
    { id: 'T1589', name: 'Gather Victim Identity Information', phases: ['reconnaissance'], url: 'https://attack.mitre.org/techniques/T1589/' },
    { id: 'T1190', name: 'Exploit Public-Facing Application', phases: ['initial-access'], url: 'https://attack.mitre.org/techniques/T1190/' },
    { id: 'T1583.001', name: 'Domains', phases: ['resource-development'], url: 'https://attack.mitre.org/techniques/T1583/T1583.001/' },
  ],
};

test.afterEach(() => {
  __resetMitreReconBundleCache();
});

test('inferMitreTechniqueIds subdomain inclui T1589 e T1595', () => {
  const ids = inferMitreTechniqueIds({ type: 'subdomain', value: 'x.example.com', meta: 'DNS: 1.1.1.1' });
  assert.ok(ids.includes('T1589'));
  assert.ok(ids.includes('T1595'));
});

test('inferMitreTags usa bundle injectado', () => {
  __setMitreReconBundleForTests(miniBundle);
  const tags = inferMitreTags({ type: 'takeover', value: 'cname', meta: '' });
  assert.equal(tags.length, 1);
  assert.equal(tags[0].id, 'T1583.001');
  assert.ok(tags[0].label.includes('Domains'));
});

test('applyMitreTagsToFindings define f.mitre', () => {
  __setMitreReconBundleForTests(miniBundle);
  const findings = [{ type: 'nuclei', value: 'x', meta: 'template=xss' }];
  applyMitreTagsToFindings(findings);
  assert.ok(findings[0].mitre);
  assert.ok(findings[0].mitre.some((x) => x.id === 'T1190'));
});

test('inferMitreTags sem bundle válido devolve vazio', () => {
  __setMitreReconBundleForTests({ schemaVersion: 1, techniques: [] });
  const tags = inferMitreTags({ type: 'subdomain', value: 'a', meta: '' });
  assert.equal(tags.length, 0);
});
