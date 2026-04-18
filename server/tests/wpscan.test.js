import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractWpscanFindings,
  resolveWpscanApiToken,
  isWpscanApiRequired,
  countWpvulndbFindings,
} from '../modules/wpscan.js';

test('extractWpscanFindings inclui vulnerabilidades WPVulnDB quando presentes no JSON', () => {
  const json = {
    version: {
      number: '6.4.3',
      confidence: 100,
      vulnerabilities: [
        {
          title: 'Test Core Issue',
          fixed_in: '6.4.4',
          references: { cve: ['CVE-2099-0001'] },
        },
      ],
    },
    plugins: {
      'sample-plugin': {
        location: 'https://exemplo.com/wp-content/plugins/sample-plugin/',
        version: { number: '1.0', confidence: 80 },
        vulnerabilities: [
          { title: 'Sample plugin vuln', references: { cve: ['CVE-2099-0002'] } },
        ],
      },
    },
  };
  const findings = extractWpscanFindings({ targetUrl: 'https://exemplo.com/', wpscanJson: json });
  const vals = findings.map((f) => f.value).join('\n');
  assert.ok(vals.includes('CVE-2099-0001'));
  assert.ok(vals.includes('CVE-2099-0002'));
});

test('resolveWpscanApiToken usa WPSCAN_API_TOKEN', () => {
  const prev = process.env.WPSCAN_API_TOKEN;
  const prevG = process.env.GHOSTRECON_WPSCAN_API_TOKEN;
  delete process.env.GHOSTRECON_WPSCAN_API_TOKEN;
  process.env.WPSCAN_API_TOKEN = 'abc-token';
  try {
    assert.equal(resolveWpscanApiToken(), 'abc-token');
  } finally {
    if (prev === undefined) delete process.env.WPSCAN_API_TOKEN;
    else process.env.WPSCAN_API_TOKEN = prev;
    if (prevG === undefined) delete process.env.GHOSTRECON_WPSCAN_API_TOKEN;
    else process.env.GHOSTRECON_WPSCAN_API_TOKEN = prevG;
  }
});

test('isWpscanApiRequired: default exige API; 0 desliga', () => {
  const prev = process.env.GHOSTRECON_WPSCAN_REQUIRE_API;
  try {
    delete process.env.GHOSTRECON_WPSCAN_REQUIRE_API;
    assert.equal(isWpscanApiRequired(), true);
    process.env.GHOSTRECON_WPSCAN_REQUIRE_API = '0';
    assert.equal(isWpscanApiRequired(), false);
  } finally {
    if (prev === undefined) delete process.env.GHOSTRECON_WPSCAN_REQUIRE_API;
    else process.env.GHOSTRECON_WPSCAN_REQUIRE_API = prev;
  }
});

test('countWpvulndbFindings', () => {
  const n = countWpvulndbFindings({
    version: { vulnerabilities: [{ title: 'x', references: { cve: ['CVE-1'] } }] },
  });
  assert.equal(n, 1);
});
