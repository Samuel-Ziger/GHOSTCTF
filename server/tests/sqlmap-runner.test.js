import test from 'node:test';
import assert from 'node:assert/strict';
import { sniffSqlmapHints } from '../modules/sqlmap-runner.js';

test('sniffSqlmapHints: MySQL na mensagem', () => {
  const h = sniffSqlmapHints("You have an error in your SQL syntax near ''1'''");
  assert.equal(h.dbms, 'MySQL');
});

test('sniffSqlmapHints: PostgreSQL', () => {
  const h = sniffSqlmapHints('ERROR: syntax error at or near "LIMIT"');
  assert.equal(h.dbms, 'PostgreSQL');
});

test('sniffSqlmapHints: Unknown database', () => {
  const h = sniffSqlmapHints("Unknown database 'acme_prod' in information");
  assert.equal(h.dbms, 'MySQL');
  assert.equal(h.database, 'acme_prod');
});
