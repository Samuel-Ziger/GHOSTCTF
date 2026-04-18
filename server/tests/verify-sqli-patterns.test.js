import test from 'node:test';
import assert from 'node:assert/strict';
import {
  responseLooksLikeSqlError,
  orderByFirstSqlErrorTransition,
  unionNullProbeSignals,
} from '../modules/verify.js';

test('responseLooksLikeSqlError: sintaxe MySQL', () => {
  assert.ok(responseLooksLikeSqlError('You have an error in your SQL syntax near \'1\\\'\' at line 1'));
});

test('responseLooksLikeSqlError: mysqli', () => {
  assert.ok(responseLooksLikeSqlError('Warning: mysqli_query(): (HY000/1064): You have an error in your SQL syntax'));
});

test('responseLooksLikeSqlError: aspas não fechadas', () => {
  assert.ok(responseLooksLikeSqlError('Unclosed quotation mark after the character string'));
});

test('responseLooksLikeSqlError: HTML normal não dispara', () => {
  assert.ok(!responseLooksLikeSqlError('<html><body>Welcome id=1 product page</body></html>'));
});

test('orderByFirstSqlErrorTransition: primeiro salto falso→true', () => {
  const n = orderByFirstSqlErrorTransition(false, [
    { n: 1, sqlErr: false },
    { n: 2, sqlErr: false },
    { n: 3, sqlErr: true },
  ]);
  assert.equal(n, 3);
});

test('orderByFirstSqlErrorTransition: sem transição', () => {
  assert.equal(
    orderByFirstSqlErrorTransition(false, [
      { n: 1, sqlErr: false },
      { n: 2, sqlErr: false },
    ]),
    null,
  );
});

test('unionNullProbeSignals: sql err vs baseline', () => {
  const rb = { text: 'x'.repeat(200) };
  const bits = unionNullProbeSignals(rb, false, [
    { k: 1, sqlErr: false, len: 200 },
    { k: 2, sqlErr: true, len: 200 },
  ]);
  assert.ok(bits.some((b) => b.includes('k2:sql_ne_base')));
});
