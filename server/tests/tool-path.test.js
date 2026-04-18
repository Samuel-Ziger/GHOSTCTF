import path from 'path';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseExtraPathInput,
  prependExtraPathToEnvPath,
  augmentProcessPathFromCommonDirs,
} from '../modules/tool-path.js';

test('parseExtraPathInput: dedupe e trim', () => {
  const sep = path.delimiter;
  const segs = parseExtraPathInput(`/a/b${sep}/a/b${sep}/c`);
  assert.ok(segs.includes('/a/b'));
  assert.ok(segs.includes('/c'));
  assert.equal(segs.length, 2);
});

test('prependExtraPathToEnvPath: prefixo', () => {
  const sep = path.delimiter;
  const merged = prependExtraPathToEnvPath(`${path.join('/tmp', 'gh-extra')}${sep}${path.join('/tmp', 'gh-extra2')}`, '/usr/bin');
  assert.ok(merged.includes('/usr/bin'));
  assert.ok(merged.startsWith(path.join('/tmp', 'gh-extra') + sep) || merged.includes('gh-extra'));
});

test('augmentProcessPathFromCommonDirs: desligado com GHOSTRECON_AUTO_PATH=0', () => {
  const prev = process.env.GHOSTRECON_AUTO_PATH;
  process.env.GHOSTRECON_AUTO_PATH = '0';
  assert.equal(augmentProcessPathFromCommonDirs().length, 0);
  process.env.GHOSTRECON_AUTO_PATH = prev;
});

test('augmentProcessPathFromCommonDirs: idempotente na mesma sessão', () => {
  const prev = process.env.GHOSTRECON_AUTO_PATH;
  const savePath = process.env.PATH;
  delete process.env.GHOSTRECON_AUTO_PATH;
  augmentProcessPathFromCommonDirs();
  const second = augmentProcessPathFromCommonDirs();
  assert.equal(second.length, 0);
  process.env.PATH = savePath;
  process.env.GHOSTRECON_AUTO_PATH = prev;
});
