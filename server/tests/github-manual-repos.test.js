import test from 'node:test';
import assert from 'node:assert/strict';
import { parseGithubManualRepoList, parseOneGithubRepoLine } from '../modules/github-manual-repos.js';

test('parseOneGithubRepoLine URL completo com tree', () => {
  const r = parseOneGithubRepoLine('https://github.com/acme/private-bounty/tree/main/apps/web');
  assert.equal(r?.full_name, 'acme/private-bounty');
  assert.equal(r?.clone_url, 'https://github.com/acme/private-bounty.git');
});

test('parseOneGithubRepoLine owner/repo', () => {
  const r = parseOneGithubRepoLine('  Foo-Bar/baz_qux  ');
  assert.equal(r?.full_name, 'Foo-Bar/baz_qux');
});

test('parseGithubManualRepoList multilinha e dedupe', () => {
  const list = parseGithubManualRepoList(
    'https://github.com/a/r1\na/r1\nhttps://github.com/b/r2',
    { max: 10 },
  );
  assert.equal(list.length, 2);
  assert.equal(list[0].full_name, 'a/r1');
  assert.equal(list[1].full_name, 'b/r2');
});

test('parseGithubManualRepoList array JSON', () => {
  const list = parseGithubManualRepoList(['x/y', '', 'https://github.com/p/q.git']);
  assert.equal(list.length, 2);
});
