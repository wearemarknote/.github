import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ManifestError, loadManifest, parseManifest } from '../lib/manifest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = join(here, 'fixtures', 'repo', 'cbom', 'crypto-assets.json');
const base = () => JSON.parse(readFileSync(fixture, 'utf8'));

const problems = (manifest) => {
  try {
    parseManifest(manifest);
  } catch (error) {
    assert.ok(error instanceof ManifestError, 'a ManifestError is thrown');
    return error.message;
  }
  assert.fail('the manifest should have been refused');
};

test('the fixture manifest parses and compiles its inline pattern', () => {
  const manifest = loadManifest(fixture);
  assert.equal(manifest.repository, 'wearemarknote/fixture');
  assert.equal(manifest.assets.length, 9);
  assert.deepEqual(manifest.scan.exclude, ['generated']);
  assert.equal(manifest.inlineDetectors.length, 1);
  assert.equal(manifest.inlineDetectors[0].language, 'csharp');
  const sha = manifest.assets.find(a => a.id === 'sha-256');
  assert.ok(sha.matchKeys.has('manifest:sha-256:4'));
  assert.ok(sha.matchKeys.has('jvm.messagedigest:SHA-256'));
  const tls = manifest.assets.find(a => a.id === 'tls');
  assert.equal(tls.evidence, 'configuration');
  assert.deepEqual(tls.refs, ['aes-256-gcm', 'sha-256']);
  const key = manifest.assets.find(a => a.id === 'vault-key');
  assert.deepEqual(key.refs, ['aes-256-gcm', 'aes-256-gcm']);
  assert.equal(manifest.assets.find(a => a.id === 'etag-sha256').securityRelevant, false);
});

test('every problem is named in one go', () => {
  const m = base();
  m.assets[0].id = m.assets[1].id;
  m.assets[2].algorithm.primitive = 'aead';
  m.assets[3].matches.push('nothing.here');
  m.assets[7].material.algorithmRef = 'ghost';
  m.assets[4].library = 'missing';
  const message = problems(m);
  for (const expected of ['duplicates', 'primitive must be one of', 'names no detector', 'does not exist: ghost', 'names no library'])
    assert.match(message, new RegExp(expected), expected);
});

test('code evidence needs matches, configuration evidence does not', () => {
  const m = base();
  m.assets[0].matches = [];
  assert.match(problems(m), /no matches/);

  const m2 = base();
  delete m2.assets[0].matches;
  m2.assets[0].evidence = 'configuration';
  assert.doesNotThrow(() => parseManifest(m2));
});

test('an inline pattern must compile and name a language', () => {
  const m = base();
  m.assets[0].matches = [{ language: 'csharp', pattern: '(' }];
  assert.match(problems(m), /not a regular expression/);
  const m2 = base();
  m2.assets[0].matches = [{ language: 'cobol', pattern: 'x' }];
  assert.match(problems(m2), /language must be one of/);
});

test('the envelope: version, repository, assets', () => {
  assert.match(problems({ version: 2, repository: 'a/b', assets: [{ id: 'x', name: 'x', assetType: 'protocol', protocol: { type: 'tls' }, purpose: 'p', evidence: 'configuration' }] }), /version must be 1/);
  assert.match(problems({ version: 1, repository: 'nope', assets: [{ id: 'x', name: 'x', assetType: 'protocol', protocol: { type: 'tls' }, purpose: 'p', evidence: 'configuration' }] }), /owner\/name/);
  assert.match(problems({ version: 1, repository: 'a/b', assets: [] }), /at least one asset/);
  assert.match(problems({ version: 1, repository: 'a/b', libraries: [{ id: 'l', name: 'L' }], assets: [{ id: 'x', name: 'x', assetType: 'protocol', protocol: { type: 'tls' }, purpose: 'p', evidence: 'configuration' }] }), /needs a purl or platform/);
});
