import assert from 'node:assert/strict';
import { test } from 'node:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { globToRegExp, scan, stripComments } from '../lib/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, 'fixtures', 'repo');

test('comments go, string literals stay, line numbers hold', () => {
  const source = 'a // X25519 here\nb /* SHA1\n MD5 */ c\nd "AES-GCM" e\nf \'/* not a comment */\' g\n';
  const out = stripComments(source);
  assert.equal(out.split('\n').length, source.split('\n').length);
  assert.doesNotMatch(out, /X25519|SHA1|MD5/);
  assert.match(out, /"AES-GCM"/);
  assert.match(out, /'\/\* not a comment \*\/'/);
});

test('raw strings and template literals keep their text', () => {
  assert.match(stripComments('x = """keep // this"""'), /keep \/\/ this/);
  assert.match(stripComments('x = `keep /* this */`'), /keep \/\* this \*\//);
});

test('globs of the kinds the exclude list uses', () => {
  assert.ok(globToRegExp('**/Tests/**').test('a/Tests/b.cs'));
  assert.ok(globToRegExp('src/Caching/**').test('src/Caching/ETags.cs'));
  assert.ok(!globToRegExp('src/Caching/**').test('src/Crypto.cs'));
  assert.ok(globToRegExp('**/*.min.js').test('wwwroot/x.min.js'));
  assert.ok(globToRegExp('**/*.min.js').test('x.min.js'));
  assert.ok(!globToRegExp('**/*.min.js').test('x.js'));
});

test('the fixture repository: what is seen and what is not', () => {
  const { detections, filesScanned } = scan(repo, { exclude: ['generated'] });
  const keys = new Set(detections.map(d => d.key));

  for (const key of [
    'dotnet.aesgcm', 'dotnet.hkdf', 'dotnet.rng', 'dotnet.sha256',
    'swift.p256-keyagreement', 'swift.hmac:SHA256', 'swift.hkdf:SHA256', 'swift.aesgcm', 'swift.sha256',
    'jvm.cipher:AES/GCM/NoPadding', 'jvm.mac:HmacSHA256', 'jvm.messagedigest:SHA-256',
    'js.algorithm:AES-GCM', 'js.algorithm:PBKDF2', 'js.algorithm:SHA-256', 'js.subtle:importKey', 'js.subtle:decrypt', 'js.subtle:deriveBits',
  ]) assert.ok(keys.has(key), `${key} should be seen`);

  for (const key of ['dotnet.x25519', 'dotnet.sha1', 'dotnet.md5', 'swift.sha512', 'jvm.cipher:AES/CBC/PKCS5Padding', 'dotnet.ecdsa'])
    assert.ok(!keys.has(key), `${key} must not be seen: it is in a comment, under tests/ or under an excluded folder`);

  assert.ok(detections.every(d => !d.location.startsWith('tests/') && !d.location.startsWith('generated/')));
  assert.equal(filesScanned, 5);

  const aes = detections.find(d => d.key === 'dotnet.aesgcm');
  assert.deepEqual({ location: aes.location, line: aes.line, symbol: aes.symbol }, { location: 'src/Crypto.cs', line: 12, symbol: 'AesGcm' });

  const cipher = detections.find(d => d.key === 'jvm.cipher:AES/GCM/NoPadding');
  assert.equal(cipher.variant, 'AES/GCM/NoPadding');
  assert.equal(cipher.detectorId, 'jvm.cipher');
});

test('include narrows the scan to the globs given', () => {
  const { detections } = scan(repo, { include: ['src/*.kt'] });
  assert.ok(detections.length > 0);
  assert.ok(detections.every(d => d.location === 'src/Vault.kt'));
});

test('an inline detector from a manifest runs like a catalogue one', () => {
  const extra = [{ id: 'manifest:sha-256:0', language: 'csharp', pattern: /\bDigestOf\(/g, template: { name: 'SHA-256', assetType: 'algorithm', algorithm: { primitive: 'hash' } }, hint: 'inline' }];
  const { detections } = scan(repo, { extraDetectors: extra });
  const hit = detections.find(d => d.detectorId === 'manifest:sha-256:0');
  assert.equal(hit.location, 'src/Crypto.cs');
  assert.equal(hit.line, 21);
});
