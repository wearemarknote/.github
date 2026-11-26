import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bomOf, directUrls, pinsOf, purlOf } from '../swiftpm-cyclonedx.mjs';
import { validate } from '../lib/validate.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const swift = join(here, 'fixtures', 'swift');
const read = (name) => readFileSync(join(swift, name), 'utf8');

test('a version 3 lockfile: every pin, the direct set from Package.swift, swift purls', () => {
  const bom = bomOf({ resolved: JSON.parse(read('Package.resolved')), manifestText: read('Package.swift'), name: 'Fixture', version: 'test' });
  assert.deepEqual(bom.components.map(c => c.purl), [
    'pkg:swift/github.com/apple/swift-asn1@1.7.4',
    'pkg:swift/github.com/apple/swift-crypto@5.1.1',
    'pkg:swift/github.com/example/unreleased-helper@0123456789ab',
  ]);
  assert.equal(bom.components[2].version, '0123456789ab');
  assert.equal(bom.components[2].properties[0].value, '0123456789abcdef0123456789abcdef01234567');
  assert.deepEqual(bom.dependencies[0].dependsOn.sort(), ['pkg:swift/github.com/apple/swift-crypto@5.1.1', 'pkg:swift/github.com/example/unreleased-helper@0123456789ab']);
  assert.equal(bom.metadata.component['bom-ref'], 'Fixture@test');
  assert.ok(bom.components.every(c => !('direct' in c)));
  assert.deepEqual(validate(bom), { ok: true, errors: [] });
});

test('a version 1 lockfile reads the same way', () => {
  const pins = pinsOf(JSON.parse(read('Package.v1.resolved')));
  assert.equal(pins.length, 1);
  assert.equal(pins[0].identity, 'swift-crypto');
  assert.equal(purlOf(pins[0]), 'pkg:swift/github.com/apple/swift-crypto@5.1.1');
});

test('direct URLs are read with or without a name and a .git suffix', () => {
  const urls = directUrls(read('Package.swift'));
  assert.ok(urls.has('https://github.com/apple/swift-crypto'));
  assert.ok(urls.has('https://github.com/example/unreleased-helper'));
});
