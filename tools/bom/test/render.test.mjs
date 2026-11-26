import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadManifest } from '../lib/manifest.mjs';
import { Status, render } from '../lib/render.mjs';
import { scan } from '../lib/scan.mjs';
import { validate } from '../lib/validate.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, 'fixtures', 'repo');

const manifest = loadManifest(join(repo, 'cbom', 'crypto-assets.json'));
const { detections, filesScanned } = scan(repo, { include: manifest.scan.include, exclude: manifest.scan.exclude, extraDetectors: manifest.inlineDetectors });
const sbom = JSON.parse(readFileSync(join(here, 'fixtures', 'sbom', 'part.cdx.json'), 'utf8'));
const { bom, summary } = render({
  manifest,
  detections,
  sbom,
  extraDetectors: manifest.inlineDetectors,
  meta: { name: 'Fixture', version: 'test', commit: '0123456', repository: 'wearemarknote/fixture', manifestPath: 'cbom/crypto-assets.json', filesScanned },
});

const byRef = (ref) => {
  const component = bom.components.find(c => c['bom-ref'] === ref);
  assert.ok(component, `${ref} is in the document`);
  return component;
};
const prop = (component, name) => component.properties?.find(p => p.name === `marknote:cbom:${name}`)?.value;

test('the four statuses come out as the fixture was built to show', () => {
  assert.deepEqual(
    { verified: summary.verified, asserted: summary.asserted, unseen: summary.unseen, undeclared: summary.undeclared, assets: summary.assets },
    { verified: 6, asserted: 2, unseen: 1, undeclared: 5, assets: 9 });
  assert.deepEqual(summary.unseenIds, ['argon2id']);
  assert.deepEqual(summary.undeclaredKeys, ['dotnet.rng', 'js.algorithm:PBKDF2', 'js.subtle:decrypt', 'js.subtle:deriveBits', 'js.subtle:importKey']);
});

test('a verified asset carries its properties and where the code shows it, never the code', () => {
  const aes = byRef('crypto:aes-256-gcm');
  assert.equal(aes.type, 'cryptographic-asset');
  assert.equal(aes.description, 'Document content under a per-document key.');
  assert.equal(aes.cryptoProperties.assetType, 'algorithm');
  assert.equal(aes.cryptoProperties.algorithmProperties.mode, 'gcm');
  assert.equal(aes.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 5);
  const locations = new Set(aes.evidence.occurrences.map(o => o.location));
  for (const file of ['src/Crypto.cs', 'src/Keys.swift', 'src/Vault.kt', 'src/share.js']) assert.ok(locations.has(file), file);
  for (const occurrence of aes.evidence.occurrences) {
    assert.deepEqual(Object.keys(occurrence).sort(), ['additionalContext', 'line', 'location', 'symbol']);
    assert.ok(occurrence.symbol.length <= 80);
  }
  assert.equal(prop(aes, 'status'), Status.verified);
  assert.equal(prop(aes, 'library'), '.NET base class library');
  assert.equal(prop(aes, 'standard'), 'NIST SP 800-38D');
  assert.equal(prop(aes, 'security-relevant'), 'true');
});

test('files scope an asset, and a hash that is not a security control says so', () => {
  const etag = byRef('crypto:etag-sha256');
  assert.ok(etag.evidence.occurrences.length > 0);
  assert.ok(etag.evidence.occurrences.every(o => o.location.startsWith('src/Caching/')));
  assert.equal(prop(etag, 'security-relevant'), 'false');
  assert.equal(prop(etag, 'status'), Status.verified);
});

test('an inline pattern attributes to its asset', () => {
  const sha = byRef('crypto:sha-256');
  assert.ok(sha.evidence.occurrences.some(o => o.additionalContext.startsWith('manifest:sha-256:') && o.location === 'src/Crypto.cs' && o.line === 21));
});

test('declared but unseen, and asserted, with their references resolved', () => {
  const argon = byRef('crypto:argon2id');
  assert.equal(prop(argon, 'status'), Status.unseen);
  assert.equal(argon.evidence, undefined);
  assert.equal(argon.cryptoProperties.algorithmProperties.parameterSetIdentifier, 'm=131072,t=3,p=4');

  const tls = byRef('crypto:tls');
  assert.equal(prop(tls, 'status'), Status.asserted);
  assert.equal(tls.cryptoProperties.protocolProperties.type, 'tls');
  assert.deepEqual(tls.cryptoProperties.protocolProperties.cipherSuites[0].algorithms, ['crypto:aes-256-gcm', 'crypto:sha-256']);

  const key = byRef('crypto:vault-key');
  assert.equal(key.cryptoProperties.assetType, 'related-crypto-material');
  assert.equal(key.cryptoProperties.relatedCryptoMaterialProperties.algorithmRef, 'crypto:aes-256-gcm');
  assert.equal(key.cryptoProperties.relatedCryptoMaterialProperties.securedBy.algorithmRef, 'crypto:aes-256-gcm');
  assert.equal(key.cryptoProperties.relatedCryptoMaterialProperties.size, 256);
});

test('a detection nobody declared becomes a marked component of its own', () => {
  const pbkdf2 = byRef('crypto:undeclared:js.algorithm:PBKDF2');
  assert.equal(prop(pbkdf2, 'status'), Status.undeclared);
  assert.equal(pbkdf2.name, 'WebCrypto algorithm name (PBKDF2)');
  assert.equal(prop(pbkdf2, 'detector'), 'js.algorithm:PBKDF2');
  assert.ok(pbkdf2.evidence.occurrences.length >= 1);
  assert.match(pbkdf2.description, /declared by nobody/);

  const rng = byRef('crypto:undeclared:dotnet.rng');
  assert.equal(rng.cryptoProperties.algorithmProperties.primitive, 'drbg');
});

test('libraries come from the SBOM when it has them, else are synthesised; provides links them to their assets', () => {
  const example = byRef('pkg:nuget/Example.Crypto@1.0.0');
  assert.equal(example.type, 'library');
  assert.equal(example.licenses[0].license.id, 'MIT');
  const bcl = byRef('platform:bcl');
  assert.equal(bcl.properties[0].name, 'marknote:cbom:platform');

  const dependency = (ref) => bom.dependencies.find(d => d.ref === ref);
  assert.deepEqual(dependency('platform:bcl').provides.sort(), ['crypto:aes-256-gcm', 'crypto:hkdf-sha256']);
  assert.deepEqual(dependency('pkg:nuget/Example.Crypto@1.0.0').provides, ['crypto:hmac-sha256']);
  const root = bom.dependencies[0];
  assert.equal(root.ref, 'Fixture@test');
  for (const ref of ['platform:bcl', 'pkg:nuget/Example.Crypto@1.0.0', 'crypto:argon2id', 'crypto:undeclared:dotnet.rng']) assert.ok(root.dependsOn.includes(ref), ref);
});

test('the envelope and the metadata, and the document validates', () => {
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.specVersion, '1.6');
  assert.match(bom.serialNumber, /^urn:uuid:/);
  assert.equal(bom.metadata.component['bom-ref'], 'Fixture@test');
  assert.equal(bom.metadata.tools.components[0].name, 'marknote-cbom');
  const props = Object.fromEntries(bom.metadata.properties.map(p => [p.name, p.value]));
  assert.equal(props['marknote:commit'], '0123456');
  assert.equal(props['marknote:repository'], 'wearemarknote/fixture');
  assert.equal(props['marknote:cbom:detected-undeclared'], '5');
  assert.equal(props['marknote:cbom:declared-unseen'], '1');
  assert.equal(props['marknote:cbom:files-scanned'], String(filesScanned));
  assert.deepEqual(validate(bom), { ok: true, errors: [] });
});

test('without an SBOM a library by purl is synthesised and says so', () => {
  const { bom: alone } = render({ manifest, detections, sbom: null, extraDetectors: manifest.inlineDetectors, meta: { name: 'Fixture', version: 'test' } });
  const example = alone.components.find(c => c['bom-ref'] === 'pkg:nuget/Example.Crypto@1.0.0');
  assert.equal(example.name, 'Example.Crypto');
  assert.equal(example.properties.find(p => p.name === 'marknote:cbom:in-sbom').value, 'false');
  assert.deepEqual(validate(alone), { ok: true, errors: [] });
});

test('a library purl matches the SBOM without its qualifiers and takes the form the SBOM uses', () => {
  // The Gradle plugin writes ?type=aar on every Android package; the manifest names the bare purl.
  const qualified = { ...sbom, components: sbom.components.map(c => c.purl === 'pkg:nuget/Example.Crypto@1.0.0' ? { ...c, purl: c.purl + '?type=aar', 'bom-ref': c.purl + '?type=aar' } : c) };
  const { bom: joined } = render({ manifest, detections, sbom: qualified, extraDetectors: manifest.inlineDetectors, meta: { name: 'Fixture', version: 'test' } });
  const example = joined.components.find(c => c.name === 'Example.Crypto');
  assert.equal(example['bom-ref'], 'pkg:nuget/Example.Crypto@1.0.0?type=aar');
  assert.equal(example.purl, 'pkg:nuget/Example.Crypto@1.0.0?type=aar');
  assert.equal(example.properties?.find(p => p.name === 'marknote:cbom:in-sbom'), undefined);
  assert.ok(joined.dependencies.some(d => d.ref === 'pkg:nuget/Example.Crypto@1.0.0?type=aar' && d.provides?.length), 'the library still provides its assets');
  assert.deepEqual(validate(joined), { ok: true, errors: [] });
});
