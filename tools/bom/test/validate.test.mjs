import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validate } from '../lib/validate.mjs';

const sound = () => ({
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: 'urn:uuid:12345678-1234-1234-1234-123456789abc',
  version: 1,
  metadata: { timestamp: '2026-11-26T00:00:00Z', component: { type: 'application', 'bom-ref': 'root', name: 'Fixture' } },
  components: [
    { type: 'library', 'bom-ref': 'lib', name: 'Lib' },
    { type: 'cryptographic-asset', 'bom-ref': 'crypto:aes', name: 'AES-GCM', cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'ae', mode: 'gcm', nistQuantumSecurityLevel: 5 } }, evidence: { occurrences: [{ location: 'src/a.cs', line: 3 }] } },
    { type: 'cryptographic-asset', 'bom-ref': 'crypto:key', name: 'Key', cryptoProperties: { assetType: 'related-crypto-material', relatedCryptoMaterialProperties: { type: 'secret-key', algorithmRef: 'crypto:aes' } } },
  ],
  dependencies: [{ ref: 'root', dependsOn: ['lib', 'crypto:aes', 'crypto:key'] }, { ref: 'lib', provides: ['crypto:aes'] }],
});

test('a sound document passes', () => {
  assert.deepEqual(validate(sound()), { ok: true, errors: [] });
});

test('each invariant is caught by name', () => {
  const cases = [
    [b => { b.specVersion = '1.5'; }, /specVersion must be 1.6/],
    [b => { b.components[0]['bom-ref'] = 'crypto:aes'; }, /duplicate bom-ref/],
    [b => { b.components[1].cryptoProperties.algorithmProperties.primitive = 'aead'; }, /primitive: "aead" is not one of/],
    [b => { b.components[1].cryptoProperties.algorithmProperties.nistQuantumSecurityLevel = 7; }, /nistQuantumSecurityLevel must be 0 to 6/],
    [b => { b.components[2].cryptoProperties.relatedCryptoMaterialProperties.algorithmRef = 'crypto:ghost'; }, /crypto:ghost resolves to nothing/],
    [b => { b.dependencies[0].dependsOn.push('nowhere'); }, /dependsOn nowhere/],
    [b => { b.dependencies[1].provides = ['nowhere']; }, /provides nowhere/],
    [b => { b.components[1].evidence.occurrences[0] = { line: 1 }; }, /occurrence needs a location/],
    [b => { delete b.components[1].cryptoProperties; }, /needs cryptoProperties/],
    [b => { b.components[1].cryptoProperties = { assetType: 'protocol' }; }, /a protocol needs protocolProperties/],
    [b => { b.metadata.component = { name: 'no type' }; }, /needs a type and a name/],
    [b => { b.components[0].type = 'widget'; }, /unknown component type/],
  ];
  for (const [mutate, expected] of cases) {
    const bom = sound();
    mutate(bom);
    const { ok, errors } = validate(bom);
    assert.equal(ok, false, expected.source);
    assert.ok(errors.some(e => expected.test(e)), `${expected.source} in ${JSON.stringify(errors)}`);
  }
});
