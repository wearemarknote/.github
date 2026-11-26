import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validate } from '../lib/validate.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, '..', 'merge-cyclonedx.mjs');
const part1 = join(here, 'fixtures', 'sbom', 'part.cdx.json');

const part2 = {
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  version: 1,
  metadata: {
    tools: { components: [{ type: 'application', name: 'another-generator', version: '2.0.0' }] },
    component: { type: 'application', 'bom-ref': 'Fixture.Web@test', name: 'Fixture.Web', version: 'test' },
  },
  components: [
    { type: 'library', 'bom-ref': 'stj', name: 'System.Text.Json', version: '10.0.0', purl: 'pkg:nuget/System.Text.Json@10.0.0' },
    { type: 'library', 'bom-ref': 'pkg:npm/other@1.0.0', name: 'other', version: '1.0.0', purl: 'pkg:npm/other@1.0.0', licenses: [{ license: { name: 'Unknown - See URL' } }] },
  ],
  dependencies: [
    { ref: 'Fixture.Web@test', dependsOn: ['stj', 'pkg:npm/other@1.0.0'] },
    { ref: 'pkg:npm/other@1.0.0', dependsOn: ['stj'] },
  ],
};

test('two parts become one product BOM: deduplicated by purl, aliases remapped, roots united, licences concluded', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bom-merge-'));
  const second = join(dir, 'part2.cdx.json');
  const out = join(dir, 'merged.cdx.json');
  writeFileSync(second, JSON.stringify(part2));

  const stdout = execFileSync(process.execPath, [script, '--name', 'Fixture', '--version', 'test', '--commit', 'abc1234', '--out', out, part1, second], { encoding: 'utf8' });
  assert.match(stdout, /4 components \(4 direct\) from 2 part\(s\)/);

  const merged = JSON.parse(readFileSync(out, 'utf8'));
  assert.deepEqual(validate(merged), { ok: true, errors: [] });
  assert.equal(merged.metadata.component['bom-ref'], 'Fixture@test');
  assert.deepEqual(merged.metadata.properties, [{ name: 'marknote:commit', value: 'abc1234' }]);
  assert.deepEqual(merged.metadata.tools.components.map(t => t.name).sort(), ['another-generator', 'fixture-generator']);

  const purls = merged.components.map(c => c.purl);
  assert.equal(new Set(purls).size, 4);
  assert.ok(purls.includes('pkg:nuget/System.Text.Json@10.0.0'));

  const root = merged.dependencies[0];
  assert.deepEqual(root.dependsOn, ['pkg:npm/other@1.0.0', 'pkg:nuget/Example.Crypto@1.0.0', 'pkg:nuget/Stripe.net@53.0.0', 'pkg:nuget/System.Text.Json@10.0.0']);
  const other = merged.dependencies.find(d => d.ref === 'pkg:npm/other@1.0.0');
  assert.deepEqual(other.dependsOn, ['pkg:nuget/System.Text.Json@10.0.0']);

  const stripe = merged.components.find(c => c.name === 'Stripe.net');
  assert.equal(stripe.licenses[0].license.id, 'Apache-2.0');
  assert.equal(stripe.licenses[0].license.acknowledgement, 'concluded');
  assert.equal(stripe.properties[0].name, 'marknote:licence-source');
  const otherComponent = merged.components.find(c => c.name === 'other');
  assert.equal(otherComponent.licenses[0].license.name, 'Unknown - See URL');
});

test('a file that is not a CycloneDX BOM stops the merge', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bom-merge-'));
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, JSON.stringify({ hello: 'world' }));
  assert.throws(() => execFileSync(process.execPath, [script, '--name', 'Fixture', '--out', join(dir, 'out.json'), bad], { encoding: 'utf8', stdio: 'pipe' }), /is not a CycloneDX BOM/);
});
