// Copyright (c) 2026 Marknote Limited. All rights reserved.
//
// Part of the shared bills-of-materials workflow (wearemarknote/.github).
// Marknote is a trade mark of Marknote Limited. Provided "as is", without
// warranty of any kind.

// Merges CycloneDX JSON BOMs into one BOM for a product (2026-09-15; shared
// across the organisation's repositories since 2026-11-26).
//
// The boms workflow generates one BOM per shipped project (and, where a
// product vendors web libraries, one for those) and merges them here, so a
// product has one file: components deduplicated by purl, the dependency graph
// kept, and a single root whose direct dependencies are the union of each
// part's direct dependencies. No packages; Node's standard library only.
//
//   node merge-cyclonedx.mjs --name "Marknote Sync" --version 1a2b3c4 \
//        --commit <sha> --out marknote-sync.cdx.json part1.json part2.json

import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const args = process.argv.slice(2);
const option = name => {
  const i = args.indexOf(`--${name}`);
  if (i < 0) return undefined;
  const [value] = args.splice(i, 2).slice(1);
  return value;
};

const name = option('name');
const version = option('version') ?? 'unversioned';
const commit = option('commit');
const out = option('out');
const inputs = args;
if (!name || !out || inputs.length === 0) {
  console.error('usage: merge-cyclonedx.mjs --name <product> [--version v] [--commit sha] --out <file> <bom.json>...');
  process.exit(2);
}

const rootRef = `${name}@${version}`;
const components = new Map();      // key -> component
const refAlias = new Map();        // an input's bom-ref -> the kept component's bom-ref
const dependsOn = new Map();       // bom-ref -> Set of bom-refs
const tools = new Map();
const direct = new Set();

const keyOf = c => c.purl ?? `${c.group ? c.group + '/' : ''}${c.name}@${c.version}`;

for (const file of inputs) {
  const bom = JSON.parse(readFileSync(file, 'utf8'));
  if (bom.bomFormat !== 'CycloneDX') throw new Error(`${file} is not a CycloneDX BOM`);

  for (const tool of bom.metadata?.tools?.components ?? []) tools.set(`${tool.name}@${tool.version}`, tool);

  for (const component of bom.components ?? []) {
    const key = keyOf(component);
    if (!components.has(key)) components.set(key, component);
    refAlias.set(component['bom-ref'] ?? key, components.get(key)['bom-ref'] ?? key);
  }

  const partRoot = bom.metadata?.component?.['bom-ref'];
  for (const dep of bom.dependencies ?? []) {
    const targets = (dep.dependsOn ?? []).map(r => refAlias.get(r) ?? r);
    if (dep.ref === partRoot) {
      targets.forEach(t => direct.add(t));
      continue;
    }
    const ref = refAlias.get(dep.ref) ?? dep.ref;
    const set = dependsOn.get(ref) ?? new Set();
    targets.forEach(t => set.add(t));
    dependsOn.set(ref, set);
  }
}

// Licences the package metadata cannot declare (2026-11-07, the two tables of
// the sync service and the Windows app joined on 2026-11-26). A nuspec with
// <license type="file"> names a file in the package and no SPDX id, so the
// BOM generator leaves the component without one, and the Windows SDK build
// tools say "Unknown - See URL"; Lighthouse's SBOM page counts both as not
// declared. Read from the files in the packages: Stripe.net's LICENSE is
// Apache 2.0; Microsoft's native shims, the Windows App SDK family, Windows
// ML and the SDK build tools carry the Microsoft Software License Terms,
// which have no SPDX id and are named; WebView2's LICENSE.txt is the
// three-clause BSD text; LibGit2Sharp is MIT and the libgit2 it wraps is GPL
// 2 with libgit2's own linking exception; khroma's licence on GitHub is MIT.
// Concluded by us, and said so, rather than declared by the package.
const microsoftTerms = (name, version) => ({ name: 'Microsoft Software License Terms', url: `https://www.nuget.org/packages/${name}/${version}/License` });
const concluded = (c) => {
  if (c.name.startsWith('Microsoft.WindowsAppSDK') || c.name === 'Microsoft.Windows.AI.MachineLearning'
      || c.name === 'Microsoft.Windows.SDK.BuildTools' || c.name === 'Microsoft.Windows.SDK.BuildTools.MSIX'
      || c.name === 'Microsoft.Data.SqlClient.SNI.runtime' || c.name === 'Microsoft.Identity.Client.NativeInterop') return microsoftTerms(c.name, c.version);
  switch (c.name) {
    case 'Stripe.net': return { id: 'Apache-2.0', url: 'https://github.com/stripe/stripe-dotnet/blob/master/LICENSE' };
    case 'Microsoft.Web.WebView2': return { id: 'BSD-3-Clause', url: `https://www.nuget.org/packages/Microsoft.Web.WebView2/${c.version}/License` };
    case 'LibGit2Sharp': return { id: 'MIT', url: 'https://github.com/libgit2/libgit2sharp/blob/master/LICENSE.md' };
    case 'LibGit2Sharp.NativeBinaries': return { name: 'GPL-2.0-only with the libgit2 linking exception', url: 'https://github.com/libgit2/libgit2/blob/main/COPYING' };
    case 'khroma': return { id: 'MIT', url: 'https://github.com/fabiospampinato/khroma/blob/master/license' };
    default: return undefined;
  }
};
// The same reading as Lighthouse's SbomReports.LicenceOf: an expression, an id or a
// name counts, a name that begins "Unknown" does not.
const declares = c => (c.licenses ?? []).some(l => l.expression || l.license?.id || (l.license?.name && !/^unknown/i.test(l.license.name)));
for (const c of components.values()) {
  const known = concluded(c);
  if (!known || declares(c)) continue;
  c.licenses = [{ license: { ...known, acknowledgement: 'concluded' } }];
  (c.properties ??= []).push({ name: 'marknote:licence-source', value: 'the LICENSE file in the package, read by hand' });
}

// Only references to components that exist; a part's root is not one.
const known = new Set([...components.values()].map(c => c['bom-ref'] ?? keyOf(c)));
const dependencies = [
  { ref: rootRef, dependsOn: [...direct].filter(r => known.has(r)).sort() },
  ...[...known].sort().map(ref => ({ ref, dependsOn: [...(dependsOn.get(ref) ?? [])].filter(r => known.has(r)).sort() })),
];

const merged = {
  $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json',
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    tools: { components: [...tools.values()] },
    component: { type: 'application', 'bom-ref': rootRef, name, version },
    properties: commit ? [{ name: 'marknote:commit', value: commit }] : undefined,
  },
  components: [...components.values()].sort((a, b) => keyOf(a).localeCompare(keyOf(b))),
  dependencies,
};

writeFileSync(out, JSON.stringify(merged, null, 2) + '\n');
console.log(`${out}: ${merged.components.length} components (${direct.size} direct) from ${inputs.length} part(s)`);
