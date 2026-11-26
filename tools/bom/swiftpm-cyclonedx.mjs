// Copyright (c) 2026 Marknote Limited. All rights reserved.
//
// Part of the shared bills-of-materials workflow (wearemarknote/.github).
// Marknote is a trade mark of Marknote Limited. Provided "as is", without
// warranty of any kind.

// A CycloneDX 1.6 BOM from a Swift package's Package.resolved (2026-11-26).
//
// Package.resolved is the lockfile SwiftPM writes: every package the build
// pinned, with its repository and the version or revision it settled on. That
// is what ships, so it is what the BOM lists. The direct dependencies are the
// `.package(url:` lines of Package.swift; the rest are transitive. The graph
// between the pins is not in the lockfile (swift package show-dependencies
// needs a toolchain), so the root depends on the direct set and nothing
// else is drawn. No packages; Node's standard library only.
//
//   node swiftpm-cyclonedx.mjs --resolved Package.resolved --manifest Package.swift \
//        --name "Marknote for macOS" --version 1a2b3c4 --out swift.cdx.json

import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

/** The pins of a v1 (object.pins), v2 or v3 (pins) lockfile, in one shape. */
export function pinsOf(resolved) {
  const list = resolved.pins ?? resolved.object?.pins ?? [];
  return list.map(p => ({
    identity: (p.identity ?? p.package ?? '').toLowerCase(),
    location: p.location ?? p.repositoryURL ?? '',
    version: p.state?.version ?? null,
    revision: p.state?.revision ?? null,
  })).filter(p => p.identity);
}

/** The repository URLs Package.swift names directly, normalised like the pins. */
export function directUrls(manifestText) {
  return new Set([...manifestText.matchAll(/\.package\(\s*(?:name:\s*"[^"]*",\s*)?url:\s*"([^"]+)"/g)].map(m => normalise(m[1])));
}

export function normalise(url) {
  return url.trim().replace(/\.git$/i, '').replace(/\/+$/, '').toLowerCase();
}

/** pkg:swift/<host>/<path>@<version>, the purl type SwiftPM packages use. */
export function purlOf(pin) {
  const url = normalise(pin.location).replace(/^(?:https?:\/\/|git@|ssh:\/\/git@)/, '').replace(':', '/');
  const ref = pin.version ?? (pin.revision ? pin.revision.slice(0, 12) : 'unversioned');
  return `pkg:swift/${url}@${ref}`;
}

export function bomOf({ resolved, manifestText, name, version }) {
  const direct = directUrls(manifestText);
  const components = pinsOf(resolved).map(pin => {
    const purl = purlOf(pin);
    return {
      type: 'library',
      'bom-ref': purl,
      name: pin.identity,
      version: pin.version ?? (pin.revision ? pin.revision.slice(0, 12) : 'unversioned'),
      purl,
      externalReferences: pin.location ? [{ type: 'vcs', url: pin.location }] : undefined,
      properties: pin.revision ? [{ name: 'swiftpm:revision', value: pin.revision }] : undefined,
      direct: direct.has(normalise(pin.location)),
    };
  }).sort((a, b) => a.purl.localeCompare(b.purl));

  const rootRef = `${name}@${version}`;
  return {
    $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      tools: { components: [{ type: 'application', group: 'wearemarknote', name: 'marknote-swiftpm-cyclonedx', version: '1.0.0' }] },
      component: { type: 'application', 'bom-ref': rootRef, name, version },
    },
    components: components.map(({ direct: _direct, ...c }) => c),
    dependencies: [
      { ref: rootRef, dependsOn: components.filter(c => c.direct).map(c => c.purl) },
      ...components.map(c => ({ ref: c.purl, dependsOn: [] })),
    ],
  };
}

if (process.argv[1] && /swiftpm-cyclonedx\.mjs$/.test(process.argv[1])) {
  const args = process.argv.slice(2);
  const option = name => {
    const i = args.indexOf(`--${name}`);
    if (i < 0) return undefined;
    const [value] = args.splice(i, 2).slice(1);
    return value;
  };

  const resolvedPath = option('resolved') ?? 'Package.resolved';
  const manifestPath = option('manifest') ?? 'Package.swift';
  const name = option('name');
  const version = option('version') ?? 'unversioned';
  const out = option('out');
  if (!name || !out) {
    console.error('usage: swiftpm-cyclonedx.mjs [--resolved Package.resolved] [--manifest Package.swift] --name <product> [--version v] --out <file>');
    process.exit(2);
  }

  const bom = bomOf({
    resolved: JSON.parse(readFileSync(resolvedPath, 'utf8')),
    manifestText: readFileSync(manifestPath, 'utf8'),
    name,
    version,
  });
  writeFileSync(out, JSON.stringify(bom, null, 2) + '\n');
  console.log(`${out}: ${bom.components.length} packages (${bom.dependencies[0].dependsOn.length} direct) from ${resolvedPath}`);
}
