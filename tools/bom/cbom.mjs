#!/usr/bin/env node
// Copyright (c) 2026 Marknote Limited. All rights reserved.
//
// Part of the shared bills-of-materials workflow (wearemarknote/.github).
// Marknote is a trade mark of Marknote Limited. Provided "as is", without
// warranty of any kind.

// The cryptography bill of materials of one repository (2026-11-26): reads
// cbom/crypto-assets.json, scans the code for the cryptography the
// catalogue knows, and writes a CycloneDX 1.6 CBOM in which every declared
// asset carries where the code shows it, every declared asset the code no
// longer shows is marked, and every detection nobody declared is marked
// too. Drift is reported, never fatal: Lighthouse reads it from the
// document. A manifest that is missing or wrong, or a document that would
// not validate, is fatal.
//
//   node cbom.mjs --manifest cbom/crypto-assets.json --root . [--sbom sbom.cdx.json] \
//        --name "Marknote Sync" --version 1a2b3c4 --commit <sha> --repository owner/repo \
//        --out cbom/marknote-sync.cbom.cdx.json [--summary $GITHUB_STEP_SUMMARY] \
//        [--outputs $GITHUB_OUTPUT] [--check]
//
// Exit codes: 0 done; 1 drift found and --check was asked; 2 usage or manifest;
// 3 the document would not validate.

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { loadManifest, ManifestError } from './lib/manifest.mjs';
import { render } from './lib/render.mjs';
import { scan } from './lib/scan.mjs';
import { validate } from './lib/validate.mjs';

const args = process.argv.slice(2);
const flag = name => {
  const i = args.indexOf(`--${name}`);
  if (i < 0) return false;
  args.splice(i, 1);
  return true;
};
const option = name => {
  const i = args.indexOf(`--${name}`);
  if (i < 0) return undefined;
  const [value] = args.splice(i, 2).slice(1);
  return value;
};

const check = flag('check');
const manifestPath = option('manifest') ?? 'cbom/crypto-assets.json';
const root = resolve(option('root') ?? '.');
const sbomPath = option('sbom');
const name = option('name');
const version = option('version') ?? 'unversioned';
const commit = option('commit');
const repository = option('repository');
const out = option('out');
const summaryPath = option('summary');
const outputsPath = option('outputs');

if (!name || !out || args.length > 0) {
  console.error('usage: cbom.mjs --manifest <file> --root <dir> [--sbom <file>] --name <product> [--version v] [--commit sha] [--repository owner/name] --out <file> [--summary <md>] [--outputs <file>] [--check]');
  process.exit(2);
}

let manifest;
try {
  manifest = loadManifest(resolve(root, manifestPath));
} catch (error) {
  if (error instanceof ManifestError) {
    console.error(`The manifest is not usable: ${error.message}`);
    process.exit(2);
  }
  throw error;
}

let sbom = null;
if (sbomPath && existsSync(sbomPath)) sbom = JSON.parse(readFileSync(sbomPath, 'utf8'));

const { detections, filesScanned } = scan(root, { include: manifest.scan.include, exclude: manifest.scan.exclude, extraDetectors: manifest.inlineDetectors });
const { bom, summary } = render({
  manifest,
  detections,
  sbom,
  extraDetectors: manifest.inlineDetectors,
  meta: { name, version, commit, repository: repository ?? manifest.repository, manifestPath, filesScanned },
});

const verdict = validate(bom);
if (!verdict.ok) {
  console.error('The CBOM would not validate:');
  for (const error of verdict.errors) console.error(`  ${error}`);
  process.exit(3);
}

mkdirSync(dirname(resolve(out)), { recursive: true });
writeFileSync(out, JSON.stringify(bom, null, 2) + '\n');

const lines = [
  `${out}: ${summary.assets} declared asset(s) over ${filesScanned} file(s): ${summary.verified} verified, ${summary.asserted} asserted, ${summary.unseen} declared but unseen, ${summary.undeclared} detected but undeclared.`,
  ...summary.unseenIds.map(id => `  unseen: ${id}`),
  ...summary.undeclaredKeys.map(key => `  undeclared: ${key} (${bom.components.find(c => c['bom-ref'] === `crypto:undeclared:${key}`)?.evidence?.occurrences?.[0]?.location ?? '?'})`),
];
console.log(lines.join('\n'));

if (summaryPath) {
  const md = [
    `### CBOM: ${name}`,
    '',
    '| Verified | Asserted | Declared, unseen | Detected, undeclared | Files scanned |',
    '| --- | --- | --- | --- | --- |',
    `| ${summary.verified} | ${summary.asserted} | ${summary.unseen} | ${summary.undeclared} | ${filesScanned} |`,
    '',
    ...summary.unseenIds.map(id => `- Declared but not seen in the code: \`${id}\``),
    ...summary.undeclaredKeys.map(key => `- Seen in the code and declared by nobody: \`${key}\``),
    '',
  ];
  appendFileSync(summaryPath, md.join('\n'));
}

if (outputsPath) {
  appendFileSync(outputsPath, `cbom-undeclared=${summary.undeclared}\ncbom-unseen=${summary.unseen}\ncbom-file=${out}\n`);
}

if (check && (summary.undeclared > 0 || summary.unseen > 0)) process.exit(1);
