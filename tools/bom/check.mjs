#!/usr/bin/env node
// Copyright (c) 2026 Marknote Limited. All rights reserved.
//
// Part of the shared bills-of-materials workflow (wearemarknote/.github).
// Marknote is a trade mark of Marknote Limited. Provided "as is", without
// warranty of any kind.

// Checks CycloneDX JSON documents before they are uploaded (2026-11-26):
// the 1.6 required fields, unique bom-refs, resolving references, and the
// enum values of every cryptographic asset. Exit 1 on the first document
// that fails, naming every problem it has.
//
//   node check.mjs bom/marknote-sync.cdx.json bom/marknote-sync.cbom.cdx.json

import { readFileSync } from 'node:fs';
import { validate } from './lib/validate.mjs';

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error('usage: check.mjs <bom.json>...');
  process.exit(2);
}

let failed = false;
for (const file of files) {
  let bom;
  try {
    bom = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    console.error(`${file}: not JSON (${error.message})`);
    failed = true;
    continue;
  }
  const { ok, errors } = validate(bom);
  if (ok) {
    console.log(`${file}: valid CycloneDX ${bom.specVersion}, ${bom.components?.length ?? 0} component(s)`);
    continue;
  }
  failed = true;
  console.error(`${file}: ${errors.length} problem(s)`);
  for (const error of errors) console.error(`  ${error}`);
}
process.exit(failed ? 1 : 0);
