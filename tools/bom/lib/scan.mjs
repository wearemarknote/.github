// Copyright (c) 2026 Marknote Limited. All rights reserved.
//
// Part of the shared bills-of-materials workflow (wearemarknote/.github).
// Marknote is a trade mark of Marknote Limited. Provided "as is", without
// warranty of any kind.

// The scanner (2026-11-26): walks a repository, strips the comments out of
// each source file of a language the catalogue knows, runs the detectors
// over what is left, and reports where each one fired. Comments go so that a
// comment saying "not X25519" is not a detection; string literals stay,
// because `Cipher.getInstance("AES/GCM/NoPadding")` is the detection.
// Nothing is executed and no source text leaves this process beyond the
// matched symbol itself.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { detectors as catalogue, languages, keyOf } from './catalogue.mjs';

/** Folders and files that never ship: build outputs, packages, build tooling, tests. */
export const defaultExcludes = [
  '.git', 'node_modules', 'bin', 'obj', '.build', 'build', '.gradle', '.idea', '.vs', 'DerivedData', 'packages', '.tools', '.bom-tools',
  'tools', 'scripts', '**/*.gradle', '**/*.gradle.kts',
  'wwwroot/lib', '**/*.min.js', '**/*.bundled.js', '**/*.Designer.cs', '**/*.g.cs', '**/*.generated.cs',
  'tests', 'test', '**/Tests/**', '**/*Tests/**', '**/*.Tests/**', '**/src/test/**', '**/androidTest/**', '**/*Test.kt', '**/*Tests.swift', '**/*.test.mjs', '**/*.spec.ts',
];

/** A glob of the kinds the exclude list uses, as a regular expression over a forward-slash relative path. */
export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        i++;
        if (glob[i + 1] === '/') { i++; re += '(?:.*/)?'; } else re += '.*';
      } else re += '[^/]*';
    } else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

function matcher(patterns) {
  const bare = new Set(patterns.filter(p => !/[*?/]/.test(p)));
  const globs = patterns.filter(p => /[*?/]/.test(p)).map(globToRegExp);
  return (relPath) => {
    const parts = relPath.split('/');
    if (parts.some(part => bare.has(part))) return true;
    return globs.some(g => g.test(relPath) || parts.some((_, i) => g.test(parts.slice(0, i + 1).join('/'))));
  };
}

/** Comments out, string literals and line structure kept. Good enough for C#, Swift, Kotlin, Java and JavaScript. */
export function stripComments(text) {
  let out = '';
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    const next = text[i + 1];
    if (ch === '/' && next === '/') {
      while (i < n && text[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    if (ch === '/' && next === '*') {
      out += '  '; i += 2;
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) { out += text[i] === '\n' ? '\n' : ' '; i++; }
      if (i < n) { out += '  '; i += 2; }
      continue;
    }
    if (ch === '"' && text.startsWith('"""', i)) {
      const end = text.indexOf('"""', i + 3);
      const stop = end < 0 ? n : end + 3;
      out += text.slice(i, stop); i = stop;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      out += ch; i++;
      while (i < n && text[i] !== quote) {
        if (text[i] === '\\' && i + 1 < n) { out += text[i] + text[i + 1]; i += 2; continue; }
        if (text[i] === '\n' && quote !== '`') break;
        out += text[i]; i++;
      }
      if (i < n && text[i] === quote) { out += quote; i++; }
      continue;
    }
    out += ch; i++;
  }
  return out;
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function* walk(root, dir, excluded) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    const full = join(dir, entry.name);
    const rel = relative(root, full).split(sep).join('/');
    if (excluded(rel)) continue;
    if (entry.isDirectory()) yield* walk(root, full, excluded);
    else if (entry.isFile()) yield { full, rel };
  }
}

function languageOf(rel) {
  const dot = rel.lastIndexOf('.');
  const ext = dot < 0 ? '' : rel.slice(dot).toLowerCase();
  for (const [language, extensions] of Object.entries(languages)) if (extensions.includes(ext)) return language;
  return null;
}

/**
 * Scans `root`. `extraDetectors` are the manifest's inline patterns, in the
 * catalogue's shape. Returns { detections, filesScanned }; a detection is
 * { key, detectorId, variant, location, line, symbol }.
 */
export function scan(root, { include = [], exclude = [], extraDetectors = [], maxFileBytes = 2 * 1024 * 1024 } = {}) {
  const excluded = matcher([...defaultExcludes, ...exclude]);
  const included = include.length > 0 ? matcher(include) : null;
  const all = [...catalogue, ...extraDetectors];
  const detections = [];
  let filesScanned = 0;

  for (const { full, rel } of walk(root, root, excluded)) {
    const language = languageOf(rel);
    if (!language) continue;
    if (included && !included(rel)) continue;
    if (statSync(full).size > maxFileBytes) continue;

    const text = stripComments(readFileSync(full, 'utf8'));
    filesScanned++;
    for (const detector of all) {
      if (detector.language !== language) continue;
      detector.pattern.lastIndex = 0;
      for (const match of text.matchAll(detector.pattern)) {
        const variant = match.slice(1).find(g => g !== undefined)?.trim() || undefined;
        detections.push({
          key: keyOf(detector.id, variant),
          detectorId: detector.id,
          variant,
          location: rel,
          line: lineOf(text, match.index),
          symbol: match[0].trim().slice(0, 80),
        });
      }
    }
  }

  detections.sort((a, b) => a.location.localeCompare(b.location) || a.line - b.line || a.key.localeCompare(b.key));
  return { detections, filesScanned };
}
