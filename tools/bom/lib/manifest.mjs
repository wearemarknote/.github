// Copyright (c) 2026 Marknote Limited. All rights reserved.
//
// Part of the shared bills-of-materials workflow (wearemarknote/.github).
// Marknote is a trade mark of Marknote Limited. Provided "as is", without
// warranty of any kind.

// The manifest a repository keeps at cbom/crypto-assets.json (2026-11-26):
// what cryptography it declares, with the parameters the code cannot show
// and the words a reader needs. Read strictly: an unknown enum value, a
// duplicate id, a match that names no detector or a reference to no asset
// stops the run, because a CBOM that is wrong is worse than none.

import { readFileSync } from 'node:fs';
import { detectorIds, languages } from './catalogue.mjs';

export const enums = {
  assetType: ['algorithm', 'certificate', 'protocol', 'related-crypto-material'],
  primitive: ['drbg', 'mac', 'block-cipher', 'stream-cipher', 'signature', 'hash', 'pke', 'xof', 'kdf', 'key-agree', 'kem', 'ae', 'combiner', 'other', 'unknown'],
  mode: ['cbc', 'ecb', 'ccm', 'gcm', 'cfb', 'ofb', 'ctr', 'other', 'unknown'],
  padding: ['pkcs5', 'pkcs7', 'pkcs1v15', 'oaep', 'raw', 'other', 'unknown'],
  cryptoFunctions: ['generate', 'keygen', 'encrypt', 'decrypt', 'digest', 'tag', 'keyderive', 'sign', 'verify', 'encapsulate', 'decapsulate', 'other', 'unknown'],
  protocolType: ['tls', 'ssh', 'ipsec', 'ike', 'sstp', 'wpa', 'other', 'unknown'],
  materialType: ['private-key', 'public-key', 'secret-key', 'key', 'ciphertext', 'signature', 'digest', 'initialization-vector', 'nonce', 'seed', 'salt', 'shared-secret', 'tag', 'additional-data', 'password', 'credential', 'token', 'other', 'unknown'],
  materialState: ['pre-activation', 'active', 'suspended', 'deactivated', 'compromised', 'destroyed'],
  evidence: ['code', 'configuration'],
};

const SLUG = /^[a-z0-9][a-z0-9.-]*$/;

export class ManifestError extends Error {}

export function loadManifest(path) {
  let raw;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new ManifestError(`${path}: ${error.message}`);
  }
  return parseManifest(raw, path);
}

/** Validates and normalises a manifest object; throws ManifestError with every problem found. */
export function parseManifest(raw, source = 'manifest') {
  const errors = [];
  const fail = (message) => errors.push(message);

  if (!raw || typeof raw !== 'object') fail('the manifest is not an object');
  if (raw?.version !== 1) fail('version must be 1');
  if (typeof raw?.repository !== 'string' || !/^[\w.-]+\/[\w.-]+$/.test(raw.repository)) fail('repository is required, as owner/name');

  const libraries = checkLibraries(raw?.libraries, fail);
  const libraryIds = new Set(libraries.map(l => l.id));

  const list = Array.isArray(raw?.assets) ? raw.assets : [];
  if (list.length === 0) fail('assets must list at least one asset');
  const ids = new Set();
  const inlineDetectors = [];
  const assets = list.map((asset, i) => normaliseAsset(asset, i, { ids, libraryIds, inlineDetectors, fail }));

  for (const asset of assets) {
    for (const ref of asset.refs) if (!ids.has(ref)) fail(`asset ${asset.id} refers to an asset that does not exist: ${ref}`);
  }

  if (errors.length > 0) throw new ManifestError(`${source}: ${errors.join('; ')}`);

  return {
    version: 1,
    repository: raw.repository,
    scan: {
      include: strings(raw.scan?.include),
      exclude: strings(raw.scan?.exclude),
    },
    libraries,
    assets,
    inlineDetectors,
  };
}

function strings(value) {
  return Array.isArray(value) ? value.filter(v => typeof v === 'string') : [];
}

function checkLibraries(value, fail) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) { fail('libraries must be an array'); return []; }
  const seen = new Set();
  return value.map((library, i) => {
    const where = `libraries[${i}]`;
    if (typeof library?.id !== 'string' || !SLUG.test(library.id)) fail(`${where}.id is missing or not a slug`);
    else if (seen.has(library.id)) fail(`${where}.id duplicates ${library.id}`);
    else seen.add(library.id);
    if (typeof library?.name !== 'string' || library.name.length === 0) fail(`${where}.name is required`);
    if (typeof library?.purl !== 'string' && library?.platform !== true) fail(`${where} needs a purl or platform: true`);
    return { id: library?.id, name: library?.name, purl: library?.purl, platform: library?.platform === true, version: library?.version };
  });
}

function oneOf(value, allowed, where, fail, { optional = true } = {}) {
  if (value === undefined || value === null) {
    if (!optional) fail(`${where} is required`);
    return undefined;
  }
  if (!allowed.includes(value)) fail(`${where} must be one of ${allowed.join(', ')}; got ${JSON.stringify(value)}`);
  return value;
}

function manyOf(value, allowed, where, fail) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) { fail(`${where} must be an array`); return undefined; }
  value.forEach((v, i) => oneOf(v, allowed, `${where}[${i}]`, fail));
  return value;
}

function integer(value, where, fail, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (value === undefined || value === null) return undefined;
  if (!Number.isInteger(value) || value < min || value > max) fail(`${where} must be an integer between ${min} and ${max}`);
  return value;
}

function text(value, where, fail, { required = false } = {}) {
  if (value === undefined || value === null) {
    if (required) fail(`${where} is required`);
    return undefined;
  }
  if (typeof value !== 'string') { fail(`${where} must be a string`); return undefined; }
  if (required && value.trim().length === 0) fail(`${where} is required`);
  return value;
}

function normaliseAsset(asset, i, context) {
  const { ids, libraryIds, inlineDetectors, fail } = context;
  const where = `assets[${i}]`;
  const id = typeof asset?.id === 'string' && SLUG.test(asset.id) ? asset.id : null;
  if (!id) fail(`${where}.id is missing or not a slug`);
  else if (ids.has(id)) fail(`${where}.id duplicates ${id}`);
  else ids.add(id);

  const label = id ?? where;
  const name = text(asset?.name, `${label}.name`, fail, { required: true });
  const assetType = oneOf(asset?.assetType, enums.assetType, `${label}.assetType`, fail, { optional: false });
  const purpose = text(asset?.purpose, `${label}.purpose`, fail, { required: true });
  const evidence = oneOf(asset?.evidence, enums.evidence, `${label}.evidence`, fail) ?? 'code';
  const securityRelevant = asset?.securityRelevant === undefined ? true : asset.securityRelevant === true;
  const standard = text(asset?.standard, `${label}.standard`, fail);
  const notes = text(asset?.notes, `${label}.notes`, fail);
  const oid = text(asset?.oid, `${label}.oid`, fail);
  const library = text(asset?.library, `${label}.library`, fail);
  if (library !== undefined && !libraryIds.has(library)) fail(`${label}.library names no library: ${library}`);

  const refs = [];
  const detail = detailOf(asset, assetType, label, fail, refs);
  const matchKeys = matchesOf(asset, label, id ?? `asset-${i}`, name ?? label, fail, inlineDetectors);
  if (evidence === 'code' && matchKeys.size === 0) fail(`${label} has evidence "code" but no matches; give it detector keys or set evidence to "configuration"`);
  const files = strings(asset?.files);

  return { id, name, assetType, purpose, evidence, securityRelevant, standard, notes, oid, library, files, matchKeys, refs, ...detail };
}

function detailOf(asset, assetType, label, fail, refs) {
  switch (assetType) {
    case 'algorithm': {
      const a = asset.algorithm;
      if (!a || typeof a !== 'object') { fail(`${label}.algorithm is required for an algorithm`); return { algorithm: { primitive: 'unknown' } }; }
      return {
        algorithm: {
          primitive: oneOf(a.primitive, enums.primitive, `${label}.algorithm.primitive`, fail, { optional: false }) ?? 'unknown',
          parameterSetIdentifier: text(a.parameterSetIdentifier, `${label}.algorithm.parameterSetIdentifier`, fail),
          curve: text(a.curve, `${label}.algorithm.curve`, fail),
          mode: oneOf(a.mode, enums.mode, `${label}.algorithm.mode`, fail),
          padding: oneOf(a.padding, enums.padding, `${label}.algorithm.padding`, fail),
          cryptoFunctions: manyOf(a.cryptoFunctions, enums.cryptoFunctions, `${label}.algorithm.cryptoFunctions`, fail),
          classicalSecurityLevel: integer(a.classicalSecurityLevel, `${label}.algorithm.classicalSecurityLevel`, fail),
          nistQuantumSecurityLevel: integer(a.nistQuantumSecurityLevel, `${label}.algorithm.nistQuantumSecurityLevel`, fail, { max: 6 }),
        },
      };
    }
    case 'protocol': {
      const p = asset.protocol;
      if (!p || typeof p !== 'object') { fail(`${label}.protocol is required for a protocol`); return { protocol: { type: 'unknown' } }; }
      const cipherSuites = Array.isArray(p.cipherSuites) ? p.cipherSuites.map((s, j) => {
        const algorithms = strings(s?.algorithms);
        refs.push(...algorithms);
        return { name: text(s?.name, `${label}.protocol.cipherSuites[${j}].name`, fail), algorithms, identifiers: strings(s?.identifiers) };
      }) : undefined;
      return { protocol: { type: oneOf(p.type, enums.protocolType, `${label}.protocol.type`, fail, { optional: false }) ?? 'unknown', version: text(p.version, `${label}.protocol.version`, fail), cipherSuites } };
    }
    case 'related-crypto-material': {
      const m = asset.material;
      if (!m || typeof m !== 'object') { fail(`${label}.material is required for related crypto material`); return { material: { type: 'unknown' } }; }
      if (typeof m.algorithmRef === 'string') refs.push(m.algorithmRef);
      const securedBy = m.securedBy && typeof m.securedBy === 'object'
        ? { mechanism: text(m.securedBy.mechanism, `${label}.material.securedBy.mechanism`, fail), algorithmRef: text(m.securedBy.algorithmRef, `${label}.material.securedBy.algorithmRef`, fail) }
        : undefined;
      if (securedBy?.algorithmRef) refs.push(securedBy.algorithmRef);
      return {
        material: {
          type: oneOf(m.type, enums.materialType, `${label}.material.type`, fail, { optional: false }) ?? 'unknown',
          id: text(m.id, `${label}.material.id`, fail),
          state: oneOf(m.state, enums.materialState, `${label}.material.state`, fail),
          size: integer(m.size, `${label}.material.size`, fail),
          format: text(m.format, `${label}.material.format`, fail),
          algorithmRef: text(m.algorithmRef, `${label}.material.algorithmRef`, fail),
          securedBy,
        },
      };
    }
    case 'certificate': {
      const c = asset.certificate ?? {};
      for (const key of ['signatureAlgorithmRef', 'subjectPublicKeyRef']) if (typeof c[key] === 'string') refs.push(c[key]);
      return {
        certificate: {
          subjectName: text(c.subjectName, `${label}.certificate.subjectName`, fail),
          issuerName: text(c.issuerName, `${label}.certificate.issuerName`, fail),
          notValidBefore: text(c.notValidBefore, `${label}.certificate.notValidBefore`, fail),
          notValidAfter: text(c.notValidAfter, `${label}.certificate.notValidAfter`, fail),
          signatureAlgorithmRef: text(c.signatureAlgorithmRef, `${label}.certificate.signatureAlgorithmRef`, fail),
          subjectPublicKeyRef: text(c.subjectPublicKeyRef, `${label}.certificate.subjectPublicKeyRef`, fail),
          certificateFormat: text(c.certificateFormat, `${label}.certificate.certificateFormat`, fail),
          certificateExtension: text(c.certificateExtension, `${label}.certificate.certificateExtension`, fail),
        },
      };
    }
    default:
      return {};
  }
}

/** The detection keys an asset claims: catalogue keys as given, inline patterns compiled into detectors of their own. */
function matchesOf(asset, label, assetId, assetName, fail, inlineDetectors) {
  const keys = new Set();
  if (asset?.matches === undefined) return keys;
  if (!Array.isArray(asset.matches)) { fail(`${label}.matches must be an array`); return keys; }
  asset.matches.forEach((match, j) => {
    const where = `${label}.matches[${j}]`;
    if (typeof match === 'string') {
      const base = match.split(':')[0];
      if (!detectorIds.has(base)) fail(`${where} names no detector in the catalogue: ${match}`);
      keys.add(match);
      return;
    }
    if (!match || typeof match !== 'object' || typeof match.pattern !== 'string') { fail(`${where} must be a detector key or { language, pattern }`); return; }
    if (!Object.hasOwn(languages, match.language)) { fail(`${where}.language must be one of ${Object.keys(languages).join(', ')}`); return; }
    let pattern;
    try {
      pattern = new RegExp(match.pattern, 'g' + (match.flags ?? '').replace(/[^imsu]/g, ''));
    } catch (error) {
      fail(`${where}.pattern is not a regular expression: ${error.message}`);
      return;
    }
    const id = `manifest:${assetId}:${j}`;
    inlineDetectors.push({ id, language: match.language, pattern, template: { name: assetName, assetType: 'algorithm', algorithm: { primitive: 'other' } }, hint: `an inline pattern of ${assetId}` });
    keys.add(id);
  });
  return keys;
}
