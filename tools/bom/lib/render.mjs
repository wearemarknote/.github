// Copyright (c) 2026 Marknote Limited. All rights reserved.
//
// Part of the shared bills-of-materials workflow (wearemarknote/.github).
// Marknote is a trade mark of Marknote Limited. Provided "as is", without
// warranty of any kind.

// From a manifest and the scanner's detections to a CycloneDX 1.6 CBOM
// (2026-11-26). Every declared asset is a cryptographic-asset component with
// the properties the manifest gave it and, where the code showed it, the
// places it was seen; a detection nobody declared becomes a component of its
// own, marked as such; a declared asset the code no longer shows is marked
// too. The document is valid either way: drift is read on the page, not
// hidden by a failed run. Occurrences carry a location, a line and the
// matched symbol, never a line of source.

import { randomUUID } from 'node:crypto';
import { detectorById } from './catalogue.mjs';
import { globToRegExp } from './scan.mjs';

export const generator = { type: 'application', group: 'wearemarknote', name: 'marknote-cbom', version: '1.0.0' };

export const Status = Object.freeze({
  verified: 'verified',
  asserted: 'asserted',
  unseen: 'declared-unseen',
  undeclared: 'detected-undeclared',
});

const OCCURRENCE_CAP = 200;
const P = (name, value) => ({ name: `marknote:cbom:${name}`, value: String(value) });

/** Which asset claims which detection; what nobody claimed, by detection key. */
export function attribute(manifest, detections) {
  const byAsset = new Map(manifest.assets.map(a => [a.id, []]));
  const fileMatchers = new Map(manifest.assets.map(a => [a.id, a.files.map(globToRegExp)]));
  const undeclared = new Map();

  for (const detection of detections) {
    let claimed = false;
    for (const asset of manifest.assets) {
      if (!asset.matchKeys.has(detection.key) && !asset.matchKeys.has(detection.detectorId)) continue;
      const files = fileMatchers.get(asset.id);
      if (files.length > 0 && !files.some(f => f.test(detection.location))) continue;
      byAsset.get(asset.id).push(detection);
      claimed = true;
    }
    if (!claimed) {
      if (!undeclared.has(detection.key)) undeclared.set(detection.key, []);
      undeclared.get(detection.key).push(detection);
    }
  }
  return { byAsset, undeclared };
}

function clean(object) {
  const out = {};
  for (const [key, value] of Object.entries(object)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value) && value.length === 0) continue;
    if (typeof value === 'object' && !Array.isArray(value)) {
      const inner = clean(value);
      if (Object.keys(inner).length === 0) continue;
      out[key] = inner;
      continue;
    }
    out[key] = value;
  }
  return out;
}

const ref = id => (id ? `crypto:${id}` : undefined);

export function cryptoPropertiesOf(asset) {
  switch (asset.assetType) {
    case 'algorithm':
      return clean({ assetType: 'algorithm', algorithmProperties: asset.algorithm, oid: asset.oid });
    case 'protocol':
      return clean({
        assetType: 'protocol',
        protocolProperties: {
          type: asset.protocol.type,
          version: asset.protocol.version,
          cipherSuites: asset.protocol.cipherSuites?.map(s => clean({ name: s.name, algorithms: s.algorithms.map(ref), identifiers: s.identifiers })),
        },
        oid: asset.oid,
      });
    case 'related-crypto-material':
      return clean({
        assetType: 'related-crypto-material',
        relatedCryptoMaterialProperties: {
          ...asset.material,
          algorithmRef: ref(asset.material.algorithmRef),
          securedBy: asset.material.securedBy ? { mechanism: asset.material.securedBy.mechanism, algorithmRef: ref(asset.material.securedBy.algorithmRef) } : undefined,
        },
        oid: asset.oid,
      });
    case 'certificate':
      return clean({
        assetType: 'certificate',
        certificateProperties: {
          ...asset.certificate,
          signatureAlgorithmRef: ref(asset.certificate.signatureAlgorithmRef),
          subjectPublicKeyRef: ref(asset.certificate.subjectPublicKeyRef),
        },
        oid: asset.oid,
      });
    default:
      return { assetType: 'algorithm', algorithmProperties: { primitive: 'unknown' } };
  }
}

function occurrencesOf(detections) {
  const sorted = [...detections].sort((a, b) => a.location.localeCompare(b.location) || a.line - b.line);
  return {
    occurrences: sorted.slice(0, OCCURRENCE_CAP).map(d => ({ location: d.location, line: d.line, symbol: d.symbol, additionalContext: d.key })),
    capped: sorted.length > OCCURRENCE_CAP,
    total: sorted.length,
  };
}

function statusOf(asset, seen) {
  if (asset.evidence === 'configuration') return Status.asserted;
  return seen > 0 ? Status.verified : Status.unseen;
}

function declaredComponent(asset, detections, libraryNames) {
  const { occurrences, capped, total } = occurrencesOf(detections);
  const status = statusOf(asset, total);
  const properties = [
    P('status', status),
    P('purpose', asset.purpose),
    P('security-relevant', asset.securityRelevant),
    P('occurrences', total),
  ];
  if (asset.standard) properties.push(P('standard', asset.standard));
  if (asset.library) properties.push(P('library', libraryNames.get(asset.library) ?? asset.library));
  if (asset.notes) properties.push(P('notes', asset.notes));
  if (capped) properties.push(P('occurrences-capped', 'true'));

  return {
    component: clean({
      type: 'cryptographic-asset',
      'bom-ref': ref(asset.id),
      name: asset.name,
      description: asset.purpose,
      cryptoProperties: cryptoPropertiesOf(asset),
      evidence: occurrences.length > 0 ? { occurrences } : undefined,
      properties,
    }),
    status,
  };
}

function undeclaredComponent(key, detections, extraDetectors) {
  const detectorId = detections[0].detectorId;
  const variant = detections[0].variant;
  const detector = detectorById(detectorId) ?? extraDetectors.find(d => d.id === detectorId);
  const template = detector?.template ?? { name: detectorId, assetType: 'algorithm', algorithm: { primitive: 'unknown' } };
  const { occurrences, total } = occurrencesOf(detections);
  const cryptoProperties = template.assetType === 'protocol'
    ? { assetType: 'protocol', protocolProperties: template.protocol ?? { type: 'unknown' } }
    : template.assetType === 'certificate'
      ? { assetType: 'certificate' }
      : { assetType: 'algorithm', algorithmProperties: template.algorithm ?? { primitive: 'unknown' } };

  return clean({
    type: 'cryptographic-asset',
    'bom-ref': `crypto:undeclared:${key}`,
    name: variant ? `${template.name} (${variant})` : template.name,
    description: `Seen in the code and declared by nobody: ${detector?.hint ?? detectorId}. Add it to cbom/crypto-assets.json with its purpose, or take it out of the code.`,
    cryptoProperties,
    evidence: { occurrences },
    properties: [P('status', Status.undeclared), P('detector', key), P('occurrences', total)],
  });
}

// The purl without qualifiers or subpath, for matching.
const barePurl = p => p.split("#")[0].split("?")[0];

function libraryComponents(manifest, sbom) {
  // A purl in the SBOM may carry qualifiers the manifest leaves out (the Gradle
  // plugin writes ?type=aar on every Android package): match without the
  // qualifiers and the subpath, and take the form the SBOM uses.
  const bySbomPurl = new Map((sbom?.components ?? []).filter(c => c.purl).map(c => [barePurl(c.purl), c]));
  const refs = new Map();
  const components = manifest.libraries.map(library => {
    if (library.platform) {
      const bomRef = `platform:${library.id}`;
      refs.set(library.id, bomRef);
      return { type: 'library', 'bom-ref': bomRef, name: library.name, version: library.version, properties: [P('platform', 'true')] };
    }
    const known = bySbomPurl.get(barePurl(library.purl));
    const bomRef = known?.['bom-ref'] ?? library.purl;
    refs.set(library.id, bomRef);
    return clean({
      type: 'library',
      'bom-ref': bomRef,
      name: known?.name ?? library.name,
      group: known?.group,
      version: known?.version ?? library.version,
      purl: known?.purl ?? library.purl,
      licenses: known?.licenses,
      properties: known ? undefined : [P('in-sbom', 'false')],
    });
  });
  return { components: components.map(clean), refs };
}

/**
 * Builds the CBOM. `meta`: { name, version, commit, repository, manifestPath, filesScanned }.
 * Returns { bom, summary } where summary has the four counts and the drift lists.
 */
export function render({ manifest, detections, sbom = null, meta, extraDetectors = [] }) {
  const { byAsset, undeclared } = attribute(manifest, detections);
  const libraryNames = new Map(manifest.libraries.map(l => [l.id, l.name]));
  const { components: libraries, refs: libraryRefs } = libraryComponents(manifest, sbom);

  const counts = { verified: 0, asserted: 0, unseen: 0, undeclared: 0 };
  const unseenIds = [];
  const declared = manifest.assets.map(asset => {
    const { component, status } = declaredComponent(asset, byAsset.get(asset.id), libraryNames);
    if (status === Status.verified) counts.verified++;
    else if (status === Status.asserted) counts.asserted++;
    else { counts.unseen++; unseenIds.push(asset.id); }
    return component;
  });

  const undeclaredKeys = [...undeclared.keys()].sort();
  const undeclaredComponents = undeclaredKeys.map(key => undeclaredComponent(key, undeclared.get(key), extraDetectors));
  counts.undeclared = undeclaredComponents.length;

  const rootRef = `${meta.name}@${meta.version}`;
  const assetRefs = [...declared, ...undeclaredComponents].map(c => c['bom-ref']);
  const dependencies = [
    { ref: rootRef, dependsOn: [...new Set([...libraryRefs.values()])].sort().concat(assetRefs) },
    ...manifest.libraries.map(library => {
      const provides = manifest.assets.filter(a => a.library === library.id).map(a => ref(a.id));
      return provides.length > 0 ? { ref: libraryRefs.get(library.id), provides } : { ref: libraryRefs.get(library.id) };
    }),
  ];

  const bom = {
    $schema: 'http://cyclonedx.org/schema/bom-1.6.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      tools: { components: [generator] },
      component: { type: 'application', 'bom-ref': rootRef, name: meta.name, version: meta.version },
      properties: [
        meta.commit ? { name: 'marknote:commit', value: meta.commit } : null,
        meta.repository ? { name: 'marknote:repository', value: meta.repository } : null,
        P('manifest', meta.manifestPath ?? 'cbom/crypto-assets.json'),
        P('files-scanned', meta.filesScanned ?? 0),
        P('verified', counts.verified),
        P('asserted', counts.asserted),
        P('declared-unseen', counts.unseen),
        P('detected-undeclared', counts.undeclared),
      ].filter(Boolean),
    },
    components: [...libraries, ...declared, ...undeclaredComponents],
    dependencies,
  };

  return { bom, summary: { ...counts, assets: manifest.assets.length, unseenIds, undeclaredKeys, filesScanned: meta.filesScanned ?? 0 } };
}
