// Copyright (c) 2026 Marknote Limited. All rights reserved.
//
// Part of the shared bills-of-materials workflow (wearemarknote/.github).
// Marknote is a trade mark of Marknote Limited. Provided "as is", without
// warranty of any kind.

// The invariants a CBOM must hold before it is uploaded (2026-11-26): the
// CycloneDX 1.6 required fields, the enum values of every cryptographic
// asset, unique bom-refs, and every reference resolving to a component.
// The CycloneDX CLI validates the full schema in this repository's own CI;
// this is the check that runs everywhere, with no binary to fetch.

import { enums } from './manifest.mjs';

const componentTypes = new Set(['application', 'framework', 'library', 'container', 'platform', 'operating-system', 'device', 'device-driver', 'firmware', 'file', 'machine-learning-model', 'data', 'cryptographic-asset']);

function check(value, allowed, where, errors) {
  if (value !== undefined && !allowed.includes(value)) errors.push(`${where}: ${JSON.stringify(value)} is not one of ${allowed.join(', ')}`);
}

function checkCrypto(component, errors) {
  const where = component['bom-ref'] ?? component.name;
  const props = component.cryptoProperties;
  if (!props || typeof props !== 'object') { errors.push(`${where}: a cryptographic-asset needs cryptoProperties`); return []; }
  check(props.assetType, enums.assetType, `${where}.assetType`, errors);
  const refs = [];
  const a = props.algorithmProperties;
  if (a) {
    check(a.primitive, enums.primitive, `${where}.primitive`, errors);
    check(a.mode, enums.mode, `${where}.mode`, errors);
    check(a.padding, enums.padding, `${where}.padding`, errors);
    for (const f of a.cryptoFunctions ?? []) check(f, enums.cryptoFunctions, `${where}.cryptoFunctions`, errors);
    if (a.classicalSecurityLevel !== undefined && (!Number.isInteger(a.classicalSecurityLevel) || a.classicalSecurityLevel < 0)) errors.push(`${where}.classicalSecurityLevel must be a non-negative integer`);
    if (a.nistQuantumSecurityLevel !== undefined && (!Number.isInteger(a.nistQuantumSecurityLevel) || a.nistQuantumSecurityLevel < 0 || a.nistQuantumSecurityLevel > 6)) errors.push(`${where}.nistQuantumSecurityLevel must be 0 to 6`);
  }
  const p = props.protocolProperties;
  if (p) {
    check(p.type, enums.protocolType, `${where}.protocol.type`, errors);
    for (const suite of p.cipherSuites ?? []) refs.push(...(suite.algorithms ?? []));
  }
  const m = props.relatedCryptoMaterialProperties;
  if (m) {
    check(m.type, enums.materialType, `${where}.material.type`, errors);
    check(m.state, enums.materialState, `${where}.material.state`, errors);
    if (m.algorithmRef) refs.push(m.algorithmRef);
    if (m.securedBy?.algorithmRef) refs.push(m.securedBy.algorithmRef);
  }
  const c = props.certificateProperties;
  if (c) {
    if (c.signatureAlgorithmRef) refs.push(c.signatureAlgorithmRef);
    if (c.subjectPublicKeyRef) refs.push(c.subjectPublicKeyRef);
  }
  if (props.assetType === 'algorithm' && !a) errors.push(`${where}: an algorithm needs algorithmProperties`);
  if (props.assetType === 'protocol' && !p) errors.push(`${where}: a protocol needs protocolProperties`);
  if (props.assetType === 'related-crypto-material' && !m) errors.push(`${where}: related crypto material needs relatedCryptoMaterialProperties`);
  return refs;
}

/** { ok, errors }: the document's shape, enums and references. */
export function validate(bom) {
  const errors = [];
  if (bom?.bomFormat !== 'CycloneDX') errors.push('bomFormat must be CycloneDX');
  if (bom?.specVersion !== '1.6') errors.push('specVersion must be 1.6');
  if (bom?.serialNumber !== undefined && !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(bom.serialNumber)) errors.push('serialNumber is not a urn:uuid');
  if (bom?.version !== undefined && (!Number.isInteger(bom.version) || bom.version < 1)) errors.push('version must be a positive integer');

  const root = bom?.metadata?.component;
  if (!root?.type || !root?.name) errors.push('metadata.component needs a type and a name');
  if (bom?.metadata?.timestamp !== undefined && Number.isNaN(Date.parse(bom.metadata.timestamp))) errors.push('metadata.timestamp is not a date-time');

  const refs = new Set();
  if (root?.['bom-ref']) refs.add(root['bom-ref']);
  const components = Array.isArray(bom?.components) ? bom.components : [];
  const pendingRefs = [];
  components.forEach((component, i) => {
    const where = component?.['bom-ref'] ?? component?.name ?? `components[${i}]`;
    if (!component?.type || !component?.name) errors.push(`${where}: a component needs a type and a name`);
    if (component?.type && !componentTypes.has(component.type)) errors.push(`${where}: unknown component type ${component.type}`);
    const bomRef = component?.['bom-ref'];
    if (bomRef !== undefined) {
      if (typeof bomRef !== 'string' || bomRef.length === 0) errors.push(`${where}: bom-ref must be a non-empty string`);
      else if (refs.has(bomRef)) errors.push(`duplicate bom-ref ${bomRef}`);
      else refs.add(bomRef);
    }
    if (component?.type === 'cryptographic-asset') pendingRefs.push(...checkCrypto(component, errors).map(r => [where, r]));
    for (const occurrence of component?.evidence?.occurrences ?? []) {
      if (typeof occurrence?.location !== 'string' || occurrence.location.length === 0) errors.push(`${where}: an occurrence needs a location`);
      if (occurrence?.line !== undefined && (!Number.isInteger(occurrence.line) || occurrence.line < 0)) errors.push(`${where}: an occurrence line must be a non-negative integer`);
    }
    for (const property of component?.properties ?? []) if (typeof property?.name !== 'string') errors.push(`${where}: a property needs a name`);
  });

  for (const [where, r] of pendingRefs) if (!refs.has(r)) errors.push(`${where}: reference ${r} resolves to nothing`);
  for (const dependency of bom?.dependencies ?? []) {
    if (!dependency?.ref || !refs.has(dependency.ref)) errors.push(`dependency ref ${dependency?.ref} resolves to nothing`);
    for (const r of dependency?.dependsOn ?? []) if (!refs.has(r)) errors.push(`${dependency.ref} dependsOn ${r}, which resolves to nothing`);
    for (const r of dependency?.provides ?? []) if (!refs.has(r)) errors.push(`${dependency.ref} provides ${r}, which resolves to nothing`);
  }
  return { ok: errors.length === 0, errors };
}
