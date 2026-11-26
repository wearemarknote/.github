# Bills of materials

The organisation's software and cryptography bills of materials come from one place: the reusable workflow [`.github/workflows/boms.yml`](../../.github/workflows/boms.yml) and the scripts in this folder. Each product repository calls the workflow from a short `boms.yml` of its own; every run leaves two artefacts, `sbom` and `cbom`, both CycloneDX 1.6 JSON, which Lighthouse reads and shows.

## What a run makes

| Artefact | File | How |
| --- | --- | --- |
| `sbom` | `bom/marknote-<slug>.cdx.json` | One BOM per shipped part (the dotnet `CycloneDX` tool 6.2.0 per csproj; `@cyclonedx/cyclonedx-npm` 6.0.1 for a vendored web folder; the `org.cyclonedx.bom` Gradle plugin 3.6.1 through [`cyclonedx.init.gradle`](cyclonedx.init.gradle); [`swiftpm-cyclonedx.mjs`](swiftpm-cyclonedx.mjs) over `Package.resolved`), merged by [`merge-cyclonedx.mjs`](merge-cyclonedx.mjs): components de-duplicated by purl, the dependency graph kept, one root whose direct dependencies are the union of the parts'. |
| `cbom` | `bom/marknote-<slug>.cbom.cdx.json` | [`cbom.mjs`](cbom.mjs): the repository's `cbom/crypto-assets.json` rendered as `cryptographic-asset` components, each with the places the scanner saw it in the code; detections nobody declared and declarations the code no longer shows are marked, not fatal. |

Both are checked by [`check.mjs`](check.mjs) before upload (required fields, enums, unique and resolving references). This repository's own [test workflow](../../.github/workflows/test.yml) also validates the fixtures against the full 1.6 schema with the CycloneDX CLI.

## Calling the workflow

```yaml
# .github/workflows/boms.yml in a product repository
name: Bills of materials
on:
  push:
    branches: [master]
  schedule:
    - cron: '23 4 * * 1'
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: boms-${{ github.ref }}
  cancel-in-progress: true
jobs:
  boms:
    uses: wearemarknote/.github/.github/workflows/boms.yml@main
    with:
      product-name: Marknote Sync
      product-slug: sync
      stack: dotnet
      projects: src/Marknote.SyncApi/Marknote.SyncApi.csproj src/Marknote.AdminPortal/Marknote.AdminPortal.csproj
      npm-dir: tools/lighthouse-vendor
```

| Input | Meaning |
| --- | --- |
| `product-name`, `product-slug` | The product as Lighthouse names it, and the file stem (`marknote-<slug>`). |
| `stack` | `dotnet` (needs `projects`), `swift` (reads `Package.resolved` and `Package.swift` at the root) or `gradle` (runs the wrapper with the init script). |
| `npm-dir`, `npm-install-flags` | A folder whose lockfile lists vendored web libraries; its production dependencies join the SBOM. |
| `gradle-configs` | A regular expression over the Gradle configurations to scan; the release runtime classpaths by default. |
| `runs-on` | `windows-latest` where the packages only restore there (the Windows app). |
| `cbom-manifest` | The cryptography manifest; `cbom/crypto-assets.json` by default. |
| `tools-ref` | The ref of this repository whose scripts run; `main` by default. A branch here can be tried from one caller before it is merged. |

Outputs: `sbom-file`, `cbom-file`, `cbom-undeclared`, `cbom-unseen`.

## The cryptography manifest

`cbom/crypto-assets.json` ([schema](crypto-assets.schema.json)) is a repository's word on the cryptography it uses: the algorithms, protocols and key material, with the parameters a call site does not show (a key size, an Argon2 cost, a curve), the purpose of each in one sentence, the standard, the library that implements it, and the **matches**: the detector keys from [`lib/catalogue.mjs`](lib/catalogue.mjs) that are this asset's footprint in the code. A detector key is an id (`dotnet.aesgcm`) or `id:variant` where the detector captures the algorithm's name (`jvm.cipher:AES/GCM/NoPadding`, `js.algorithm:SHA-256`); an inline `{ "language", "pattern" }` matches code the catalogue does not know, such as a hand-written PBKDF2. `files` narrows an asset to the folders where it counts, so two uses of one algorithm can be two assets. `evidence: "configuration"` is for what nothing greps for (TLS, HSTS, key material): asserted, never flagged.

Every asset ends in one of four states, written as the component property `marknote:cbom:status`:

| Status | Meaning | What to do |
| --- | --- | --- |
| `verified` | Declared, and the scanner saw it. | Nothing. |
| `asserted` | Declared with configuration evidence. | Keep it true. |
| `declared-unseen` | Declared, and the scanner saw nothing. | The code moved on: take the asset out, or fix its matches. |
| `detected-undeclared` | The scanner saw it, and no asset claims it. | Declare it with its purpose, or take it out of the code. |

Occurrences carry a location, a line number and the matched symbol, never a line of source. The scanner reads source with its comments removed (a comment naming an algorithm is not a use) and its string literals kept (a JCA transformation string is the use); it skips build outputs, packages, build tooling (`tools`, `scripts`, Gradle build files) and tests, plus whatever the manifest's `scan.exclude` adds.

`securityRelevant: false` marks a hash that is a cache key or a content address rather than a security control; `nistQuantumSecurityLevel` 0 on an asymmetric algorithm is what Lighthouse shows as "not quantum-safe".

## Adding a repository

1. Write `cbom/crypto-assets.json`. Run the scanner locally until the drift is zero or every remaining line is a finding you mean to keep:
   `node tools/bom/cbom.mjs --manifest cbom/crypto-assets.json --root /path/to/repo --name "Product" --version local --out /tmp/x.cbom.cdx.json --check`
2. Add the caller workflow above with the inputs for its stack, and run it by hand once.
3. In Lighthouse, add the repository to `CiCdRepo.All` and `SbomProduct.All`; the GitHub App's installation must cover it with Actions read.

## Working on the tools

`node --test tools/bom/test` runs the unit tests against the fixture repository in `test/fixtures/repo`; the test workflow renders the fixtures end to end and validates them with the CycloneDX CLI. A change to the catalogue is a change to every repository's next run, so a new detector should be tried against the real repositories first (`--tools-ref` points a caller at a branch).
