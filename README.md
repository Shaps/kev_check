# Firetruck KEV check

A GitHub Action that fails CI when a locked dependency is affected by a [CISA Known Exploited Vulnerability](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). It reads your lockfiles or SBOM and checks every resolved package against the [Firetruck](https://firetruck.dev) API.

```yaml
- uses: actions/checkout@v5
- uses: shaps/kev_check@v0
```

With no inputs, the action finds supported lockfiles and SBOMs anywhere in the workspace, skipping `node_modules`, `vendor`, and `.git`.

## Supported files

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (classic and Berry), `bun.lock` |
| Go | `go.mod` |
| Python | `requirements*.txt` (exact `==` pins only), `Pipfile.lock`, `poetry.lock`, `uv.lock` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |
| PHP | `composer.lock` |
| Any | CycloneDX JSON (`*.cdx.json`, `bom.json`) and SPDX JSON (`*.spdx.json`) |

SBOM components are identified by their package URL (purl). A component whose purl type is not one of the supported ecosystems below, or that has no purl, is not checked; see [Verdicts](#verdicts).

For ecosystems without a lockfile, such as Maven or Gradle, generate an SBOM first and point `paths` at it:

```yaml
- uses: anchore/sbom-action@v0
  with:
    format: cyclonedx-json
    output-file: sbom.cdx.json
- uses: shaps/kev_check@v0
  with:
    paths: sbom.cdx.json
```

## Verdicts

The action sends each dependency to the API as an ecosystem, a name, and a version. The ecosystem matters: the same name and version in two ecosystems (for example `requests` on npm and PyPI) are looked up separately. Supported ecosystems are Maven, npm, PyPI, Go, RubyGems, NuGet, Cargo (crates.io), and Composer (Packagist).

Each dependency gets one verdict:

| Verdict | Meaning | Effect |
| --- | --- | --- |
| `yes` | A known exploited vulnerability affects this exact version. | Error annotation; fails the step unless `fail-on-kev` is `false`. |
| `unverified` | The package is linked to a known exploited vulnerability, but its affected versions could not be compared with your version. | Warning annotation; never fails the step. Check it by hand. |
| `no` | No known exploited vulnerability affects this version. | Nothing. |

A dependency can also end up **not checked**, with no verdict at all. This happens when:

- an SBOM component's purl type is not a supported ecosystem (for example `deb`, `rpm`, or `generic`). It is never sent to the API.
- an SBOM component has no purl, so its ecosystem is unknown.
- the API rejects that one entry. The rest of the batch is unaffected.

Not-checked dependencies do not fail the step. They raise a single warning and are listed with the reason in the job summary.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `paths` | auto-detect | Newline-separated files or globs to scan. SBOMs with other names are detected by content. |
| `api-key` | none | Firetruck API key. Store it as a secret. |
| `fail-on-kev` | `true` | Fail the step on any `yes` verdict. Set to `false` to only annotate and summarize. `unverified` never fails the step. |
| `concurrency` | `8` | Batch requests in flight at once. |

## Outputs

| Output | Description |
| --- | --- |
| `findings` | JSON array of `{ ecosystem, name, version, verdict, files, kevs, unverifiedKevs }`, one entry per dependency with verdict `yes` or `unverified`, `yes` entries first. |
| `kev-count` | Distinct KEV CVE IDs confirmed to affect a dependency (`yes` verdicts only). |
| `vulnerable-count` | Distinct dependencies with verdict `yes`. |
| `unverified-count` | Distinct dependencies with verdict `unverified`. |
| `unchecked-count` | Distinct dependencies that were not checked. |
| `checked-count` | Distinct dependencies that received a verdict. |

`findings` is a single array, so filter on `verdict` before acting on it. `kevs` holds the CVE IDs confirmed to affect the version and is empty for `unverified` entries; `unverifiedKevs` holds the linked CVE IDs that could not be compared. Dependencies that were not checked are not in `findings`; they are counted in `unchecked-count` and listed in the job summary.

```yaml
- id: kev
  uses: shaps/kev_check@v0
  with:
    fail-on-kev: false
- run: echo '${{ steps.kev.outputs.findings }}' | jq '[.[] | select(.verdict == "unverified")]'
```

Each `yes` and `unverified` dependency is also reported as an annotation on the lockfile that declared it. The job summary lists confirmed matches, then unverified dependencies, then dependencies that were not checked, each with the files that declared them.

## Rate limits

Anonymous requests are limited per IP, and GitHub-hosted runners share IPs. The action looks up each distinct ecosystem, name, and version once, sending them in batches of 100 packages per request; a whole batch counts as one request. A failed batch (server error or network failure) is retried as a whole. If a rate limit resets within a minute the action waits; otherwise it fails with the reset time. Large monorepos should set `api-key`:

```yaml
- uses: shaps/kev_check@v0
  with:
    api-key: ${{ secrets.FIRETRUCK_API_KEY }}
```

## Development

```sh
npm install
npm run all   # typecheck, test, and bundle to dist/
```

`dist/index.js` is committed because GitHub runs it directly. CI fails if it is stale.
