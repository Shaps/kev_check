# Firetruck KEV check

A GitHub Action that fails CI when a locked dependency is tied to a [CISA Known Exploited Vulnerability](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). It reads your lockfiles or SBOM and checks every resolved package against the [Firetruck](https://firetruck.dev) API.

```yaml
- uses: actions/checkout@v5
- uses: firetruck-dev/kev-check@v0
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

For ecosystems without a lockfile, such as Maven or Gradle, generate an SBOM first and point `paths` at it:

```yaml
- uses: anchore/sbom-action@v0
  with:
    format: cyclonedx-json
    output-file: sbom.cdx.json
- uses: firetruck-dev/kev-check@v0
  with:
    paths: sbom.cdx.json
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `paths` | auto-detect | Newline-separated files or globs to scan. SBOMs with other names are detected by content. |
| `api-key` | none | Firetruck API key. Raises the rate limit above the anonymous per-IP default. Store it as a secret. |
| `fail-on-kev` | `true` | Fail the step on any match. Set to `false` to only annotate and summarize. |
| `concurrency` | `8` | Lookups in flight at once. |
| `api-url` | `https://api.firetruck.dev` | API base URL, for self-hosted instances. |

## Outputs

| Output | Description |
| --- | --- |
| `findings` | JSON array of `{ ecosystem, name, version, files, kevs }` for each matching dependency. |
| `kev-count` | Distinct KEV CVE IDs found. |
| `vulnerable-count` | Distinct dependencies that matched. |
| `checked-count` | Distinct dependencies looked up. |

Each match is also reported as an annotation on the lockfile that declared it, and the job summary lists every match.

## Rate limits

Anonymous lookups are limited per IP, and GitHub-hosted runners share IPs. The action looks up each distinct `name@version` once. If the limit resets within a minute it waits; otherwise it fails with the reset time. Large monorepos should set `api-key`:

```yaml
- uses: firetruck-dev/kev-check@v0
  with:
    api-key: ${{ secrets.FIRETRUCK_API_KEY }}
```

## Development

```sh
npm install
npm run all   # typecheck, test, and bundle to dist/
```

`dist/index.js` is committed because GitHub runs it directly. CI fails if it is stale.
