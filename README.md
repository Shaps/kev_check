# Firetruck KEV check

A GitHub Action that fails CI when a locked dependency is affected by a [CISA Known Exploited Vulnerability](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). It reads your lockfiles or SBOM and checks every resolved package against the [Firetruck](https://firetruck.dev) API.

> [!WARNING]
> This action is in beta. It may fail or misbehave unexpectedly, and a green run is not a guarantee that your dependencies are free of known exploited vulnerabilities. Please [report problems](https://github.com/shaps/kev_check/issues/new/choose), including false positives, missed vulnerabilities and unsupported lockfile formats.

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
| Maven, Gradle | No native parser. Generate a CycloneDX SBOM first; see [Maven and Gradle](#maven-and-gradle). |

SBOM components are identified by their package URL (purl). A component whose purl type is not one of the supported ecosystems below, or that has no purl, is not checked; see [Verdicts](#verdicts).

Only JSON SBOMs are read: CycloneDX XML (`bom.xml`) and SPDX tag-value files are not. Auto-detection never picks up other files. If `paths` names one, such as `pom.xml`, `build.gradle`, `build.gradle.kts`, or `gradle.lockfile`, it is skipped with a warning.

## Maven and Gradle

The action does not read `pom.xml`, `build.gradle`, `build.gradle.kts`, or `gradle.lockfile`. A repository with only those files fails with `no lockfiles or SBOMs found in the workspace`. Generate a CycloneDX JSON SBOM in an earlier step and point `paths` at it.

Generate the SBOM with your build tool. Maven or Gradle resolves the full dependency tree, so the SBOM has every transitive dependency at the version your build actually uses, including versions set by a parent POM or a BOM.

### Maven

The [CycloneDX Maven plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin) runs without any change to `pom.xml`:

```yaml
- uses: actions/checkout@v5
- uses: actions/setup-java@v5
  with:
    distribution: temurin
    java-version: '17'
    cache: maven
- run: mvn -B -q org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom -DoutputFormat=json
- uses: shaps/kev_check@v0
  with:
    paths: target/bom.json
```

`makeAggregateBom` writes a single SBOM covering every module of the build to `target/bom.json` in the directory where Maven runs. It leaves out test-scoped dependencies by default.

### Gradle

Apply the [CycloneDX Gradle plugin](https://github.com/CycloneDX/cyclonedx-gradle-plugin) to the root project. By default it scans every resolvable configuration, test ones included, so limit it to `runtimeClasspath`:

```kotlin
// build.gradle.kts
plugins {
    id("org.cyclonedx.bom") version "3.5.1"
}

tasks.cyclonedxDirectBom {
    includeConfigs = listOf("runtimeClasspath")
}
```

```groovy
// build.gradle
plugins {
    id 'org.cyclonedx.bom' version '3.5.1'
}

tasks.cyclonedxDirectBom {
    includeConfigs = ['runtimeClasspath']
}
```

In a multi-project build, configure `cyclonedxDirectBom` in each subproject as well; see the plugin's README. Then run the aggregate task before the action:

```yaml
- uses: actions/checkout@v5
- uses: actions/setup-java@v5
  with:
    distribution: temurin
    java-version: '17'
    cache: gradle
- run: ./gradlew cyclonedxBom
- uses: shaps/kev_check@v0
  with:
    paths: build/reports/cyclonedx/*.json
```

The aggregate SBOM is written to `build/reports/cyclonedx/bom.json`. Spring Boot renames it to `application.cdx.json`, and the glob above matches both names.

#### Gradle dependency locking

The action cannot read `gradle.lockfile` directly. If you already commit one, [Syft](https://github.com/anchore/syft) can convert it to an SBOM without running Gradle:

```yaml
- uses: actions/checkout@v5
- uses: anchore/sbom-action@v0
  with:
    file: gradle.lockfile
    format: cyclonedx-json
    output-file: gradle.cdx.json
    upload-artifact: false
- uses: shaps/kev_check@v0
  with:
    paths: gradle.cdx.json
```

The lockfile holds every locked configuration, so the SBOM includes test dependencies unless you lock only `runtimeClasspath`. Each Gradle project has its own lockfile, so a multi-project build needs one conversion per lockfile.

### Do not scan the source tree

A generic scanner run on the checked-out sources, such as `anchore/sbom-action` with its default `path: .`, reads `pom.xml` without resolving it. Transitive dependencies are missing, versions inherited from a parent POM or a BOM come out as `UNKNOWN`, and Gradle build scripts are not read at all. The action reports those components as not checked, and the step can pass while checking almost nothing. Generate the SBOM with Maven or Gradle as shown above.

### Fail when nothing was checked

If `paths` matches only files the action cannot parse, such as a `pom.xml` or `gradle.lockfile`, they are skipped with a warning and the step passes with `checked-count` set to `0`. The same happens with an SBOM that lists no components. To fail in that case:

```yaml
- id: kev
  uses: shaps/kev_check@v0
  with:
    paths: target/bom.json
- if: steps.kev.outputs.checked-count == '0'
  run: |
    echo "::error::kev_check did not check any dependencies"
    exit 1
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
