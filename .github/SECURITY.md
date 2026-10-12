# Security policy

This action is in beta. It runs inside your CI, with access to your checkout and, if you set it, a Firetruck API key, so security reports are taken seriously.

## Supported versions

Only the latest release is supported. Fixes ship as a new `v0.x` release, and the `v0` tag is moved to it.

| Version | Supported |
| --- | --- |
| Latest `v0.x` | Yes |
| Older releases | No |

## Reporting a vulnerability

Please report vulnerabilities privately. Do not open a public issue, pull request or discussion for them.

Use GitHub's private reporting: go to the [Security tab](https://github.com/shaps/kev_check/security/advisories/new) and click **Report a vulnerability**. Only the maintainer can see the report.

Please include:

- the action version, or commit SHA, you tested
- a minimal workflow and input files (lockfile, SBOM) that reproduce the problem
- what an attacker can do with it, and under which conditions (for example, a pull request from a fork)

## What to expect

This project has a single maintainer, so responses are best-effort:

- an acknowledgement within about 7 days
- an assessment and a status update within about 30 days
- a fix released as a new version, then a published GitHub security advisory crediting you, unless you prefer to stay anonymous

Please give me a chance to release a fix before you disclose publicly. I will coordinate the disclosure timing with you.

## Scope

In scope, meaning the code in this repository and the published `dist/`:

- leaking the `api-key` input or the `GITHUB_TOKEN`
- injection through crafted file paths, package names, versions or lockfile contents, for example into the job summary or annotations
- reading files outside the workspace
- resource exhaustion from a crafted lockfile or SBOM
- weaknesses in the build or release workflows that could be used to tamper with the published action

Out of scope:

- A wrong, missing or `unverified` verdict. This is a normal bug, so open a public issue.
- Vulnerabilities in the Firetruck API or website. They are not part of this repository.
- Vulnerabilities in the dependencies of the projects you scan. Reporting those is what this action is for.
