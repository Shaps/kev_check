# Fail the step when a file is skipped, warn when a dependency is unchecked

A green run must not hide input the action could not read. Any skipped file (unsupported type, malformed content, symlink or oversized file rejected before reading) fails the step by default, and `fail-on-skipped: false` opts out. The same input governs the "checked nothing" failure for a recognized lockfile that parsed to no dependencies.

Unchecked dependencies (unsupported ecosystem, or an entry the API rejected) and unverified verdicts only warn by default, because unsupported ecosystems are routine in real repositories and failing on them would make the action unusable. `fail-on-unchecked: true` opts in to failing on any unchecked dependency; unverified stays warn-only.

## Consequences

Flipping the `fail-on-skipped` default later breaks builds that rely on either behaviour, so the defaults are part of the public contract.
