import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as core from '@actions/core';
import { run, type Inputs } from '../src/main.ts';
import { FiretruckError, type LookupResult } from '../src/client.ts';
import type { Dependency } from '../src/types.ts';

vi.mock('@actions/core', async (importOriginal) => {
  const actual = await importOriginal<typeof core>();
  return { ...actual, setOutput: vi.fn(), setFailed: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() };
});

const inputs = (overrides: Partial<Inputs> = {}): Inputs => ({
  paths: [],
  apiKey: '',
  apiUrl: 'https://api.example.test',
  failOnKev: true,
  concurrency: 4,
  ...overrides,
});

const noKev: LookupResult = { verdict: 'no', kevs: [], unverifiedKevs: [] };
const answers: Record<string, LookupResult> = {
  'npm:jquery@1.12.4': { verdict: 'yes', kevs: ['CVE-2020-11023'], unverifiedKevs: [] },
  'pypi:requests@2.0.0': { verdict: 'yes', kevs: ['CVE-2099-0001'], unverifiedKevs: [] },
  'maven:org.example:lib@1.0': { verdict: 'unverified', kevs: [], unverifiedKevs: ['CVE-2021-0002'] },
  'npm:broken@1.0.0': { verdict: 'unchecked', reason: 'name is not valid' },
};
const fakeLookup = vi.fn(async (deps: Dependency[]) =>
  deps.map((d) => answers[`${d.ecosystem}:${d.name}@${d.version}`] ?? noKev),
);
const sentDependencies = () => fakeLookup.mock.calls.flatMap(([deps]) => deps.map((d) => `${d.ecosystem}:${d.name}@${d.version}`));

let workspace: string;
// core.summary caches the summary path on first write, so every test shares one file.
const summaryFile = join(await mkdtemp(join(tmpdir(), 'firetruck-summary-')), 'summary.md');

beforeEach(async () => {
  vi.clearAllMocks();
  workspace = await mkdtemp(join(tmpdir(), 'firetruck-'));
  await writeFile(summaryFile, '');
  vi.stubEnv('GITHUB_WORKSPACE', workspace);
  vi.stubEnv('GITHUB_STEP_SUMMARY', summaryFile);
  vi.spyOn(process, 'cwd').mockReturnValue(workspace);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

const outputs = () => Object.fromEntries(vi.mocked(core.setOutput).mock.calls);

async function writeWorkspace(files: Record<string, string>) {
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(workspace, path, '..'), { recursive: true });
    await writeFile(join(workspace, path), content);
  }
}

const packageLock = (deps: Record<string, string>) =>
  JSON.stringify({
    lockfileVersion: 3,
    packages: Object.fromEntries(Object.entries(deps).map(([name, version]) => [`node_modules/${name}`, { version }])),
  });

describe('run', () => {
  it('auto-detects lockfiles, dedupes across files, annotates, and fails on a yes verdict', async () => {
    await writeWorkspace({
      'package-lock.json': packageLock({ jquery: '1.12.4', lodash: '4.17.21' }),
      'web/package-lock.json': packageLock({ jquery: '1.12.4' }),
      'node_modules/dep/package-lock.json': packageLock({ ignored: '1.0.0' }),
      'svc/requirements.txt': 'django==4.2.1\n',
    });

    const findings = await run(inputs(), fakeLookup);

    expect(fakeLookup).toHaveBeenCalledTimes(1);
    expect(sentDependencies()).toEqual(['npm:jquery@1.12.4', 'npm:lodash@4.17.21', 'pypi:django@4.2.1']);
    expect(findings).toHaveLength(1);
    expect(outputs()).toMatchObject({
      'kev-count': 1,
      'vulnerable-count': 1,
      'unverified-count': 0,
      'unchecked-count': 0,
      'checked-count': 3,
    });
    expect(JSON.parse(outputs().findings)).toEqual([
      {
        ecosystem: 'npm',
        name: 'jquery',
        version: '1.12.4',
        verdict: 'yes',
        files: ['package-lock.json', 'web/package-lock.json'],
        kevs: ['CVE-2020-11023'],
        unverifiedKevs: [],
      },
    ]);
    expect(core.error).toHaveBeenCalledTimes(2);
    expect(core.error).toHaveBeenCalledWith(
      'jquery@1.12.4 is affected by known exploited CVE-2020-11023',
      expect.objectContaining({ file: 'package-lock.json', startLine: 1 }),
    );
    expect(core.setFailed).toHaveBeenCalledWith('1 dependency matches known exploited vulnerabilities: CVE-2020-11023');

    const summary = await readFile(summaryFile, 'utf8');
    expect(summary).toContain('| `jquery` | 1.12.4 | npm | [CVE-2020-11023]');
    expect(summary).toContain('Checked 3 distinct dependencies from 3 files.');
  });

  it('only warns on a yes verdict when fail-on-kev is false', async () => {
    await writeWorkspace({ 'package-lock.json': packageLock({ jquery: '1.12.4' }) });
    await run(inputs({ failOnKev: false }), fakeLookup);
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('CVE-2020-11023'), expect.anything());
    expect(core.error).not.toHaveBeenCalled();
    expect(core.setFailed).not.toHaveBeenCalled();
  });

  it('passes clean dependency sets', async () => {
    await writeWorkspace({ 'go.mod': 'module x\n\nrequire github.com/a/b v1.0.0\n' });
    await expect(run(inputs(), fakeLookup)).resolves.toEqual([]);
    expect(core.setFailed).not.toHaveBeenCalled();
    expect(await readFile(summaryFile, 'utf8')).toContain('No dependencies matched');
  });

  it('warns on an unverified verdict without failing the step', async () => {
    await writeWorkspace({
      'sbom.cdx.json': JSON.stringify({
        bomFormat: 'CycloneDX',
        components: [{ name: 'lib', group: 'org.example', version: '1.0', purl: 'pkg:maven/org.example/lib@1.0' }],
      }),
    });

    const findings = await run(inputs(), fakeLookup);

    expect(findings.map((f) => [f.dependency.name, f.verdict])).toEqual([['org.example:lib', 'unverified']]);
    expect(core.setFailed).not.toHaveBeenCalled();
    expect(core.error).not.toHaveBeenCalled();
    expect(core.warning).toHaveBeenCalledWith(
      expect.stringContaining('org.example:lib@1.0 is linked to known exploited CVE-2021-0002'),
      expect.objectContaining({ file: 'sbom.cdx.json' }),
    );
    expect(outputs()).toMatchObject({ 'kev-count': 0, 'vulnerable-count': 0, 'unverified-count': 1, 'checked-count': 1 });
    expect(JSON.parse(outputs().findings)).toEqual([
      {
        ecosystem: 'maven',
        name: 'org.example:lib',
        version: '1.0',
        verdict: 'unverified',
        files: ['sbom.cdx.json'],
        kevs: [],
        unverifiedKevs: ['CVE-2021-0002'],
      },
    ]);
    const summary = await readFile(summaryFile, 'utf8');
    expect(summary).toContain('No dependencies matched');
    expect(summary).toContain('### Unverified (1)');
    expect(summary).toContain('| `org.example:lib` | 1.0 | maven | [CVE-2021-0002]');
  });

  it('lists confirmed findings before unverified ones', async () => {
    await writeWorkspace({
      'sbom.cdx.json': JSON.stringify({
        bomFormat: 'CycloneDX',
        components: [
          { name: 'lib', version: '1.0', purl: 'pkg:maven/org.example/lib@1.0' },
          { name: 'jquery', version: '1.12.4', purl: 'pkg:npm/jquery@1.12.4' },
        ],
      }),
    });
    await run(inputs(), fakeLookup);
    expect(JSON.parse(outputs().findings).map((f: { verdict: string }) => f.verdict)).toEqual(['yes', 'unverified']);
    expect(core.setFailed).toHaveBeenCalledTimes(1);
  });

  it('answers the same name@version in two ecosystems independently', async () => {
    await writeWorkspace({
      'package-lock.json': packageLock({ requests: '2.0.0' }),
      'requirements.txt': 'requests==2.0.0\n',
    });

    const findings = await run(inputs(), fakeLookup);

    expect(sentDependencies()).toEqual(['npm:requests@2.0.0', 'pypi:requests@2.0.0']);
    expect(findings.map((f) => [f.dependency.ecosystem, f.files])).toEqual([['pypi', ['requirements.txt']]]);
    expect(outputs()).toMatchObject({ 'checked-count': 2, 'vulnerable-count': 1 });
  });

  it('reports a per-item API error as unchecked, with its reason', async () => {
    await writeWorkspace({ 'package-lock.json': packageLock({ broken: '1.0.0', lodash: '4.17.21' }) });

    await run(inputs(), fakeLookup);

    expect(core.setFailed).not.toHaveBeenCalled();
    expect(outputs()).toMatchObject({ 'unchecked-count': 1, 'checked-count': 1, 'vulnerable-count': 0 });
    const summary = await readFile(summaryFile, 'utf8');
    expect(summary).toContain('### Not checked (1)');
    expect(summary).toContain('| `broken` | 1.0.0 | npm | name is not valid | `package-lock.json` |');
  });

  it('never sends SBOM components in unsupported ecosystems and reports them as unchecked', async () => {
    await writeWorkspace({
      'sbom.cdx.json': JSON.stringify({
        bomFormat: 'CycloneDX',
        components: [
          { name: 'openssl', version: '3.0.11-1', purl: 'pkg:deb/debian/openssl@3.0.11-1' },
          { name: 'mystery', version: '2.0' },
          { name: 'jquery', version: '1.12.4', purl: 'pkg:npm/jquery@1.12.4' },
        ],
      }),
    });

    await run(inputs(), fakeLookup);

    expect(sentDependencies()).toEqual(['npm:jquery@1.12.4']);
    expect(outputs()).toMatchObject({ 'unchecked-count': 2, 'checked-count': 1 });
    const summary = await readFile(summaryFile, 'utf8');
    expect(summary).toContain('| `debian/openssl` | 3.0.11-1 | deb | ecosystem not supported (purl type "deb") | `sbom.cdx.json` |');
    expect(summary).toContain('| `mystery` | 2.0 | unknown | no package URL (purl), so the ecosystem is unknown |');
  });

  it('sends nothing when every dependency is unsupported', async () => {
    await writeWorkspace({
      'sbom.cdx.json': JSON.stringify({ bomFormat: 'CycloneDX', components: [{ name: 'a', version: '1', purl: 'pkg:deb/debian/a@1' }] }),
    });
    await run(inputs(), fakeLookup);
    expect(fakeLookup).not.toHaveBeenCalled();
    expect(outputs()).toMatchObject({ 'unchecked-count': 1, 'checked-count': 0 });
  });

  it('splits large inventories into requests of 100', async () => {
    const deps = Object.fromEntries(Array.from({ length: 250 }, (_, i) => [`pkg-${i}`, '1.0.0']));
    await writeWorkspace({ 'package-lock.json': packageLock(deps) });

    await run(inputs({ concurrency: 1 }), fakeLookup);

    expect(fakeLookup.mock.calls.map(([chunk]) => chunk.length)).toEqual([100, 100, 50]);
    expect(outputs()).toMatchObject({ 'checked-count': 250 });
  });

  it('surfaces a lookup failure such as a rate limit', async () => {
    await writeWorkspace({ 'package-lock.json': packageLock({ lodash: '4.17.21' }) });
    const limited = vi.fn(async () => {
      throw new FiretruckError('rate limited by the Firetruck API.');
    });
    await expect(run(inputs(), limited)).rejects.toThrow(/rate limited/);
  });

  it('scans explicit paths, sniffing SBOMs and warning on unparseable files', async () => {
    await writeWorkspace({
      'out/sbom.json': JSON.stringify({ bomFormat: 'CycloneDX', components: [{ name: 'jquery', version: '1.12.4', purl: 'pkg:npm/jquery@1.12.4' }] }),
      'out/broken.cdx.json': '{not json',
      'package-lock.json': packageLock({ lodash: '4.17.21' }),
    });

    const findings = await run(inputs({ paths: ['out/*.json'] }), fakeLookup);

    expect(findings.map((f) => f.dependency.name)).toEqual(['jquery']);
    expect(sentDependencies()).toEqual(['npm:jquery@1.12.4']);
    expect(core.warning).toHaveBeenCalledWith(expect.stringMatching(/^Skipped out\/broken\.cdx\.json: .*JSON/), {
      file: 'out/broken.cdx.json',
    });
  });

  it('errors clearly when nothing is found', async () => {
    await expect(run(inputs(), fakeLookup)).rejects.toThrow(/no lockfiles or SBOMs found in the workspace/);
  });
});
