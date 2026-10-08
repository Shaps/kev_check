import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as core from '@actions/core';
import { run, type Inputs } from '../src/main.ts';
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

const knownExploited: Record<string, string[]> = { 'jquery@1.12.4': ['CVE-2020-11023'] };
const fakeLookup = vi.fn(async (d: Dependency) => knownExploited[`${d.name}@${d.version}`] ?? []);

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
  it('auto-detects lockfiles, dedupes across files, annotates, and fails on a KEV', async () => {
    await writeWorkspace({
      'package-lock.json': packageLock({ jquery: '1.12.4', lodash: '4.17.21' }),
      'web/package-lock.json': packageLock({ jquery: '1.12.4' }),
      'node_modules/dep/package-lock.json': packageLock({ ignored: '1.0.0' }),
      'svc/requirements.txt': 'django==4.2.1\n',
    });

    const findings = await run(inputs(), fakeLookup);

    expect(fakeLookup).toHaveBeenCalledTimes(3);
    expect(findings).toHaveLength(1);
    expect(outputs()).toMatchObject({ 'kev-count': 1, 'vulnerable-count': 1, 'checked-count': 3 });
    expect(JSON.parse(outputs().findings)).toEqual([
      {
        ecosystem: 'npm',
        name: 'jquery',
        version: '1.12.4',
        files: ['package-lock.json', 'web/package-lock.json'],
        kevs: ['CVE-2020-11023'],
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

  it('only warns when fail-on-kev is false', async () => {
    await writeWorkspace({ 'package-lock.json': packageLock({ jquery: '1.12.4' }) });
    await run(inputs({ failOnKev: false }), fakeLookup);
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('CVE-2020-11023'), expect.anything());
    expect(core.setFailed).not.toHaveBeenCalled();
  });

  it('passes clean dependency sets', async () => {
    await writeWorkspace({ 'go.mod': 'module x\n\nrequire github.com/a/b v1.0.0\n' });
    await expect(run(inputs(), fakeLookup)).resolves.toEqual([]);
    expect(core.setFailed).not.toHaveBeenCalled();
    expect(await readFile(summaryFile, 'utf8')).toContain('No dependencies matched');
  });

  it('scans explicit paths, sniffing SBOMs and warning on unparseable files', async () => {
    await writeWorkspace({
      'out/sbom.json': JSON.stringify({ bomFormat: 'CycloneDX', components: [{ name: 'jquery', version: '1.12.4', purl: 'pkg:npm/jquery@1.12.4' }] }),
      'out/broken.cdx.json': '{not json',
      'package-lock.json': packageLock({ lodash: '4.17.21' }),
    });

    const findings = await run(inputs({ paths: ['out/*.json'] }), fakeLookup);

    expect(findings.map((f) => f.dependency.name)).toEqual(['jquery']);
    expect(fakeLookup).toHaveBeenCalledTimes(1);
    expect(core.warning).toHaveBeenCalledWith(expect.stringMatching(/^Skipped out\/broken\.cdx\.json: .*JSON/), {
      file: 'out/broken.cdx.json',
    });
  });

  it('errors clearly when nothing is found', async () => {
    await expect(run(inputs(), fakeLookup)).rejects.toThrow(/no lockfiles or SBOMs found in the workspace/);
  });
});
