import * as core from '@actions/core';
import { createClient, lookupAll, type Lookup } from './client.ts';
import { buildInventory, findFiles, parseFiles, type ParsedFile, type Skipped } from './inventory.ts';
import { isKnownLockfile } from './parsers/index.ts';
import { distinctKevs, lineOf, renderSummary } from './report.ts';
import { isUnchecked, type Finding, type UncheckedEntry } from './types.ts';

export interface Inputs {
  paths: string[];
  apiKey: string;
  failOnKev: boolean;
  failOnSkipped: boolean;
  failOnUnchecked: boolean;
  concurrency: number;
}

export function readInputs(): Inputs {
  const concurrency = Number(core.getInput('concurrency') || '8');
  if (!Number.isInteger(concurrency) || concurrency < 1) {
    throw new Error(`concurrency must be a positive integer, got "${core.getInput('concurrency')}"`);
  }
  const apiKey = core.getInput('api-key');
  if (apiKey) core.setSecret(apiKey);
  return {
    paths: core.getMultilineInput('paths').filter(Boolean),
    apiKey,
    failOnKev: core.getBooleanInput('fail-on-kev'),
    failOnSkipped: core.getBooleanInput('fail-on-skipped'),
    failOnUnchecked: core.getBooleanInput('fail-on-unchecked'),
    concurrency,
  };
}

/**
 * A green run that checked nothing is a silent pass. When nothing at all could be checked, a
 * recognized lockfile that parsed to no dependencies is a failure. An SBOM with no components is
 * not a lockfile and may still pass. Skipped files are reported separately at the end of the run.
 */
function emptyLockfileFailure(parsed: ParsedFile[]): string | undefined {
  const emptyLocks = parsed
    .filter((entry) => isKnownLockfile(entry.file) && !entry.dependencies.some((dep) => !isUnchecked(dep)))
    .map((entry) => entry.file);
  return emptyLocks.length === 0 ? undefined : `recognized lockfile(s) parsed to no dependencies: ${emptyLocks.join(', ')}`;
}

export async function run(inputs: Inputs, lookup: Lookup = createClient(inputs)): Promise<Finding[]> {
  const root = process.env.GITHUB_WORKSPACE ?? process.cwd();
  const files = await findFiles(inputs.paths);
  if (files.length === 0) {
    const where = inputs.paths.length > 0 ? `matching ${inputs.paths.join(', ')}` : 'in the workspace';
    throw new Error(`no lockfiles or SBOMs found ${where}. Set the paths input to point at them.`);
  }

  const { parsed, skipped } = await parseFiles(files, root);
  for (const { file, reason } of skipped) core.warning(`Skipped ${file}: ${reason}`, { file });
  const { inventory, unchecked: unsupported } = buildInventory(parsed);
  if (inventory.length === 0 && inputs.failOnSkipped) {
    const failure = emptyLockfileFailure(parsed);
    if (failure) throw new Error(failure);
  }
  core.info(`Checking ${inventory.length} distinct dependencies from ${parsed.length} files.`);

  const results = await lookupAll(lookup, inventory.map((entry) => entry.dependency), inputs.concurrency);
  const findings: Finding[] = [];
  const unchecked: UncheckedEntry[] = [...unsupported];
  let checked = 0;
  inventory.forEach((entry, i) => {
    const result = results[i]!;
    if (result.verdict === 'unchecked') {
      unchecked.push({ dependency: { ...entry.dependency, reason: result.reason }, files: entry.files });
      return;
    }
    checked++;
    if (result.verdict !== 'no') {
      findings.push({ ...entry, verdict: result.verdict, kevs: result.kevs, unverifiedKevs: result.unverifiedKevs });
    }
  });
  // Confirmed findings first, then unverified ones; each group by name.
  findings.sort((a, b) => (a.verdict === b.verdict ? 0 : a.verdict === 'yes' ? -1 : 1) || a.dependency.name.localeCompare(b.dependency.name));
  const vulnerable = findings.filter((f) => f.verdict === 'yes');
  const unverified = findings.filter((f) => f.verdict === 'unverified');

  const contents = new Map(parsed.map((p) => [p.file, p.content]));
  const annotate = inputs.failOnKev ? core.error : core.warning;
  for (const { dependency: d, verdict, kevs, unverifiedKevs, files: declaredIn } of findings) {
    for (const file of declaredIn) {
      const location = { file, startLine: lineOf(contents.get(file)!, d.name, d.version) };
      if (verdict === 'yes') {
        annotate(`${d.name}@${d.version} is affected by known exploited ${kevs.join(', ')}`, {
          title: 'Known exploited vulnerability',
          ...location,
        });
      } else {
        const linked = unverifiedKevs.length > 0 ? ` known exploited ${unverifiedKevs.join(', ')}` : ' a known exploited vulnerability';
        core.warning(`${d.name}@${d.version} is linked to${linked}, but its affected versions could not be compared`, {
          title: 'Unverified known exploited vulnerability',
          ...location,
        });
      }
    }
  }
  const uncheckedMessage =
    `${unchecked.length} ${unchecked.length === 1 ? 'dependency was' : 'dependencies were'} not checked; the job summary lists them with the reason.`;
  if (unchecked.length > 0) core.warning(uncheckedMessage);

  core.setOutput('findings', JSON.stringify(findings.map(({ dependency, verdict, files, kevs, unverifiedKevs }) => ({ ...dependency, verdict, files, kevs, unverifiedKevs }))));
  core.setOutput('kev-count', distinctKevs(vulnerable).length);
  core.setOutput('vulnerable-count', vulnerable.length);
  core.setOutput('unverified-count', unverified.length);
  core.setOutput('unchecked-count', unchecked.length);
  core.setOutput('checked-count', checked);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await core.summary.addRaw(renderSummary({ findings, checked, unchecked, files: parsed.map((p) => p.file), skipped })).write();
  }

  if (vulnerable.length > 0 && inputs.failOnKev) {
    const noun = vulnerable.length === 1 ? 'dependency matches' : 'dependencies match';
    core.setFailed(`${vulnerable.length} ${noun} known exploited vulnerabilities: ${distinctKevs(vulnerable).join(', ')}`);
  }
  if (inputs.failOnSkipped && skipped.length > 0) {
    core.setFailed(`${skipped.length} ${skipped.length === 1 ? 'file was' : 'files were'} skipped: ${skipped.map((s) => s.file).join(', ')}`);
  }
  if (inputs.failOnUnchecked && unchecked.length > 0) core.setFailed(uncheckedMessage);
  return findings;
}
