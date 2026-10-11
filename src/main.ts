import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import * as core from '@actions/core';
import { createClient, lookupAll, type Lookup } from './client.ts';
import { buildInventory, findFiles, parseFiles } from './inventory.ts';
import { distinctKevs, lineOf, renderSummary } from './report.ts';
import type { Finding, UncheckedEntry } from './types.ts';

export interface Inputs {
  paths: string[];
  apiKey: string;
  failOnKev: boolean;
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
    concurrency,
  };
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

  const annotate = inputs.failOnKev ? core.error : core.warning;
  for (const { dependency: d, verdict, kevs, unverifiedKevs, files: declaredIn } of findings) {
    for (const file of declaredIn) {
      const content = await readFile(resolve(root, file), 'utf8');
      const location = { file, startLine: lineOf(content, d.name, d.version) };
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
  if (unchecked.length > 0) {
    const noun = unchecked.length === 1 ? 'dependency was' : 'dependencies were';
    core.warning(`${unchecked.length} ${noun} not checked; the job summary lists them with the reason.`);
  }

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
  return findings;
}
