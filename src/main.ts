import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import * as core from '@actions/core';
import { createClient, mapConcurrent, type Lookup } from './client.ts';
import { buildInventory, findFiles, parseFiles } from './inventory.ts';
import { distinctKevs, lineOf, renderSummary } from './report.ts';
import type { Finding } from './types.ts';

export interface Inputs {
  paths: string[];
  apiKey: string;
  apiUrl: string;
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
    apiUrl: core.getInput('api-url') || 'https://api.firetruck.dev',
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
  const inventory = buildInventory(parsed);
  core.info(`Checking ${inventory.length} distinct dependencies from ${parsed.length} files.`);

  const kevsPerEntry = await mapConcurrent(inventory, inputs.concurrency, (entry) => lookup(entry.dependency));
  const findings = inventory
    .map((entry, i) => ({ ...entry, kevs: kevsPerEntry[i]! }))
    .filter((f) => f.kevs.length > 0)
    .sort((a, b) => a.dependency.name.localeCompare(b.dependency.name));

  const annotate = inputs.failOnKev ? core.error : core.warning;
  for (const { dependency: d, kevs, files: declaredIn } of findings) {
    for (const file of declaredIn) {
      const content = await readFile(resolve(root, file), 'utf8');
      annotate(`${d.name}@${d.version} is affected by known exploited ${kevs.join(', ')}`, {
        title: 'Known exploited vulnerability',
        file,
        startLine: lineOf(content, d.name, d.version),
      });
    }
  }

  core.setOutput('findings', JSON.stringify(findings.map(({ dependency, files, kevs }) => ({ ...dependency, files, kevs }))));
  core.setOutput('kev-count', distinctKevs(findings).length);
  core.setOutput('vulnerable-count', findings.length);
  core.setOutput('checked-count', inventory.length);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await core.summary.addRaw(renderSummary(findings, inventory, parsed.map((p) => p.file), skipped)).write();
  }

  if (findings.length > 0 && inputs.failOnKev) {
    const noun = findings.length === 1 ? 'dependency matches' : 'dependencies match';
    core.setFailed(`${findings.length} ${noun} known exploited vulnerabilities: ${distinctKevs(findings).join(', ')}`);
  }
  return findings;
}
