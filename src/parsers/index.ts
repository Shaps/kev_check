import { basename } from 'node:path';
import type { Parser } from '../types.ts';
import { parseBunLock, parsePackageLock, parsePnpmLock, parseYarnLock } from './npm.ts';
import {
  parseCargoLock,
  parseComposerLock,
  parseGemfileLock,
  parseGoMod,
  parseGradleLockfile,
  parsePipfileLock,
  parsePythonTomlLock,
  parseRequirements,
} from './others.ts';
import { isSbom, parseSbom } from './sbom.ts';

const lockfiles: Record<string, Parser> = {
  'package-lock.json': parsePackageLock,
  'npm-shrinkwrap.json': parsePackageLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'yarn.lock': parseYarnLock,
  'bun.lock': parseBunLock,
  'go.mod': parseGoMod,
  'requirements.txt': parseRequirements,
  'Pipfile.lock': parsePipfileLock,
  'poetry.lock': parsePythonTomlLock,
  'uv.lock': parsePythonTomlLock,
  'Cargo.lock': parseCargoLock,
  'Gemfile.lock': parseGemfileLock,
  'composer.lock': parseComposerLock,
  'gradle.lockfile': parseGradleLockfile,
};

const requirementsTxt = /^requirements.*\.txt$/;

/** True for a registered lockfile name, including `requirements*.txt`. SBOMs are not lockfiles. */
export function isKnownLockfile(path: string): boolean {
  const name = basename(path);
  return Object.hasOwn(lockfiles, name) || requirementsTxt.test(name);
}

/** Glob patterns for auto-detection when the `paths` input is empty. */
export const autoDetectPatterns = [
  ...Object.keys(lockfiles).map((name) => `**/${name}`),
  '**/requirements*.txt',
  '**/*.cdx.json',
  '**/bom.json',
  '**/*.spdx.json',
];

/** Picks a parser by filename, falling back to sniffing JSON for an SBOM. */
export function parserFor(path: string, content: string): Parser | undefined {
  const name = basename(path);
  if (lockfiles[name]) return lockfiles[name];
  if (requirementsTxt.test(name)) return parseRequirements;
  if (/(\.cdx|\.spdx)\.json$|^bom\.json$/.test(name)) return parseSbom;
  if (name.endsWith('.json') && isSbom(content)) return parseSbom;
  return undefined;
}
