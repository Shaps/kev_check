import { readFile, realpath, stat } from 'node:fs/promises';
import { isAbsolute, relative, sep } from 'node:path';
import * as glob from '@actions/glob';
import { autoDetectPatterns, parserFor } from './parsers/index.ts';
import { isUnchecked, type InventoryEntry, type ParsedDependency, type UncheckedEntry } from './types.ts';

const excluded = ['!**/node_modules/**', '!**/vendor/**', '!**/.git/**'];

export async function findFiles(paths: string[]): Promise<string[]> {
  const patterns = paths.length > 0 ? paths : [...autoDetectPatterns, ...excluded];
  const globber = await glob.create(patterns.join('\n'), { matchDirectories: false, followSymbolicLinks: false });
  return (await globber.glob()).sort();
}

export interface ParsedFile {
  file: string;
  content: string;
  dependencies: ParsedDependency[];
}

/** Largest file the action will read; real lockfiles and SBOMs are far smaller. */
export const MAX_FILE_BYTES = 50 * 1024 * 1024;

export interface Skipped {
  file: string;
  reason: string;
}

/**
 * Why a file must not be read, if so. The glob lists symlinks without following them, so each
 * match is resolved here: a link that leaves the workspace, a device such as /dev/zero, or a huge
 * file must not be read, let alone have its content echoed into annotations.
 */
async function refusal(path: string, root: string, maxBytes: number): Promise<string | undefined> {
  const [real, realRoot] = await Promise.all([realpath(path), realpath(root)]);
  const fromRoot = relative(realRoot, real);
  if (fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) return 'resolves outside the workspace';
  const info = await stat(real);
  if (!info.isFile()) return 'not a regular file';
  if (info.size > maxBytes) return `larger than the ${Math.round(maxBytes / (1024 * 1024))} MiB limit`;
  return undefined;
}

export async function parseFiles(
  files: string[],
  root: string,
  maxBytes = MAX_FILE_BYTES,
): Promise<{ parsed: ParsedFile[]; skipped: Skipped[] }> {
  const parsed: ParsedFile[] = [];
  const skipped: Skipped[] = [];

  for (const path of files) {
    const file = relative(root, path) || path;
    const reason = await refusal(path, root, maxBytes);
    if (reason) {
      skipped.push({ file, reason });
      continue;
    }
    const content = await readFile(path, 'utf8');
    const parser = parserFor(path, content);
    if (!parser) {
      skipped.push({ file, reason: 'unsupported file type' });
      continue;
    }
    try {
      parsed.push({ file, content, dependencies: parser(content) });
    } catch (error) {
      skipped.push({ file, reason: error instanceof Error ? error.message : String(error) });
    }
  }
  return { parsed, skipped };
}

/**
 * Dependencies are distinct by ecosystem, name and version: the same name@version in two
 * ecosystems is two lookups. Ones that cannot be looked up are listed separately.
 */
export function buildInventory(parsed: ParsedFile[]): { inventory: InventoryEntry[]; unchecked: UncheckedEntry[] } {
  const inventory = new Map<string, InventoryEntry>();
  const unchecked = new Map<string, UncheckedEntry>();
  for (const { file, dependencies } of parsed) {
    for (const dependency of dependencies) {
      const key = `${dependency.ecosystem}:${dependency.name}@${dependency.version}`;
      const entries = (isUnchecked(dependency) ? unchecked : inventory) as Map<string, InventoryEntry<typeof dependency>>;
      const entry = entries.get(key) ?? { dependency, files: [] };
      if (!entry.files.includes(file)) entry.files.push(file);
      entries.set(key, entry);
    }
  }
  return { inventory: [...inventory.values()], unchecked: [...unchecked.values()] };
}
