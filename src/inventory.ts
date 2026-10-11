import { readFile } from 'node:fs/promises';
import { relative } from 'node:path';
import * as glob from '@actions/glob';
import { autoDetectPatterns, parserFor } from './parsers/index.ts';
import { isUnchecked, type InventoryEntry, type ParsedDependency, type UncheckedEntry } from './types.ts';

const excluded = ['!**/node_modules/**', '!**/vendor/**', '!**/.git/**'];

export async function findFiles(paths: string[]): Promise<string[]> {
  const patterns = paths.length > 0 ? paths : [...autoDetectPatterns, ...excluded];
  const globber = await glob.create(patterns.join('\n'), { matchDirectories: false });
  return (await globber.glob()).sort();
}

export interface ParsedFile {
  file: string;
  dependencies: ParsedDependency[];
}

export interface Skipped {
  file: string;
  reason: string;
}

export async function parseFiles(files: string[], root: string): Promise<{ parsed: ParsedFile[]; skipped: Skipped[] }> {
  const parsed: ParsedFile[] = [];
  const skipped: Skipped[] = [];

  for (const path of files) {
    const file = relative(root, path) || path;
    const content = await readFile(path, 'utf8');
    const parser = parserFor(path, content);
    if (!parser) {
      skipped.push({ file, reason: 'unsupported file type' });
      continue;
    }
    try {
      parsed.push({ file, dependencies: parser(content) });
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
      const key = `${dependency.ecosystem}:${dependency.name.toLowerCase()}@${dependency.version}`;
      const entries = (isUnchecked(dependency) ? unchecked : inventory) as Map<string, InventoryEntry<typeof dependency>>;
      const entry = entries.get(key) ?? { dependency, files: [] };
      if (!entry.files.includes(file)) entry.files.push(file);
      entries.set(key, entry);
    }
  }
  return { inventory: [...inventory.values()], unchecked: [...unchecked.values()] };
}
