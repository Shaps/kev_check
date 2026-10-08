import { readFile } from 'node:fs/promises';
import { relative } from 'node:path';
import * as glob from '@actions/glob';
import { autoDetectPatterns, parserFor } from './parsers/index.ts';
import type { Dependency, InventoryEntry } from './types.ts';

const excluded = ['!**/node_modules/**', '!**/vendor/**', '!**/.git/**'];

export async function findFiles(paths: string[]): Promise<string[]> {
  const patterns = paths.length > 0 ? paths : [...autoDetectPatterns, ...excluded];
  const globber = await glob.create(patterns.join('\n'), { matchDirectories: false });
  return (await globber.glob()).sort();
}

export interface ParsedFile {
  file: string;
  dependencies: Dependency[];
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
 * The API matches on name and version only, so the same name@version from two ecosystems is
 * one lookup. The first ecosystem seen is kept for display.
 */
export function buildInventory(parsed: ParsedFile[]): InventoryEntry[] {
  const byKey = new Map<string, InventoryEntry>();
  for (const { file, dependencies } of parsed) {
    for (const dependency of dependencies) {
      const key = `${dependency.name.toLowerCase()}@${dependency.version}`;
      const entry = byKey.get(key) ?? { dependency, files: [] };
      if (!entry.files.includes(file)) entry.files.push(file);
      byKey.set(key, entry);
    }
  }
  return [...byKey.values()];
}
