export type Ecosystem =
  | 'npm'
  | 'golang'
  | 'pypi'
  | 'cargo'
  | 'rubygems'
  | 'composer'
  | 'maven'
  | 'nuget'
  | 'generic';

/** A resolved dependency, named the way its ecosystem names it (Maven as `group:artifact`). */
export interface Dependency {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

/** Every distinct name@version found across the scanned files, with the files that declared it. */
export interface InventoryEntry {
  dependency: Dependency;
  files: string[];
}

export interface Finding extends InventoryEntry {
  kevs: string[];
}

export type Parser = (content: string) => Dependency[];
