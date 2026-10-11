/** The ecosystem IDs the Firetruck API accepts for lookups. */
export type Ecosystem = 'maven' | 'npm' | 'pypi' | 'golang' | 'gem' | 'nuget' | 'cargo' | 'composer';

/** A resolved dependency, named the way its ecosystem names it (Maven as `group:artifact`). */
export interface Dependency {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

/**
 * A dependency that is never sent to the API: its ecosystem is not supported, or the API
 * rejected the item. `ecosystem` is the purl type (or `unknown`) for unsupported ones.
 */
export interface UncheckedDependency {
  ecosystem: string;
  name: string;
  version: string;
  reason: string;
}

export type ParsedDependency = Dependency | UncheckedDependency;

export const isUnchecked = (dependency: ParsedDependency): dependency is UncheckedDependency => 'reason' in dependency;

/** Every distinct ecosystem + name + version found across the scanned files, with the files that declared it. */
export interface InventoryEntry<D = Dependency> {
  dependency: D;
  files: string[];
}

export type UncheckedEntry = InventoryEntry<UncheckedDependency>;

/** `yes`: a KEV affects this version. `unverified`: a linked KEV could not be compared. */
export interface Finding extends InventoryEntry {
  verdict: 'yes' | 'unverified';
  /** KEV CVEs confirmed to affect this version; always empty for `unverified`. */
  kevs: string[];
  /** KEV CVEs linked to the package whose affected range could not be compared. */
  unverifiedKevs: string[];
}

export type Parser = (content: string) => ParsedDependency[];
