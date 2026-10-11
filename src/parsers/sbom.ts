import type { ParsedDependency, UncheckedDependency } from '../types.ts';
import { ecosystemFromPurlType, pypiName } from './others.ts';

const unchecked = (ecosystem: string, name: string, version: string, reason: string): UncheckedDependency => ({
  ecosystem,
  name,
  version,
  reason,
});

/**
 * Maps a package URL to the name its ecosystem uses, e.g. `pkg:maven/g/a@1` → `g:a`.
 * Purl types outside the supported ecosystems come back unchecked, never as a guessed lookup.
 */
export function fromPurl(purl: string): ParsedDependency | undefined {
  const match = purl.match(/^pkg:([^/]+)\/([^?#]+)/);
  if (!match) return undefined;
  const [, rawType, rest] = match as unknown as [string, string, string];
  // A scope's `@` is only ever at index 0, so the last `@` separates the version.
  const at = rest.lastIndexOf('@');
  if (at <= 0 || at === rest.length - 1) return undefined;

  const type = rawType.toLowerCase();
  let segments: string[];
  let version: string;
  try {
    segments = rest.slice(0, at).split('/').map(decodeURIComponent);
    version = decodeURIComponent(rest.slice(at + 1));
  } catch {
    return unchecked(type, rest.slice(0, at), rest.slice(at + 1), 'invalid package URL encoding');
  }

  const ecosystem = ecosystemFromPurlType[type];
  if (!ecosystem) {
    return unchecked(type, segments.join('/'), version, `ecosystem not supported (purl type "${type}")`);
  }
  if (ecosystem === 'maven') {
    if (segments.length !== 2) return unchecked(type, segments.join('/'), version, 'Maven package URL needs a group and an artifact');
    return { ecosystem, name: segments.join(':'), version };
  }
  const name = segments.join('/');
  return { ecosystem, name: ecosystem === 'pypi' ? pypiName(name) : name, version };
}

/** A component without a usable purl has no known ecosystem, so it cannot be looked up. */
const noPurl = (name: string, version: string) => unchecked('unknown', name, version, 'no package URL (purl), so the ecosystem is unknown');

interface CycloneDXComponent {
  name?: string;
  version?: string;
  group?: string;
  purl?: string;
  components?: CycloneDXComponent[];
}

interface SpdxPackage {
  SPDXID?: string;
  name?: string;
  versionInfo?: string;
  externalRefs?: { referenceType?: string; referenceLocator?: string }[];
}

interface Sbom {
  bomFormat?: string;
  components?: CycloneDXComponent[];
  spdxVersion?: string;
  packages?: SpdxPackage[];
  documentDescribes?: string[];
}

export function isSbom(content: string): boolean {
  try {
    const doc = JSON.parse(content) as Sbom;
    return doc.bomFormat === 'CycloneDX' || typeof doc.spdxVersion === 'string';
  } catch {
    return false;
  }
}

export function parseSbom(content: string): ParsedDependency[] {
  const doc = JSON.parse(content) as Sbom;

  if (doc.bomFormat === 'CycloneDX') {
    const walk = (components: CycloneDXComponent[] = []): ParsedDependency[] =>
      components.flatMap((c) => {
        const own = (c.purl && fromPurl(c.purl)) || (c.name && c.version ? noPurl(c.group ? `${c.group}:${c.name}` : c.name, c.version) : undefined);
        return [...(own ? [own] : []), ...walk(c.components)];
      });
    return walk(doc.components);
  }

  if (doc.spdxVersion) {
    const described = new Set(doc.documentDescribes ?? []);
    return (doc.packages ?? []).flatMap((pkg) => {
      if (pkg.SPDXID && described.has(pkg.SPDXID)) return [];
      const purl = pkg.externalRefs?.find((ref) => ref.referenceType === 'purl')?.referenceLocator;
      const dep = (purl && fromPurl(purl)) || (pkg.name && pkg.versionInfo ? noPurl(pkg.name, pkg.versionInfo) : undefined);
      return dep ? [dep] : [];
    });
  }

  throw new Error('not a CycloneDX or SPDX JSON document');
}
