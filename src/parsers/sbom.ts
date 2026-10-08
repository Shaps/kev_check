import type { Dependency } from '../types.ts';
import { ecosystemFromPurlType } from './others.ts';

/** Maps a package URL to the name its ecosystem uses, e.g. `pkg:maven/g/a@1` → `g:a`. */
export function fromPurl(purl: string): Dependency | undefined {
  const match = purl.match(/^pkg:([^/]+)\/([^@?#]+)@([^?#]+)/);
  if (!match) return undefined;
  const [, type, path, version] = match as unknown as [string, string, string, string];
  const segments = path.split('/').map(decodeURIComponent);
  const ecosystem = ecosystemFromPurlType[type.toLowerCase()] ?? 'generic';
  const name = ecosystem === 'maven' ? segments.join(':') : ecosystem === 'generic' ? segments.at(-1)! : segments.join('/');
  return { ecosystem, name, version: decodeURIComponent(version) };
}

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

export function parseSbom(content: string): Dependency[] {
  const doc = JSON.parse(content) as Sbom;

  if (doc.bomFormat === 'CycloneDX') {
    const walk = (components: CycloneDXComponent[] = []): Dependency[] =>
      components.flatMap((c) => {
        const own = (c.purl && fromPurl(c.purl)) ||
          (c.name && c.version
            ? { ecosystem: 'generic' as const, name: c.group ? `${c.group}:${c.name}` : c.name, version: c.version }
            : undefined);
        return [...(own ? [own] : []), ...walk(c.components)];
      });
    return walk(doc.components);
  }

  if (doc.spdxVersion) {
    const described = new Set(doc.documentDescribes ?? []);
    return (doc.packages ?? []).flatMap((pkg) => {
      if (pkg.SPDXID && described.has(pkg.SPDXID)) return [];
      const purl = pkg.externalRefs?.find((ref) => ref.referenceType === 'purl')?.referenceLocator;
      const dep = (purl && fromPurl(purl)) ||
        (pkg.name && pkg.versionInfo ? { ecosystem: 'generic' as const, name: pkg.name, version: pkg.versionInfo } : undefined);
      return dep ? [dep] : [];
    });
  }

  throw new Error('not a CycloneDX or SPDX JSON document');
}
