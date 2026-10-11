import { parse as parseToml } from 'smol-toml';
import type { Dependency, Ecosystem } from '../types.ts';

/** go.mod lists the versions the build actually selects; go.sum also holds stale ones. */
export function parseGoMod(content: string): Dependency[] {
  const deps: Dependency[] = [];
  let inRequire = false;

  for (const raw of content.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, '').trim();
    if (line.startsWith('require (')) inRequire = true;
    else if (inRequire && line === ')') inRequire = false;
    else {
      const spec = inRequire ? line : line.match(/^require\s+(.*)$/)?.[1];
      const [name, version] = spec?.split(/\s+/) ?? [];
      if (name && version) deps.push({ ecosystem: 'golang', name, version });
    }
  }
  return deps;
}

/** PEP 503 normalization, so `Django_REST.framework` and `django-rest-framework` compare equal. */
export const pypiName = (name: string) => name.toLowerCase().replace(/[-_.]+/g, '-');

/** Only exact pins (`==`) resolve to one version; ranges are skipped rather than guessed. */
export function parseRequirements(content: string): Dependency[] {
  return content.split(/\r?\n/).flatMap((raw) => {
    const line = raw.replace(/(^|\s)#.*$/, '').split(';')[0]!.trim();
    const match = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s,\\]+)$/);
    return match ? [{ ecosystem: 'pypi' as const, name: pypiName(match[1]!), version: match[2]! }] : [];
  });
}

export function parsePipfileLock(content: string): Dependency[] {
  const lock = JSON.parse(content) as Record<string, Record<string, { version?: string }>>;
  return [lock.default, lock.develop].flatMap((section) =>
    Object.entries(section ?? {}).flatMap(([name, pkg]) =>
      pkg.version?.startsWith('==')
        ? [{ ecosystem: 'pypi' as const, name: pypiName(name), version: pkg.version.slice(2) }]
        : [],
    ),
  );
}

interface TomlPackage {
  name?: string;
  version?: string;
  source?: unknown;
}

function tomlPackages(content: string): TomlPackage[] {
  const doc = parseToml(content) as { package?: TomlPackage[] };
  return doc.package ?? [];
}

/** poetry.lock and uv.lock share the `[[package]]` shape; uv also lists the local project itself. */
export function parsePythonTomlLock(content: string): Dependency[] {
  return tomlPackages(content).flatMap(({ name, version, source }) => {
    const local = typeof source === 'object' && source !== null && ('editable' in source || 'virtual' in source);
    return name && version && !local ? [{ ecosystem: 'pypi' as const, name: pypiName(name), version }] : [];
  });
}

/** Workspace crates have no `source`; only registry and git crates are third-party. */
export function parseCargoLock(content: string): Dependency[] {
  return tomlPackages(content).flatMap(({ name, version, source }) =>
    name && version && source ? [{ ecosystem: 'cargo' as const, name, version }] : [],
  );
}

export function parseGemfileLock(content: string): Dependency[] {
  const deps: Dependency[] = [];
  let section = '';

  for (const line of content.split(/\r?\n/)) {
    if (/^\S/.test(line)) section = line.trim();
    const match = section === 'GEM' && line.match(/^ {4}([^\s(]+) \(([^)\s]+)\)$/);
    if (match) {
      const version = match[2]!.replace(/-(x86|x64|arm|aarch|universal|java|mingw|mswin|darwin|linux).*$/, '');
      deps.push({ ecosystem: 'gem', name: match[1]!, version });
    }
  }
  return deps;
}

export function parseComposerLock(content: string): Dependency[] {
  const lock = JSON.parse(content) as Record<string, { name?: string; version?: string }[] | undefined>;
  return [...(lock.packages ?? []), ...(lock['packages-dev'] ?? [])].flatMap(({ name, version }) =>
    name && version && !version.startsWith('dev-')
      ? [{ ecosystem: 'composer' as const, name, version: version.replace(/^v/, '') }]
      : [],
  );
}

export const ecosystemFromPurlType: Record<string, Ecosystem> = {
  npm: 'npm',
  golang: 'golang',
  pypi: 'pypi',
  cargo: 'cargo',
  gem: 'gem',
  composer: 'composer',
  maven: 'maven',
  nuget: 'nuget',
};
