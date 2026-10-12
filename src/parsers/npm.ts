import { parseAllDocuments } from "yaml";
import type { Dependency } from "../types.ts";

const npm = (name: string, version: string): Dependency => ({ ecosystem: "npm", name, version });

/** Splits `name@version`, where a leading `@` belongs to the scope, not the separator. */
export function splitAtVersion(spec: string): [string, string] | undefined {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return undefined;
  return [spec.slice(0, at), spec.slice(at + 1)];
}

interface PackageLockV1Dep {
  version?: string;
  dependencies?: Record<string, PackageLockV1Dep>;
}

interface PackageLock {
  packages?: Record<string, { version?: string; link?: boolean; name?: string }>;
  dependencies?: Record<string, PackageLockV1Dep>;
}

export function parsePackageLock(content: string): Dependency[] {
  const lock = JSON.parse(content) as PackageLock;

  if (lock.packages) {
    return Object.entries(lock.packages).flatMap(([path, pkg]) => {
      const marker = path.lastIndexOf("node_modules/");
      if (marker === -1 || pkg.link || !pkg.version) return [];
      const name = pkg.name ?? path.slice(marker + "node_modules/".length);
      return [npm(name, pkg.version)];
    });
  }

  const walk = (deps: Record<string, PackageLockV1Dep> = {}): Dependency[] =>
    Object.entries(deps).flatMap(([name, dep]) => [
      ...(dep.version && !dep.version.includes(":") ? [npm(name, dep.version)] : []),
      ...walk(dep.dependencies),
    ]);
  return walk(lock.dependencies);
}

/** pnpm 10+ may prepend a separate YAML document (env lockfile) before the main one; collect packages from all. */
export function parsePnpmLock(content: string): Dependency[] {
  const keys = parseAllDocuments(content).flatMap((doc) => {
    if (doc.errors.length) throw doc.errors[0];
    const lock = doc.toJS() as { packages?: Record<string, unknown> } | null;
    return Object.keys(lock?.packages ?? {});
  });
  return keys.flatMap((key) => {
    const spec = key.replace(/^\//, "").replace(/\(.*$/, "");
    const split = splitAtVersion(spec);
    if (split) return [npm(...split)];
    // pnpm lockfile v5 keys look like `/name/1.2.3` or `/@scope/name/1.2.3`.
    const slash = spec.lastIndexOf("/");
    return slash > 0 ? [npm(spec.slice(0, slash), spec.slice(slash + 1))] : [];
  });
}

/** Handles both Yarn classic (`version "1.2.3"`) and Berry (`version: 1.2.3`) lockfiles. */
export function parseYarnLock(content: string): Dependency[] {
  const deps: Dependency[] = [];
  let name: string | undefined;

  for (const line of content.split(/\r?\n/)) {
    if (line && !line.startsWith(" ") && !line.startsWith("#") && line.endsWith(":")) {
      const first = line.slice(0, -1).split(",")[0]!.trim().replace(/^"|"$/g, "");
      const split = splitAtVersion(first);
      name = split && !/^(workspace|link|portal|file):/.test(split[1]) ? split[0] : undefined;
      continue;
    }
    const version = line.match(/^ {2}version:? "?([^"\s]+)"?$/)?.[1];
    if (name && version) {
      deps.push(npm(name, version));
      name = undefined;
    }
  }
  return deps;
}

/** bun.lock is JSON with trailing commas; each package entry starts with its resolved `name@version`. */
export function parseBunLock(content: string): Dependency[] {
  const lock = JSON.parse(content.replace(/,(\s*[}\]])/g, "$1")) as {
    packages?: Record<string, unknown[]>;
  };
  return Object.values(lock.packages ?? {}).flatMap((entry) => {
    const split = typeof entry[0] === "string" ? splitAtVersion(entry[0]) : undefined;
    return split && !split[1].includes(":") ? [npm(...split)] : [];
  });
}
