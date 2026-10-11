import type { Dependency } from './types.ts';
import { userAgent } from './version.ts';

export class FiretruckError extends Error {
  override name = 'FiretruckError';
}

export const DEFAULT_API_URL = 'https://api.firetruck.dev';

export interface ClientOptions {
  /** Overridden only by tests; there is no action input for it. */
  apiUrl?: string;
  apiKey?: string;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  /** Longest wait for a rate-limit window to reset before giving up. */
  maxRateLimitWaitMs?: number;
  maxAttempts?: number;
}

/** Packages per request; keeps each request small. */
export const BATCH_SIZE = 100;

interface ErrorEnvelope {
  error?: { code?: string; message?: string };
}

interface BatchItem {
  verdict?: unknown;
  kevs?: unknown;
  matches?: unknown;
  error?: { code?: string; message?: string };
}

/**
 * The API's answer for one dependency. `unchecked` means the API rejected that item, so no
 * verdict exists; the rest of the batch is unaffected.
 */
export type LookupResult =
  | { verdict: 'yes' | 'no' | 'unverified'; kevs: string[]; unverifiedKevs: string[] }
  | { verdict: 'unchecked'; reason: string };

const verdicts = new Set(['yes', 'no', 'unverified']);

function toResult(item: unknown, dependency: Dependency): LookupResult {
  const { verdict, kevs, matches, error } = (item ?? {}) as BatchItem;
  if (error && typeof error === 'object') {
    return { verdict: 'unchecked', reason: error.message || error.code || 'rejected by the API' };
  }
  if (typeof verdict !== 'string' || !verdicts.has(verdict) || !Array.isArray(kevs)) {
    throw new FiretruckError(`unexpected response for ${dependency.name}@${dependency.version}`);
  }
  const unverifiedKevs = (Array.isArray(matches) ? (matches as { cve_id?: unknown; verdict?: unknown }[]) : [])
    .filter((m) => m?.verdict === 'unverified' && typeof m.cve_id === 'string')
    .map((m) => m.cve_id as string);
  return { verdict: verdict as 'yes' | 'no' | 'unverified', kevs: kevs.map(String), unverifiedKevs: [...new Set(unverifiedKevs)] };
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function createClient(options: ClientOptions) {
  const {
    apiUrl = DEFAULT_API_URL,
    apiKey,
    fetch: doFetch = fetch,
    sleep = defaultSleep,
    maxRateLimitWaitMs = 60_000,
    maxAttempts = 4,
  } = options;
  const endpoint = new URL('/v1/packages/kevs/batch', apiUrl).toString();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': userAgent(),
    ...(apiKey ? { 'X-API-Key': apiKey } : {}),
  };

  /** Looks up one chunk of dependencies; results are in the same order as `dependencies`. */
  return async function lookup(dependencies: Dependency[]): Promise<LookupResult[]> {
    const body = JSON.stringify({
      packages: dependencies.map(({ ecosystem, name, version }) => ({ ecosystem, name, version })),
    });

    for (let attempt = 1; ; attempt++) {
      let response: Response;
      try {
        response = await doFetch(endpoint, { method: 'POST', headers, body });
      } catch (error) {
        if (attempt >= maxAttempts) throw new FiretruckError(`could not reach ${endpoint}: ${String(error)}`);
        await sleep(2 ** attempt * 500);
        continue;
      }

      if (response.ok) {
        const { results } = (await response.json().catch(() => ({}))) as { results?: unknown };
        if (!Array.isArray(results) || results.length !== dependencies.length) {
          const got = Array.isArray(results) ? `${results.length} results` : 'no results';
          throw new FiretruckError(`unexpected response: expected ${dependencies.length} results, got ${got}`);
        }
        return results.map((item, i) => toResult(item, dependencies[i]!));
      }

      const message = ((await response.json().catch(() => ({}))) as ErrorEnvelope).error?.message ?? response.statusText;

      if (response.status === 401) {
        throw new FiretruckError(`the API key was rejected (${message}). Check the api-key input or remove it.`);
      }

      if (response.status === 429) {
        const reset = Number(response.headers.get('X-RateLimit-Reset'));
        const waitMs = Number.isFinite(reset) && reset > 0 ? reset * 1000 - Date.now() : Infinity;
        if (waitMs > maxRateLimitWaitMs || attempt >= maxAttempts) {
          const resetAt = Number.isFinite(waitMs) ? ` until ${new Date(reset * 1000).toISOString()}` : '';
          const hint = apiKey ? '' : ' Set the api-key input to get a higher limit.';
          throw new FiretruckError(`rate limited by the Firetruck API${resetAt}.${hint}`);
        }
        await sleep(Math.max(waitMs, 0) + 1000);
        continue;
      }

      if (response.status >= 500 && attempt < maxAttempts) {
        await sleep(2 ** attempt * 500);
        continue;
      }

      if (response.status >= 500) {
        throw new FiretruckError(`lookup of ${dependencies.length} packages failed with HTTP ${response.status}: ${message}`);
      }

      // The API's message is deliberately not echoed: a rejected chunk is reported by status alone.
      throw new FiretruckError(`batch rejected by the API: ${response.status}`);
    }
  };
}

export type Lookup = ReturnType<typeof createClient>;

/** Looks up `dependencies` in chunks of `BATCH_SIZE`, at most `concurrency` requests in flight; results keep input order. */
export async function lookupAll(lookup: Lookup, dependencies: Dependency[], concurrency: number): Promise<LookupResult[]> {
  const chunks: Dependency[][] = [];
  for (let i = 0; i < dependencies.length; i += BATCH_SIZE) chunks.push(dependencies.slice(i, i + BATCH_SIZE));
  return (await mapConcurrent(chunks, concurrency, lookup)).flat();
}

/** Runs `fn` over `items` with at most `limit` in flight, preserving order; the first rejection wins. */
export async function mapConcurrent<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  let failed = false;
  const worker = async () => {
    while (!failed && next < items.length) {
      const index = next++;
      try {
        results[index] = await fn(items[index]!);
      } catch (error) {
        failed = true;
        throw error;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
