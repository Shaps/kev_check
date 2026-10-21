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
  /** Longest a single request may take before it is abandoned and retried. */
  requestTimeoutMs?: number;
  /** Longest the whole client may spend on the API, retries and waits included. */
  deadlineMs?: number;
}

/** Packages per request; keeps each request small. */
export const BATCH_SIZE = 100;

interface ErrorEnvelope {
  error?: { code?: string; message?: string; details?: { limit?: unknown; max_limit?: unknown; received?: unknown } };
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * The API's answer for one dependency. `unchecked` means the API rejected that item, so no
 * verdict exists; the rest of the batch is unaffected.
 */
export type LookupResult =
  | { verdict: 'yes' | 'no' | 'unverified'; kevs: string[]; unverifiedKevs: string[] }
  | { verdict: 'unchecked'; reason: string };

const verdicts = new Set(['yes', 'no', 'unverified']);

/** Checks one batch item against the API's OpenAPI contract: a lookup result or an input-plus-error item. */
function toResult(item: unknown, dependency: Dependency): LookupResult {
  const unexpected = () => new FiretruckError(`unexpected response for ${dependency.name}@${dependency.version}`);
  if (!isObject(item)) throw unexpected();
  if ('error' in item) {
    const { error } = item;
    if (!isObject(error) || typeof error.code !== 'string' || typeof error.message !== 'string') throw unexpected();
    return { verdict: 'unchecked', reason: error.message || error.code };
  }
  const { verdict, kevs, matches } = item;
  if (typeof verdict !== 'string' || !verdicts.has(verdict)) throw unexpected();
  if (!Array.isArray(kevs) || !kevs.every((kev) => typeof kev === 'string')) throw unexpected();
  if (
    matches !== undefined &&
    (!Array.isArray(matches) ||
      !matches.every((m) => isObject(m) && typeof m.cve_id === 'string' && (m.verdict === 'yes' || m.verdict === 'unverified')))
  ) {
    throw unexpected();
  }
  const unverifiedKevs = ((matches ?? []) as { cve_id: string; verdict: string }[])
    .filter((m) => m.verdict === 'unverified')
    .map((m) => m.cve_id);
  return { verdict: verdict as 'yes' | 'no' | 'unverified', kevs: kevs as string[], unverifiedKevs: [...new Set(unverifiedKevs)] };
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
    requestTimeoutMs = 30_000,
    deadlineMs = 300_000,
  } = options;
  const endpoint = new URL('/v1/packages/kevs/batch', apiUrl).toString();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': userAgent(),
    ...(apiKey ? { 'X-API-Key': apiKey } : {}),
  };
  const deadline = AbortSignal.timeout(deadlineMs);
  const deadlineAt = Date.now() + deadlineMs;
  const outOfTime = () => new FiretruckError(`the Firetruck API did not finish within ${deadlineMs / 1000}s`);
  /** Sleeps before a retry, unless the wait would run past the overall deadline. */
  const pause = async (ms: number) => {
    if (Date.now() + ms >= deadlineAt) throw outOfTime();
    await sleep(ms);
  };

  /** Looks up one chunk of dependencies; results are in the same order as `dependencies`. */
  return async function lookup(dependencies: Dependency[]): Promise<LookupResult[]> {
    const body = JSON.stringify({
      packages: dependencies.map(({ ecosystem, name, version }) => ({ ecosystem, name, version })),
    });

    for (let attempt = 1; ; attempt++) {
      let response: Response;
      try {
        // A redirect is never followed: it could carry the API key to another origin.
        response = await doFetch(endpoint, {
          method: 'POST',
          headers,
          body,
          redirect: 'error',
          signal: AbortSignal.any([AbortSignal.timeout(requestTimeoutMs), deadline]),
        });
      } catch (error) {
        if (deadline.aborted) throw outOfTime();
        if (attempt >= maxAttempts) {
          const cause = error instanceof Error && error.cause instanceof Error ? ` (${error.cause.message})` : '';
          throw new FiretruckError(`could not reach ${endpoint}: ${String(error)}${cause}`);
        }
        await pause(2 ** attempt * 500);
        continue;
      }

      if (response.ok) {
        const payload: unknown = await response.json().catch(() => undefined);
        if (deadline.aborted) throw outOfTime();
        if (payload === undefined) {
          // Typically an HTML error page from a proxy in front of the API: as transient as a 5xx.
          if (attempt >= maxAttempts) throw new FiretruckError('unexpected response: non-JSON response from the API');
          await pause(2 ** attempt * 500);
          continue;
        }
        const results = isObject(payload) ? payload.results : undefined;
        if (!Array.isArray(results) || results.length !== dependencies.length) {
          const got = Array.isArray(results) ? `${results.length} results` : 'no results';
          throw new FiretruckError(`unexpected response: expected ${dependencies.length} results, got ${got}`);
        }
        return results.map((item, i) => toResult(item, dependencies[i]!));
      }

      const envelope = (await response.json().catch(() => ({}))) as ErrorEnvelope;
      const message = envelope.error?.message ?? response.statusText;

      if (response.status === 401) {
        throw new FiretruckError(`the API key was rejected (${message}). Check the api-key input or remove it.`);
      }

      if (response.status === 429) {
        // A batch over the caller's limit can never succeed on retry: fail with what the API said.
        const { limit, max_limit: maxLimit, received } = envelope.error?.details ?? {};
        if (typeof maxLimit === 'number') {
          throw new FiretruckError(`the API accepts at most ${limit} packages per batch for this key; this batch had ${received}`);
        }
        const reset = Number(response.headers.get('X-RateLimit-Reset'));
        const waitMs = Number.isFinite(reset) && reset > 0 ? reset * 1000 - Date.now() : Infinity;
        if (waitMs > maxRateLimitWaitMs || attempt >= maxAttempts) {
          const resetAt = Number.isFinite(waitMs) ? ` until ${new Date(reset * 1000).toISOString()}` : '';
          const hint = apiKey ? '' : ' Set the api-key input to get a higher limit.';
          throw new FiretruckError(`rate limited by the Firetruck API${resetAt}.${hint}`);
        }
        await pause(Math.max(waitMs, 0) + 1000);
        continue;
      }

      if (response.status >= 500 && attempt < maxAttempts) {
        await pause(2 ** attempt * 500);
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
