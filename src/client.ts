import type { Dependency } from './types.ts';

export class FiretruckError extends Error {
  override name = 'FiretruckError';
}

export interface ClientOptions {
  apiUrl: string;
  apiKey?: string;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  /** Longest wait for a rate-limit window to reset before giving up. */
  maxRateLimitWaitMs?: number;
  maxAttempts?: number;
}

interface ErrorEnvelope {
  error?: { code?: string; message?: string };
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function createClient(options: ClientOptions) {
  const {
    apiUrl,
    apiKey,
    fetch: doFetch = fetch,
    sleep = defaultSleep,
    maxRateLimitWaitMs = 60_000,
    maxAttempts = 4,
  } = options;
  const endpoint = new URL('/v1/packages/kevs', apiUrl).toString();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'firetruck-github-action',
    ...(apiKey ? { 'X-API-Key': apiKey } : {}),
  };

  return async function lookup({ name, version }: Dependency): Promise<string[]> {
    for (let attempt = 1; ; attempt++) {
      let response: Response;
      try {
        response = await doFetch(endpoint, { method: 'POST', headers, body: JSON.stringify({ name, version }) });
      } catch (error) {
        if (attempt >= maxAttempts) throw new FiretruckError(`could not reach ${endpoint}: ${String(error)}`);
        await sleep(2 ** attempt * 500);
        continue;
      }

      if (response.ok) {
        const body = (await response.json()) as { kevs?: unknown };
        if (!Array.isArray(body.kevs)) throw new FiretruckError(`unexpected response for ${name}@${version}`);
        return body.kevs.map(String);
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

      throw new FiretruckError(`lookup for ${name}@${version} failed with HTTP ${response.status}: ${message}`);
    }
  };
}

export type Lookup = ReturnType<typeof createClient>;

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
