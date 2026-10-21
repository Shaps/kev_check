import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it, vi } from 'vitest';
import { BATCH_SIZE, createClient, FiretruckError, lookupAll, mapConcurrent } from '../src/client.ts';
import type { Dependency } from '../src/types.ts';
import { VERSION } from '../src/version.ts';

const dep: Dependency = { ecosystem: 'npm', name: 'jquery', version: '3.7.1' };
const clean = { verdict: 'no', kevs: [], matches: [] };
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
const batch = (...results: unknown[]) => json(200, { results });

function setup(...responses: (Response | Error)[]) {
  const fetch = vi.fn(async (_url: RequestInfo | URL, _init: RequestInit = {}) => {
    const next = responses.shift();
    if (!next) throw new Error('no more responses');
    if (next instanceof Error) throw next;
    return next;
  });
  const sleep = vi.fn(async (_ms: number) => {});
  return { fetch, sleep };
}

const bodyOf = (call: unknown[]) => JSON.parse((call[1] as RequestInit).body as string) as { packages: Dependency[] };

describe('createClient', () => {
  it('posts ecosystem, name and version to the batch endpoint with the API key', async () => {
    const { fetch, sleep } = setup(batch({ ecosystem: 'npm', name: 'jquery', version: '3.7.1', verdict: 'yes', kevs: ['CVE-2020-11023'], matches: [] }));
    const lookup = createClient({ apiUrl: 'https://api.example.test/', apiKey: 'k', fetch, sleep });

    await expect(lookup([dep])).resolves.toEqual([{ verdict: 'yes', kevs: ['CVE-2020-11023'], unverifiedKevs: [] }]);
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.example.test/v1/packages/kevs/batch');
    expect(JSON.parse(init.body as string)).toEqual({ packages: [{ ecosystem: 'npm', name: 'jquery', version: '3.7.1' }] });
    expect((init.headers as Record<string, string>)['X-API-Key']).toBe('k');
  });

  it('omits the key header when no key is set', async () => {
    const { fetch, sleep } = setup(batch(clean));
    await createClient({ apiUrl: 'https://api.example.test', fetch, sleep })([dep]);
    expect(fetch.mock.calls[0]![1]!.headers).not.toHaveProperty('X-API-Key');
  });

  it('identifies itself with the action version and the pinned ref', async () => {
    vi.stubEnv('GITHUB_ACTION_REF', 'v0.1.0');
    try {
      const { fetch, sleep } = setup(batch(clean));
      await createClient({ apiUrl: 'https://api.example.test', fetch, sleep })([dep]);
      expect((fetch.mock.calls[0]![1]!.headers as Record<string, string>)['User-Agent']).toBe(`firetruck-action/${VERSION} (v0.1.0)`);
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('maps results back to dependencies by request order', async () => {
    const deps: Dependency[] = [
      { ecosystem: 'npm', name: 'a', version: '1.0.0' },
      { ecosystem: 'pypi', name: 'b', version: '2.0.0' },
      { ecosystem: 'gem', name: 'c', version: '3.0.0' },
    ];
    const { fetch, sleep } = setup(
      batch(
        { verdict: 'no', kevs: [], matches: [] },
        { verdict: 'yes', kevs: ['CVE-2'], matches: [] },
        { verdict: 'unverified', kevs: [], matches: [{ cve_id: 'CVE-3', verdict: 'unverified' }, { cve_id: 'CVE-3', verdict: 'unverified' }] },
      ),
    );
    await expect(createClient({ apiUrl: 'https://api.example.test', fetch, sleep })(deps)).resolves.toEqual([
      { verdict: 'no', kevs: [], unverifiedKevs: [] },
      { verdict: 'yes', kevs: ['CVE-2'], unverifiedKevs: [] },
      { verdict: 'unverified', kevs: [], unverifiedKevs: ['CVE-3'] },
    ]);
  });

  it('answers the same name@version in two ecosystems independently', async () => {
    const deps: Dependency[] = [
      { ecosystem: 'npm', name: 'requests', version: '2.0.0' },
      { ecosystem: 'pypi', name: 'requests', version: '2.0.0' },
    ];
    const { fetch, sleep } = setup(batch({ verdict: 'no', kevs: [] }, { verdict: 'yes', kevs: ['CVE-9'] }));
    const results = await createClient({ apiUrl: 'https://api.example.test', fetch, sleep })(deps);
    expect(bodyOf(fetch.mock.calls[0]!).packages).toEqual(deps);
    expect(results.map((r) => r.verdict)).toEqual(['no', 'yes']);
  });

  it('turns a per-item error into an unchecked result without failing the batch', async () => {
    const { fetch, sleep } = setup(
      batch(
        { input: { ecosystem: 'npm', name: '', version: '1' }, error: { code: 'VALIDATION_ERROR', message: 'name is required' } },
        clean,
      ),
    );
    const deps: Dependency[] = [{ ecosystem: 'npm', name: '', version: '1' }, dep];
    await expect(createClient({ apiUrl: 'https://api.example.test', fetch, sleep })(deps)).resolves.toEqual([
      { verdict: 'unchecked', reason: 'name is required' },
      { verdict: 'no', kevs: [], unverifiedKevs: [] },
    ]);
  });

  it('rejects a response whose length differs from the request', async () => {
    const { fetch, sleep } = setup(batch(clean));
    const lookup = createClient({ apiUrl: 'https://api.example.test', fetch, sleep });
    await expect(lookup([dep, dep])).rejects.toThrow(/expected 2 results, got 1 results/);
  });

  it('rejects an item with an unknown verdict', async () => {
    const { fetch, sleep } = setup(batch({ verdict: 'maybe', kevs: [] }));
    await expect(createClient({ apiUrl: 'https://api.example.test', fetch, sleep })([dep])).rejects.toThrow(/unexpected response for jquery@3.7.1/);
  });

  it('fails fast on a rejected key', async () => {
    const { fetch, sleep } = setup(json(401, { error: { code: 'INVALID_API_KEY', message: 'invalid api key' } }));
    const lookup = createClient({ apiUrl: 'https://api.example.test', apiKey: 'bad', fetch, sleep });
    await expect(lookup([dep])).rejects.toThrow(/API key was rejected \(invalid api key\)/);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('waits out a short rate-limit window and resends the chunk', async () => {
    const reset = String(Math.floor(Date.now() / 1000) + 5);
    const { fetch, sleep } = setup(json(429, { error: { message: 'slow down' } }, { 'X-RateLimit-Reset': reset }), batch(clean));
    await expect(createClient({ apiUrl: 'https://api.example.test', fetch, sleep })([dep])).resolves.toHaveLength(1);
    expect(sleep).toHaveBeenCalledTimes(1);
    // X-RateLimit-Reset is a Unix epoch in seconds: wait until it, plus a second of slack.
    expect(sleep.mock.calls[0]![0]).toBeGreaterThan(5000);
    expect(sleep.mock.calls[0]![0]).toBeLessThanOrEqual(6000);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('gives up on a long rate-limit window and suggests an API key', async () => {
    const reset = String(Math.floor(Date.now() / 1000) + 3600);
    const { fetch, sleep } = setup(json(429, {}, { 'X-RateLimit-Reset': reset }));
    const error = await createClient({ apiUrl: 'https://api.example.test', fetch, sleep })([dep]).catch((e) => e);
    expect(error).toBeInstanceOf(FiretruckError);
    expect(error.message).toMatch(/rate limited .* Set the api-key input/);
    expect(sleep).not.toHaveBeenCalled();
  });

  it('resends the whole chunk after a server error or network failure', async () => {
    const deps: Dependency[] = [dep, { ecosystem: 'gem', name: 'rails', version: '7.0.0' }];
    const { fetch, sleep } = setup(json(503, {}), new TypeError('fetch failed'), batch(clean, { verdict: 'yes', kevs: ['CVE-1'] }));
    const results = await createClient({ apiUrl: 'https://api.example.test', fetch, sleep })(deps);
    expect(results.map((r) => r.verdict)).toEqual(['no', 'yes']);
    expect(fetch).toHaveBeenCalledTimes(3);
    const bodies = fetch.mock.calls.map((call) => (call[1] as RequestInit).body);
    expect(new Set(bodies).size).toBe(1);
  });

  it('stops retrying server errors after maxAttempts', async () => {
    const { fetch, sleep } = setup(json(500, {}), json(500, {}));
    const lookup = createClient({ apiUrl: 'https://api.example.test', fetch, sleep, maxAttempts: 2 });
    await expect(lookup([dep])).rejects.toThrow(/HTTP 500/);
  });

  it('fails the step with a generic message when the API rejects a whole chunk', async () => {
    for (const status of [400, 402, 413]) {
      const { fetch, sleep } = setup(json(status, { error: { code: 'ANY', message: 'server-side detail that must not be echoed' } }));
      const error = await createClient({ apiUrl: 'https://api.example.test', fetch, sleep })([dep]).catch((e) => e);
      expect(error).toBeInstanceOf(FiretruckError);
      expect(error.message).toBe(`batch rejected by the API: ${status}`);
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(sleep).not.toHaveBeenCalled();
    }
  });

  it('propagates a rejected chunk through lookupAll so the step fails instead of marking dependencies unchecked', async () => {
    const deps: Dependency[] = Array.from({ length: BATCH_SIZE + 1 }, (_, i) => ({ ecosystem: 'npm', name: `pkg-${i}`, version: '1.0.0' }));
    const { fetch, sleep } = setup(batch(...deps.slice(0, BATCH_SIZE).map(() => clean)), json(402, { error: { message: 'x' } }));
    const lookup = createClient({ apiUrl: 'https://api.example.test', fetch, sleep });
    await expect(lookupAll(lookup, deps, 1)).rejects.toThrow('batch rejected by the API: 402');
  });

  it('never follows a redirect, so the API key cannot leave the API origin', async () => {
    const hits: (string | undefined)[] = [];
    const target = createServer((req, res) => {
      hits.push(req.headers['x-api-key'] as string | undefined);
      res.end('{}');
    });
    const origin = createServer((_req, res) => {
      res.writeHead(307, { Location: `http://127.0.0.1:${(target.address() as AddressInfo).port}/steal` });
      res.end();
    });
    const listen = (server: Server) => new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    await Promise.all([listen(target), listen(origin)]);
    try {
      const lookup = createClient({
        apiUrl: `http://127.0.0.1:${(origin.address() as AddressInfo).port}`,
        apiKey: 'secret',
        sleep: async () => {},
        maxAttempts: 1,
      });
      await expect(lookup([dep])).rejects.toThrow(FiretruckError);
      expect(hits).toEqual([]);
    } finally {
      origin.close();
      target.close();
    }
  });

  it('retries a request that exceeds the per-request timeout', async () => {
    let calls = 0;
    const fetch = vi.fn(async (_url: RequestInfo | URL, init: RequestInit = {}) => {
      if (++calls > 1) return batch(clean);
      return new Promise<Response>((_resolve, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason)));
    });
    const lookup = createClient({ apiUrl: 'https://api.example.test', fetch, sleep: async () => {}, requestTimeoutMs: 20 });
    await expect(lookup([dep])).resolves.toHaveLength(1);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[0]![1]!.signal).toBeInstanceOf(AbortSignal);
  });

  it('fails once the overall deadline passes, however many attempts remain', async () => {
    const fetch = vi.fn(
      (_url: RequestInfo | URL, init: RequestInit = {}) =>
        new Promise<Response>((_resolve, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason))),
    );
    const lookup = createClient({ apiUrl: 'https://api.example.test', fetch, sleep: async () => {}, requestTimeoutMs: 10_000, deadlineMs: 30 });
    await expect(lookup([dep])).rejects.toThrow(/did not finish within/);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('does not sleep past the overall deadline', async () => {
    const { fetch, sleep } = setup(json(503, {}));
    const lookup = createClient({ apiUrl: 'https://api.example.test', fetch, sleep, deadlineMs: 100 });
    await expect(lookup([dep])).rejects.toThrow(/did not finish within/);
    expect(sleep).not.toHaveBeenCalled();
  });

  it('retries a non-JSON 200 like a server error, then reports it as non-JSON', async () => {
    const html = () => new Response('<html>bad gateway</html>', { status: 200, headers: { 'Content-Type': 'text/html' } });
    const retried = setup(html(), batch(clean));
    await expect(createClient({ apiUrl: 'https://api.example.test', fetch: retried.fetch, sleep: retried.sleep })([dep])).resolves.toHaveLength(1);
    expect(retried.fetch).toHaveBeenCalledTimes(2);

    const failing = setup(html(), html());
    const lookup = createClient({ apiUrl: 'https://api.example.test', fetch: failing.fetch, sleep: failing.sleep, maxAttempts: 2 });
    await expect(lookup([dep])).rejects.toThrow(/non-JSON response/);
  });

  it('rejects results that break the API contract', async () => {
    const malformed: Record<string, unknown> = {
      'a non-string kev': { verdict: 'yes', kevs: [{ id: 1 }] },
      'kevs that are not an array': { verdict: 'yes', kevs: 'CVE-1' },
      'matches that are not an array': { verdict: 'no', kevs: [], matches: 'x' },
      'a match without a string cve_id': { verdict: 'unverified', kevs: [], matches: [{ cve_id: 7, verdict: 'unverified' }] },
      'a match with an unknown verdict': { verdict: 'unverified', kevs: [], matches: [{ cve_id: 'CVE-1', verdict: 'no' }] },
      'an error without a message': { input: {}, error: { code: 'VALIDATION_ERROR' } },
      'an item that is not an object': 'no',
    };
    for (const [label, item] of Object.entries(malformed)) {
      const { fetch, sleep } = setup(batch(item));
      const error = await createClient({ apiUrl: 'https://api.example.test', fetch, sleep })([dep]).catch((e) => e);
      expect(error, label).toBeInstanceOf(FiretruckError);
      expect(error.message, label).toMatch(/unexpected response for jquery@3.7.1/);
    }
  });

  it('fails immediately when the batch is larger than the key allows, without waiting or retrying', async () => {
    const body = { error: { code: 'RATE_LIMITED', message: 'too many packages', details: { limit: 50, max_limit: 1000, received: 100 } } };
    const reset = String(Math.floor(Date.now() / 1000) + 5);
    const { fetch, sleep } = setup(json(429, body, { 'X-RateLimit-Reset': reset }), batch(clean));
    const error = await createClient({ apiUrl: 'https://api.example.test', fetch, sleep })([dep]).catch((e) => e);
    expect(error).toBeInstanceOf(FiretruckError);
    expect(error.message).toBe('the API accepts at most 50 packages per batch for this key; this batch had 100');
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
  });
});

describe('lookupAll', () => {
  const many = (n: number): Dependency[] =>
    Array.from({ length: n }, (_, i) => ({ ecosystem: 'npm', name: `pkg-${i}`, version: '1.0.0' }));

  /** A fake API that flags every package whose name ends in 7 as a KEV hit. */
  const echoApi = () => {
    const sizes: number[] = [];
    const fetch = vi.fn(async (_url: RequestInfo | URL, init: RequestInit = {}) => {
      const { packages } = JSON.parse(init.body as string) as { packages: Dependency[] };
      sizes.push(packages.length);
      return batch(...packages.map((p) => (p.name.endsWith('7') ? { verdict: 'yes', kevs: [`CVE-${p.name}`] } : clean)));
    });
    return { fetch, sizes };
  };

  it('splits 250 dependencies into three requests and keeps input order', async () => {
    const { fetch, sizes } = echoApi();
    const lookup = createClient({ apiUrl: 'https://api.example.test', fetch });
    const deps = many(250);

    const results = await lookupAll(lookup, deps, 2);

    expect(BATCH_SIZE).toBe(100);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(sizes.toSorted((a, b) => b - a)).toEqual([100, 100, 50]);
    expect(results).toHaveLength(250);
    results.forEach((result, i) => {
      expect(result.verdict).toBe(deps[i]!.name.endsWith('7') ? 'yes' : 'no');
      if (result.verdict === 'yes') expect(result.kevs).toEqual([`CVE-${deps[i]!.name}`]);
    });
  });

  it('sends nothing for an empty list', async () => {
    const { fetch } = echoApi();
    await expect(lookupAll(createClient({ apiUrl: 'https://api.example.test', fetch }), [], 4)).resolves.toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('retries only the failing chunk', async () => {
    let failedOnce = false;
    const fetch = vi.fn(async (_url: RequestInfo | URL, init: RequestInit = {}) => {
      const { packages } = JSON.parse(init.body as string) as { packages: Dependency[] };
      if (packages[0]!.name === 'pkg-100' && !failedOnce) {
        failedOnce = true;
        return json(502, {});
      }
      return batch(...packages.map(() => clean));
    });
    const lookup = createClient({ apiUrl: 'https://api.example.test', fetch, sleep: async () => {} });
    await expect(lookupAll(lookup, many(150), 1)).resolves.toHaveLength(150);
    expect(fetch).toHaveBeenCalledTimes(3);
  });
});

describe('mapConcurrent', () => {
  it('preserves order and respects the limit', async () => {
    let inFlight = 0;
    let peak = 0;
    const result = await mapConcurrent([5, 1, 3, 2, 4], 2, async (n) => {
      peak = Math.max(peak, ++inFlight);
      await new Promise((r) => setTimeout(r, n));
      inFlight--;
      return n * 10;
    });
    expect(result).toEqual([50, 10, 30, 20, 40]);
    expect(peak).toBe(2);
  });

  it('stops starting new work after a failure', async () => {
    const seen: number[] = [];
    await expect(
      mapConcurrent([1, 2, 3, 4, 5], 1, async (n) => {
        seen.push(n);
        if (n === 2) throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(seen).toEqual([1, 2]);
  });
});
