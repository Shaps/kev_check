import { describe, expect, it, vi } from 'vitest';
import { createClient, FiretruckError, mapConcurrent } from '../src/client.ts';
import type { Dependency } from '../src/types.ts';

const dep: Dependency = { ecosystem: 'npm', name: 'jquery', version: '3.7.1' };
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

function setup(...responses: (Response | Error)[]) {
  const fetch = vi.fn(async () => {
    const next = responses.shift();
    if (!next) throw new Error('no more responses');
    if (next instanceof Error) throw next;
    return next;
  });
  const sleep = vi.fn(async () => {});
  return { fetch, sleep };
}

describe('createClient', () => {
  it('posts name and version with the API key and returns KEV IDs', async () => {
    const { fetch, sleep } = setup(json(200, { name: 'jquery', version: '3.7.1', kevs: ['CVE-2020-11023'] }));
    const lookup = createClient({ apiUrl: 'https://api.example.test/', apiKey: 'k', fetch, sleep });

    await expect(lookup(dep)).resolves.toEqual(['CVE-2020-11023']);
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://api.example.test/v1/packages/kevs');
    expect(JSON.parse(init.body as string)).toEqual({ name: 'jquery', version: '3.7.1' });
    expect((init.headers as Record<string, string>)['X-API-Key']).toBe('k');
  });

  it('omits the key header when no key is set', async () => {
    const { fetch, sleep } = setup(json(200, { kevs: [] }));
    await createClient({ apiUrl: 'https://api.example.test', fetch, sleep })(dep);
    const [, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.headers).not.toHaveProperty('X-API-Key');
  });

  it('fails fast on a rejected key', async () => {
    const { fetch, sleep } = setup(json(401, { error: { code: 'INVALID_API_KEY', message: 'invalid api key' } }));
    const lookup = createClient({ apiUrl: 'https://api.example.test', apiKey: 'bad', fetch, sleep });
    await expect(lookup(dep)).rejects.toThrow(/API key was rejected \(invalid api key\)/);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('waits out a short rate-limit window and retries', async () => {
    const reset = String(Math.floor(Date.now() / 1000) + 5);
    const { fetch, sleep } = setup(json(429, { error: { message: 'slow down' } }, { 'X-RateLimit-Reset': reset }), json(200, { kevs: [] }));
    await expect(createClient({ apiUrl: 'https://api.example.test', fetch, sleep })(dep)).resolves.toEqual([]);
    expect(sleep).toHaveBeenCalledTimes(1);
  });

  it('gives up on a long rate-limit window and suggests an API key', async () => {
    const reset = String(Math.floor(Date.now() / 1000) + 3600);
    const { fetch, sleep } = setup(json(429, {}, { 'X-RateLimit-Reset': reset }));
    const error = await createClient({ apiUrl: 'https://api.example.test', fetch, sleep })(dep).catch((e) => e);
    expect(error).toBeInstanceOf(FiretruckError);
    expect(error.message).toMatch(/rate limited .* Set the api-key input/);
    expect(sleep).not.toHaveBeenCalled();
  });

  it('retries server errors and network failures, then succeeds', async () => {
    const { fetch, sleep } = setup(json(503, {}), new TypeError('fetch failed'), json(200, { kevs: ['CVE-1'] }));
    await expect(createClient({ apiUrl: 'https://api.example.test', fetch, sleep })(dep)).resolves.toEqual(['CVE-1']);
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it('stops retrying server errors after maxAttempts', async () => {
    const { fetch, sleep } = setup(json(500, {}), json(500, {}));
    const lookup = createClient({ apiUrl: 'https://api.example.test', fetch, sleep, maxAttempts: 2 });
    await expect(lookup(dep)).rejects.toThrow(/HTTP 500/);
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
