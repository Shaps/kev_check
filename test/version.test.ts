import { describe, expect, it } from 'vitest';
import pkg from '../package.json' with { type: 'json' };
import { userAgent, VERSION } from '../src/version.ts';

describe('userAgent', () => {
  it('uses the package.json version', () => {
    expect(VERSION).toBe(pkg.version);
    expect(userAgent({})).toBe(`firetruck-action/${pkg.version}`);
  });

  it('appends the ref of the pinned action, which may be a SHA', () => {
    const sha = 'a'.repeat(40);
    expect(userAgent({ GITHUB_ACTION_REF: sha })).toBe(`firetruck-action/${pkg.version} (${sha})`);
  });

  it('keeps the header value on one line and free of separators', () => {
    expect(userAgent({ GITHUB_ACTION_REF: 'feat/x\r\nX-Evil: 1 (y)' })).toBe(`firetruck-action/${pkg.version} (feat/xX-Evil1y)`);
  });

  it('omits an empty ref', () => {
    expect(userAgent({ GITHUB_ACTION_REF: '' })).toBe(`firetruck-action/${pkg.version}`);
  });
});
