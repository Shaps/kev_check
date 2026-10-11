import pkg from '../package.json' with { type: 'json' };

/** Version of this action, bundled from package.json at build time. */
export const VERSION: string = pkg.version;

/**
 * `firetruck-action/<version>`, plus the ref the consumer's `uses:` pinned (a tag, branch or SHA)
 * when GitHub provides one. The ref is reduced to characters valid in a header value.
 */
export function userAgent(env: NodeJS.ProcessEnv = process.env): string {
  const ref = env.GITHUB_ACTION_REF?.replace(/[^\w./-]/g, '');
  return ref ? `firetruck-action/${VERSION} (${ref})` : `firetruck-action/${VERSION}`;
}
