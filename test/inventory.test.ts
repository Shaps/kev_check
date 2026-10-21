import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { buildInventory, findFiles, parseFiles } from '../src/inventory.ts';

const lock = (deps: Record<string, string>) =>
  JSON.stringify({ lockfileVersion: 3, packages: Object.fromEntries(Object.entries(deps).map(([name, version]) => [`node_modules/${name}`, { version }])) });

let root: string;
let outside: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'firetruck-ws-'));
  outside = await mkdtemp(join(tmpdir(), 'firetruck-outside-'));
});

describe('parseFiles', () => {
  it('skips a symlink that leaves the workspace without reading or echoing its content', async () => {
    await writeFile(join(outside, 'package-lock.json'), 'TOP-SECRET {not json');
    await symlink(join(outside, 'package-lock.json'), join(root, 'package-lock.json'));

    const { parsed, skipped } = await parseFiles([join(root, 'package-lock.json')], root);

    expect(parsed).toEqual([]);
    expect(skipped).toEqual([{ file: 'package-lock.json', reason: 'resolves outside the workspace' }]);
  });

  it('skips a symlink to an endless device instead of reading it', async () => {
    await mkdir(join(root, 'sub'));
    await symlink('/dev/zero', join(root, 'sub', 'yarn.lock'));

    const { skipped } = await parseFiles([join(root, 'sub', 'yarn.lock')], root);

    expect(skipped).toEqual([{ file: 'sub/yarn.lock', reason: 'resolves outside the workspace' }]);
  });

  it('skips a file inside the workspace that is not a regular file', async () => {
    execFileSync('mkfifo', [join(root, 'package-lock.json')]);

    const { skipped } = await parseFiles([join(root, 'package-lock.json')], root);

    expect(skipped).toEqual([{ file: 'package-lock.json', reason: 'not a regular file' }]);
  });

  it('skips a file over the size cap', async () => {
    await writeFile(join(root, 'package-lock.json'), lock({ lodash: '4.17.21' }));

    const { parsed, skipped } = await parseFiles([join(root, 'package-lock.json')], root, 10);

    expect(parsed).toEqual([]);
    expect(skipped).toEqual([{ file: 'package-lock.json', reason: expect.stringMatching(/larger than the .* limit/) }]);
  });

  it('still reads a symlink whose target stays inside the workspace', async () => {
    await mkdir(join(root, 'app'));
    await writeFile(join(root, 'package-lock.json'), lock({ lodash: '4.17.21' }));
    await symlink('../package-lock.json', join(root, 'app', 'package-lock.json'));

    const { parsed, skipped } = await parseFiles([join(root, 'app', 'package-lock.json')], root);

    expect(skipped).toEqual([]);
    expect(parsed.map((p) => [p.file, p.dependencies])).toEqual([
      ['app/package-lock.json', [{ ecosystem: 'npm', name: 'lodash', version: '4.17.21' }]],
    ]);
  });

  it('keeps each parsed file content so callers do not read it again', async () => {
    const content = lock({ lodash: '4.17.21' });
    await writeFile(join(root, 'package-lock.json'), content);

    const { parsed } = await parseFiles([join(root, 'package-lock.json')], root);

    expect(parsed[0]!.content).toBe(content);
  });
});

describe('findFiles', () => {
  it('does not descend into a symlinked directory', async () => {
    await writeFile(join(outside, 'package-lock.json'), lock({ lodash: '4.17.21' }));
    await symlink(outside, join(root, 'linked'));
    await writeFile(join(root, 'package-lock.json'), lock({ lodash: '4.17.21' }));

    const files = await findFiles([`${root}/**/package-lock.json`]);

    expect(files).toEqual([join(root, 'package-lock.json')]);
  });
});

describe('buildInventory', () => {
  it('counts an unchecked dependency once when two files declare it', () => {
    const dependency = {
      ecosystem: 'deb',
      name: 'debian/openssl',
      version: '3.0.11-1',
      reason: 'ecosystem not supported (purl type "deb")',
    };
    const { inventory, unchecked } = buildInventory([
      { file: 'a.cdx.json', content: '', dependencies: [dependency] },
      { file: 'b.cdx.json', content: '', dependencies: [{ ...dependency }] },
    ]);

    expect(inventory).toEqual([]);
    expect(unchecked).toEqual([{ dependency, files: ['a.cdx.json', 'b.cdx.json'] }]);
  });

  it('keeps names that differ only in case as separate dependencies', () => {
    const dependency = (name: string) => ({ ecosystem: 'golang' as const, name, version: 'v1.0.0' });
    const { inventory } = buildInventory([
      { file: 'go.mod', content: '', dependencies: [dependency('github.com/Foo/bar'), dependency('github.com/foo/bar')] },
    ]);

    expect(inventory.map((entry) => entry.dependency.name)).toEqual(['github.com/Foo/bar', 'github.com/foo/bar']);
  });
});
