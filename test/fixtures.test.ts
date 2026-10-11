import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { isUnchecked } from '../src/types.ts';
import { parserFor } from '../src/parsers/index.ts';

const root = join(import.meta.dirname, 'fixtures', 'ecosystems');

interface Expected {
  file: string;
  ecosystem: string;
  name: string;
  version: string;
  kev: string;
}

const expected = JSON.parse(await readFile(join(root, 'expected.json'), 'utf8')) as Expected[];

// expected.json also drives the live CI matrix, so each entry must be something the parsers produce.
describe('ecosystem fixtures', () => {
  it.each(expected)('$file yields $ecosystem $name@$version', async ({ file, ecosystem, name, version }) => {
    const path = join(root, file);
    const content = await readFile(path, 'utf8');
    const parse = parserFor(path, content);
    expect(parse, `no parser for ${file}`).toBeDefined();
    expect(parse!(content)).toContainEqual({ ecosystem, name, version });
  });

  it('keeps purl-less and unsupported SBOM components out of the lookups', async () => {
    const path = join(root, 'sbom', 'sbom.cdx.json');
    const content = await readFile(path, 'utf8');
    const unchecked = parserFor(path, content)!(content).filter(isUnchecked);
    expect(unchecked.map((d) => d.name)).toEqual(['no-purl', 'debian/openssl']);
  });
});
