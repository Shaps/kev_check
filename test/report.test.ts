import { describe, expect, it } from 'vitest';
import { renderSummary } from '../src/report.ts';
import type { Finding, UncheckedEntry } from '../src/types.ts';

const hostile = '`</details>\n<img src=x onerror=alert(1)>[click](https://evil.test)|`';

const finding = (overrides: Partial<Finding['dependency']> = {}, kevs: string[] = ['CVE-2020-0001']): Finding => ({
  dependency: { ecosystem: 'npm', name: 'lodash', version: '1.0.0', ...overrides },
  files: ['package-lock.json'],
  verdict: 'yes',
  kevs,
  unverifiedKevs: [],
});

const summary = (input: Partial<Parameters<typeof renderSummary>[0]> = {}) =>
  renderSummary({ findings: [], checked: 0, unchecked: [], files: [], skipped: [], ...input });

/** Cells of a Markdown table row, splitting only on pipes that are not backslash-escaped. */
const cells = (row: string) => row.split(/(?<!\\)\|/).slice(1, -1);

/** What Markdown would interpret: the summary with its code spans removed, where hostile text is inert. */
const outsideCode = (markdown: string) => markdown.replace(/(`+)[\s\S]*?\1(?!`)/g, '');

describe('renderSummary escaping', () => {
  it('keeps a hostile package name, version and path inside their table cells', () => {
    const out = summary({
      findings: [{ ...finding({ name: hostile, version: hostile }), files: [hostile] }],
      checked: 1,
    });
    const row = out.split('\n').find((line) => line.startsWith('| `'))!;
    expect(cells(row)).toHaveLength(5);
    expect(outsideCode(out)).not.toMatch(/<img|<\/details>|\[click\]/);
    expect(out.split('\n').filter((line) => line.startsWith('| '))).toHaveLength(2 + 1);
  });

  it('fences code spans that contain backticks so they cannot be closed early', () => {
    const out = summary({ findings: [finding({ name: 'a`b``c' })], checked: 1 });
    expect(out).toContain('| ```a`b``c``` |');
  });

  it('renders a hostile skip reason and path on one list item without markup', () => {
    const out = summary({ skipped: [{ file: hostile, reason: `Unexpected token\n# heading <script>alert(1)</script> www.evil.test https://evil.test a@b.test` }] });
    const items = out.split('\n').filter((line) => line.startsWith('- '));
    expect(items).toHaveLength(1);
    const rendered = outsideCode(out);
    expect(rendered).not.toMatch(/<script|<img|\]\(|https:\/\/evil\.test|www\.evil|a@b\.test/);
    expect(out).not.toMatch(/^# heading/m);
    expect(rendered.match(/<\/details>/g)).toHaveLength(1);
  });

  it('escapes the reason and ecosystem of an unchecked dependency', () => {
    const unchecked: UncheckedEntry = {
      dependency: { ecosystem: '<b>x</b>', name: 'n', version: '1', reason: '[link](https://evil.test) | extra' },
      files: ['sbom.json'],
    };
    const out = summary({ unchecked: [unchecked] });
    const row = out.split('\n').find((line) => line.startsWith('| `n`'))!;
    expect(cells(row)).toHaveLength(5);
    expect(row).not.toMatch(/<b>|\]\(/);
  });

  it('percent-encodes a KEV ID in the link target and escapes it in the link text', () => {
    const out = summary({ findings: [finding({}, ['CVE-1](https://evil.test) <i>'])], checked: 1 });
    expect(out).toContain('(https://www.cve.org/CVERecord?id=CVE-1%5D(https%3A%2F%2Fevil.test)%20%3Ci%3E)');
    expect(out).not.toMatch(/<i>|\[CVE-1\]/);
  });

  it('leaves ordinary values readable', () => {
    const out = summary({ findings: [finding({ name: '@babel/core', version: '7.24.0' })], checked: 1 });
    expect(out).toContain('| `@babel/core` | 7.24.0 | npm | [CVE-2020-0001](https://www.cve.org/CVERecord?id=CVE-2020-0001) | `package-lock.json` |');
  });
});
