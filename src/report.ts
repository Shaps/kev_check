import type { Finding, UncheckedEntry } from './types.ts';
import type { Skipped } from './inventory.ts';

/** Untrusted text as inert plain text: newlines collapse, and every character or sequence Markdown would act on is neutralized. */
const plain = (text: string) =>
  text
    .replace(/[\r\n]+/g, ' ')
    .replace(/[&<>\\`|[\]*_~$@]/g, (char) => `&#${char.charCodeAt(0)};`)
    .replace(/:\/\//g, '&#58;//')
    .replace(/www\./gi, 'www&#46;');

/** Untrusted text as a code span: the fence outgrows any backtick run in it, and `\|` keeps a pipe inside its table cell. */
function code(text: string): string {
  const flat = text.replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|');
  const fence = '`'.repeat(Math.max(0, ...(flat.match(/`+/g) ?? []).map((run) => run.length)) + 1);
  const pad = /^`|`$/.test(flat) ? ' ' : '';
  return `${fence}${pad}${flat}${pad}${fence}`;
}

const kevLink = (id: string) => `[${plain(id)}](https://www.cve.org/CVERecord?id=${encodeURIComponent(id)})`;

export function distinctKevs(findings: Finding[]): string[] {
  return [...new Set(findings.flatMap((f) => f.kevs))].sort();
}

const fileList = (files: string[]) => files.map(code).join(', ');
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

export interface SummaryInput {
  /** Both verdicts: `yes` and `unverified`. */
  findings: Finding[];
  /** Dependencies that received a verdict from the API. */
  checked: number;
  unchecked: UncheckedEntry[];
  files: string[];
  skipped: Skipped[];
}

export function renderSummary({ findings, checked, unchecked, files, skipped }: SummaryInput): string {
  const vulnerable = findings.filter((f) => f.verdict === 'yes');
  const unverified = findings.filter((f) => f.verdict === 'unverified');
  const lines: string[] = ['## Firetruck KEV check', ''];

  if (vulnerable.length === 0) {
    lines.push('No dependencies matched a CISA Known Exploited Vulnerability.');
  } else {
    const kevs = distinctKevs(vulnerable);
    lines.push(
      `**${vulnerable.length}** ${plural(vulnerable.length, 'dependency matches', 'dependencies match')} ` +
        `**${kevs.length}** known exploited ${plural(kevs.length, 'vulnerability', 'vulnerabilities')}.`,
      '',
      '| Package | Version | Ecosystem | KEVs | Found in |',
      '| --- | --- | --- | --- | --- |',
      ...vulnerable.map(
        ({ dependency: d, kevs, files }) =>
          `| ${code(d.name)} | ${plain(d.version)} | ${d.ecosystem} | ${kevs.map(kevLink).join(', ')} | ${fileList(files)} |`,
      ),
    );
  }

  if (unverified.length > 0) {
    lines.push(
      '',
      `### Unverified (${unverified.length})`,
      '',
      'These dependencies are linked to a known exploited vulnerability, but the affected version range could not be compared with the locked version. They do not fail the step; check them by hand.',
      '',
      '| Package | Version | Ecosystem | Linked KEVs | Found in |',
      '| --- | --- | --- | --- | --- |',
      ...unverified.map(
        ({ dependency: d, unverifiedKevs, files }) =>
          `| ${code(d.name)} | ${plain(d.version)} | ${d.ecosystem} | ${unverifiedKevs.map(kevLink).join(', ') || '-'} | ${fileList(files)} |`,
      ),
    );
  }

  if (unchecked.length > 0) {
    lines.push(
      '',
      `### Not checked (${unchecked.length})`,
      '',
      'These dependencies were not looked up, so nothing is known about them.',
      '',
      '| Package | Version | Ecosystem | Reason | Found in |',
      '| --- | --- | --- | --- | --- |',
      ...unchecked.map(
        ({ dependency: d, files }) =>
          `| ${code(d.name)} | ${plain(d.version)} | ${plain(d.ecosystem)} | ${plain(d.reason)} | ${fileList(files)} |`,
      ),
    );
  }

  lines.push('', `Checked ${checked} distinct ${plural(checked, 'dependency', 'dependencies')} from ${files.length} ${plural(files.length, 'file', 'files')}.`);
  if (skipped.length > 0) {
    lines.push('', '<details><summary>Skipped files</summary>', '', ...skipped.map((s) => `- ${code(s.file)}: ${plain(s.reason)}`), '', '</details>');
  }
  return lines.join('\n') + '\n';
}

/**
 * Best-effort line of the dependency in its manifest, so the annotation lands near it. The name must
 * be a whole token: `react` is not `react-dom`, `lodash.merge`, or `@types/react`.
 */
export function lineOf(content: string, name: string, version: string): number | undefined {
  const token = new RegExp(`(?<![\\w.@-])(?<!@[\\w.-]*/)${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w./-])`);
  const lines = content.split(/\r?\n/);
  const both = lines.findIndex((line) => token.test(line) && line.includes(version));
  const index = both !== -1 ? both : lines.findIndex((line) => token.test(line));
  return index === -1 ? undefined : index + 1;
}
