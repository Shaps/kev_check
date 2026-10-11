import type { Finding, UncheckedEntry } from './types.ts';
import type { Skipped } from './inventory.ts';

const kevLink = (id: string) => `[${id}](https://www.cve.org/CVERecord?id=${id})`;
const escapeCell = (text: string) => text.replace(/\|/g, '\\|');

export function distinctKevs(findings: Finding[]): string[] {
  return [...new Set(findings.flatMap((f) => f.kevs))].sort();
}

const fileList = (files: string[]) => files.map((f) => `\`${escapeCell(f)}\``).join(', ');
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
          `| \`${escapeCell(d.name)}\` | ${escapeCell(d.version)} | ${d.ecosystem} | ${kevs.map(kevLink).join(', ')} | ${fileList(files)} |`,
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
          `| \`${escapeCell(d.name)}\` | ${escapeCell(d.version)} | ${d.ecosystem} | ${unverifiedKevs.map(kevLink).join(', ') || '-'} | ${fileList(files)} |`,
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
          `| \`${escapeCell(d.name)}\` | ${escapeCell(d.version)} | ${escapeCell(d.ecosystem)} | ${escapeCell(d.reason)} | ${fileList(files)} |`,
      ),
    );
  }

  lines.push('', `Checked ${checked} distinct ${plural(checked, 'dependency', 'dependencies')} from ${files.length} ${plural(files.length, 'file', 'files')}.`);
  if (skipped.length > 0) {
    lines.push('', '<details><summary>Skipped files</summary>', '', ...skipped.map((s) => `- \`${s.file}\`: ${s.reason}`), '', '</details>');
  }
  return lines.join('\n') + '\n';
}

/** Best-effort line of the dependency in its manifest, so the annotation lands near it. */
export function lineOf(content: string, name: string, version: string): number | undefined {
  const lines = content.split(/\r?\n/);
  const both = lines.findIndex((line) => line.includes(name) && line.includes(version));
  const index = both !== -1 ? both : lines.findIndex((line) => line.includes(name));
  return index === -1 ? undefined : index + 1;
}
