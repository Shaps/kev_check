import type { Finding, InventoryEntry } from './types.ts';
import type { Skipped } from './inventory.ts';

const kevLink = (id: string) => `[${id}](https://www.cve.org/CVERecord?id=${id})`;
const escapeCell = (text: string) => text.replace(/\|/g, '\\|');

export function distinctKevs(findings: Finding[]): string[] {
  return [...new Set(findings.flatMap((f) => f.kevs))].sort();
}

export function renderSummary(findings: Finding[], checked: InventoryEntry[], files: string[], skipped: Skipped[]): string {
  const lines: string[] = ['## Firetruck KEV check', ''];

  if (findings.length === 0) {
    lines.push(`No dependencies matched a CISA Known Exploited Vulnerability.`);
  } else {
    const kevs = distinctKevs(findings);
    lines.push(
      `**${findings.length}** ${findings.length === 1 ? 'dependency matches' : 'dependencies match'} ` +
        `**${kevs.length}** known exploited ${kevs.length === 1 ? 'vulnerability' : 'vulnerabilities'}.`,
      '',
      '| Package | Version | Ecosystem | KEVs | Found in |',
      '| --- | --- | --- | --- | --- |',
      ...findings.map(({ dependency: d, kevs, files }) =>
        `| \`${escapeCell(d.name)}\` | ${escapeCell(d.version)} | ${d.ecosystem} | ${kevs.map(kevLink).join(', ')} | ${files.map((f) => `\`${escapeCell(f)}\``).join(', ')} |`,
      ),
    );
  }

  lines.push('', `Checked ${checked.length} distinct ${checked.length === 1 ? 'dependency' : 'dependencies'} from ${files.length} ${files.length === 1 ? 'file' : 'files'}.`);
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
