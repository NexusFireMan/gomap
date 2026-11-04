import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { extractSection } from './sections.mjs';

const readme = await readFile(new URL('../../README.md', import.meta.url), 'utf8');
const destination = new URL('../src/content/docs/generated/', import.meta.url);
await mkdir(destination, { recursive: true });
for (const [slug, heading, title] of [
  ['cli', 'CLI Reference', 'CLI reference'],
  ['quick-start', 'Quick Start', 'Quick start'],
  ['output', 'Output Formats', 'Output formats'],
]) {
  const body = extractSection(readme, heading)
    .replace(/\]\(#([^)]*)\)/g, '](https://github.com/NexusFireMan/gomap#$1)')
    .replace(/\]\((docs\/[^)]*)\)/g, '](https://github.com/NexusFireMan/gomap/blob/main/$1)');
  await writeFile(fileURLToPath(new URL(`${slug}.md`, destination)),
    `---\ntitle: ${title}\ndescription: GoMap ${title.toLowerCase()}, generated from the repository README.\n---\n\n` +
    'This reference is generated from the repository README during the site build.\n\n' + body);
}
