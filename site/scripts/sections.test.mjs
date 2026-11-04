import test from 'node:test';
import assert from 'node:assert/strict';
import { extractSection } from './sections.mjs';

test('extracts an exact level-two section including its subsections', () => {
  assert.equal(extractSection('## Other\na\n## CLI\nb\n### Flags\nc\n## End\nd', 'CLI'), 'b\n### Flags\nc\n');
  assert.throws(() => extractSection('## CLI extra\nb', 'CLI'), /Missing/);
  assert.throws(() => extractSection('## CLI\n\n## End', 'CLI'), /Empty/);
});
