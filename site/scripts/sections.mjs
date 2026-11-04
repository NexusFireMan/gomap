export function extractSection(markdown, heading) {
  const lines = markdown.split('\n');
  const start = lines.indexOf(`## ${heading}`);
  if (start === -1) throw new Error(`Missing README section: ${heading}`);
  let end = start + 1;
  while (end < lines.length && !lines[end].startsWith('## ')) end++;
  const body = lines.slice(start + 1, end).join('\n').trim();
  if (!body) throw new Error(`Empty README section: ${heading}`);
  return body + '\n';
}
