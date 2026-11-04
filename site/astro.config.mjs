import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://nexusfireman.github.io',
  base: '/gomap',
  trailingSlash: 'always',
  integrations: [starlight({
    title: 'GoMap',
    description: 'Native network reconnaissance. Observed evidence, structured output and controlled rates.',
    social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/NexusFireMan/gomap' }],
    customCss: ['./src/styles/custom.css'],
    sidebar: [
      { label: 'GoMap', items: [
        { label: 'Overview', link: '/' },
        { label: 'Install', slug: 'install' },
        { label: 'Quick start', slug: 'generated/quick-start' },
      ] },
      { label: 'Documentation', items: [
        { label: 'CLI reference', slug: 'generated/cli' },
        { label: 'Output formats', slug: 'generated/output' },
        { label: 'Detection and evidence', slug: 'docs/detection' },
        { label: 'UDP and SNMP', slug: 'docs/udp' },
      ] },
      { label: 'Project', items: [
        { label: 'Lab benchmarks', slug: 'benchmarks' },
        { label: 'Releases', slug: 'releases' },
        { label: 'Security and responsible use', slug: 'security' },
        { label: 'APT repository', link: '/apt/' },
      ] },
    ],
    expressiveCode: { themes: ['github-dark', 'github-light'] },
  })],
});
