import test from 'node:test';
import assert from 'node:assert/strict';
import { lstat, mkdtemp, mkdir, writeFile, readFile, readdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { composePages } from './compose-pages.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'gomap-pages-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const apt = join(root, 'apt'), web = join(root, 'web'), out = join(root, 'output');
  await mkdir(apt); await mkdir(web);
  const contents = new Map([
    ['index.html', 'original apt instructions'], ['gomap.list', 'original source'],
    ['gomap-archive-keyring.gpg', 'public key'], ['gomap-archive-keyring.asc', 'armored key'],
    ['dists/stable/InRelease', 'signed metadata'], ['dists/stable/Release', 'metadata'],
    ['dists/stable/Release.gpg', 'signature'], ['pool/main/g/gomap/package.deb', 'package bytes'],
  ]);
  for (const arch of ['amd64', 'arm64']) {
    for (const suffix of ['', '.gz']) contents.set(`dists/stable/main/binary-${arch}/Packages${suffix}`, 'package index');
  }
  for (const [file, content] of contents) {
    await mkdir(dirname(join(apt, file)), { recursive: true });
    await writeFile(join(apt, file), content);
  }
  await writeFile(join(web, 'index.html'), 'website home');
  await mkdir(join(web, 'install'));
  await writeFile(join(web, 'install/index.html'), 'installation');
  return { root, apt, web, out, contents };
}

test('keeps original APT files byte-identical and relocates instructions only', async t => {
  const f = await fixture(t);
  await composePages(f.apt, f.web, f.out);
  for (const [file, content] of f.contents) {
    assert.equal(await readFile(join(f.out, file === 'index.html' ? 'apt/index.html' : file), 'utf8'), content);
    assert.equal(await readFile(join(f.apt, file), 'utf8'), content);
  }
  assert.equal(await readFile(join(f.out, 'index.html'), 'utf8'), 'website home');
  assert.equal(await readFile(join(f.out, 'install/index.html'), 'utf8'), 'installation');
  assert.equal(await readFile(join(f.out, '.nojekyll'), 'utf8'), '');
  assert.equal((await lstat(f.out)).mode & 0o777, 0o755);
});

for (const path of ['dists', 'pool', 'gomap-archive-keyring.gpg', 'gomap-archive-keyring.asc', 'gomap.list', 'apt', 'apt-ftparchive.conf']) {
  test(`rejects reserved website path ${path} before creating output`, async t => {
    const f = await fixture(t);
    await writeFile(join(f.web, path), 'collision');
    await assert.rejects(composePages(f.apt, f.web, f.out), /collides/);
    assert.ok(!(await readdir(f.root)).includes('output'));
  });
}
test('refuses missing signatures, packages and incomplete web builds', async t => {
  const f = await fixture(t);
  await rm(join(f.apt, 'dists/stable/InRelease'));
  await assert.rejects(composePages(f.apt, f.web, f.out), /Missing/);
  await writeFile(join(f.apt, 'dists/stable/InRelease'), 'signed');
  await rm(join(f.apt, 'pool'), { recursive: true });
  await assert.rejects(composePages(f.apt, f.web, f.out), /packages/);
  await mkdir(join(f.apt, 'pool'));
  await writeFile(join(f.apt, 'pool/example.deb'), 'deb');
  await rm(join(f.web, 'index.html'));
  await assert.rejects(composePages(f.apt, f.web, f.out), /website index/);
});
test('rejects symlinks, overlapping paths and existing output without deleting it', async t => {
  const f = await fixture(t);
  await assert.rejects(composePages(f.apt, f.web, join(f.apt, 'nested')), /overlap/);
  await assert.rejects(composePages(f.apt, f.apt, f.out), /overlap/);
  await mkdir(f.out);
  await writeFile(join(f.out, 'marker'), 'keep');
  await assert.rejects(composePages(f.apt, f.web, f.out), /already exists/);
  assert.equal(await readFile(join(f.out, 'marker'), 'utf8'), 'keep');
  await rm(f.out, { recursive: true });
  await symlink(join(f.apt, 'gomap.list'), join(f.web, 'leak'));
  await assert.rejects(composePages(f.apt, f.web, f.out), /symlinks/);
  await rm(join(f.web, 'leak'));
  await symlink(join(f.web, 'index.html'), join(f.apt, 'unexpected-link'));
  await assert.rejects(composePages(f.apt, f.web, f.out), /symlinks/);
});
