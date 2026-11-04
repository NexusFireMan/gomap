import { chmod, cp, copyFile, lstat, mkdir, mkdtemp, readdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const protectedNames = new Set([
  'dists', 'pool', 'gomap-archive-keyring.gpg', 'gomap-archive-keyring.asc',
  'gomap.list', 'apt-ftparchive.conf', 'apt',
]);
const required = [
  'index.html', 'gomap.list', 'gomap-archive-keyring.gpg', 'gomap-archive-keyring.asc',
  'dists/stable/InRelease', 'dists/stable/Release', 'dists/stable/Release.gpg',
  ...['amd64', 'arm64'].flatMap(arch => [
    `dists/stable/main/binary-${arch}/Packages`,
    `dists/stable/main/binary-${arch}/Packages.gz`,
  ]),
];

function within(parent, child) {
  const path = relative(parent, child);
  return path === '' || (!path.startsWith(`..${sep}`) && path !== '..' && !path.startsWith(sep));
}

async function files(root, prefix = '') {
  const found = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const path = join(prefix, entry.name);
    if (entry.isDirectory()) found.push(...await files(root, path));
    else if (entry.isFile()) found.push(path);
    else throw new Error(`Non-regular input (including symlinks): ${path}`);
  }
  return found;
}

async function directory(path) {
  if (!(await lstat(path)).isDirectory()) throw new Error(`Expected a directory: ${path}`);
  return realpath(path);
}

const hash = async path => createHash('sha256').update(await readFile(path)).digest('hex');

// Compose only after validating both inputs; publish no partially merged tree.
export async function composePages(aptInput, webInput, output) {
  const apt = await directory(resolve(aptInput));
  const web = await directory(resolve(webInput));
  const target = join(await realpath(dirname(resolve(output))), resolve(output).split(sep).at(-1));
  for (const [a, b] of [[apt, web], [apt, target], [web, target]]) {
    if (within(a, b) || within(b, a)) throw new Error('Inputs and output must not overlap');
  }
  try {
    await lstat(target);
    throw new Error('Output already exists; refusing to replace it');
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  const aptFiles = await files(apt);
  const webFiles = await files(web);
  for (const name of required) {
    if (!aptFiles.includes(name) || !(await lstat(join(apt, name))).size) {
      throw new Error(`Missing or empty APT input: ${name}`);
    }
  }
  if (!aptFiles.some(path => path.startsWith(`pool${sep}`) && path.endsWith('.deb'))) {
    throw new Error('Missing APT packages');
  }
  if (!webFiles.includes('index.html')) throw new Error('Missing website index');
  const aptNames = new Set(await readdir(apt));
  for (const name of await readdir(web)) {
    if (protectedNames.has(name) || (name !== 'index.html' && aptNames.has(name))) {
      throw new Error(`Website collides with APT path: ${name}`);
    }
  }
  const staging = await mkdtemp(`${target}.staging-`);
  try {
    await cp(apt, staging, { recursive: true });
    await mkdir(join(staging, 'apt'));
    await copyFile(join(apt, 'index.html'), join(staging, 'apt/index.html'));
    await cp(web, staging, { recursive: true });
    await writeFile(join(staging, '.nojekyll'), '');
    for (const file of aptFiles) {
      const destination = file === 'index.html' ? 'apt/index.html' : file;
      if (await hash(join(apt, file)) !== await hash(join(staging, destination))) {
        throw new Error(`APT bytes changed during composition: ${file}`);
      }
    }
    await chmod(staging, 0o755);
    await rename(staging, target);
  } catch (err) {
    await rm(staging, { recursive: true, force: true });
    throw err;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 5) throw new Error('Usage: node compose-pages.mjs <signed-apt> <web-dist> <new-output>');
  await composePages(...process.argv.slice(2));
  console.log('Composed website + signed APT; all original APT bytes preserved.');
}
