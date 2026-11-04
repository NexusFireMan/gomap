# Website And APT Hosting

## Two Repositories, Two Pages Sites

`NexusFireMan/nexusfireman.github.io` serves the personal portfolio at `/`.
`NexusFireMan/gomap` has its own workflow-backed project Pages site at `/gomap/`.
The portal belongs to the latter; no generated `gomap/` directory needs to be
added to the portfolio repository. Do not configure a competing Pages deployment
from that repository for this path.

## Source And Preview

The static portal uses Astro/Starlight in `site/`, Node 24 and the exact pnpm
version declared in `site/package.json`. These are website build/test tools,
not GoMap runtime dependencies. CLI, quick-start and output pages are generated
from README sections to avoid maintaining competing references.

```bash
cd site
corepack pnpm install --frozen-lockfile
corepack pnpm test
corepack pnpm build
corepack pnpm dev
```

Preview uses `/gomap/`, not `/`. Browser tests use a separate built-site preview:

```bash
corepack pnpm exec playwright install chromium
corepack pnpm test:browser
```

Set `PLAYWRIGHT_CHROMIUM_EXECUTABLE` only to an existing local Chromium when
using that instead of Playwright's managed browser. Normal tests contact no
scan targets. The CLI image depicts a local HTTP fixture, not a benchmark.

## Single Deployment

The existing `APT Repository` workflow remains the only Pages publisher. It runs
after successful releases, on trusted-main website/publishing changes, or by
manual dispatch from `main`. Website edits do not require a release tag.

1. Build the website in a separate job with no signing secrets; retain its exact
   source commit and static artifact.
2. Download public release packages and build/sign the APT tree as before.
3. Scope private signing material to a single step and remove its temporary
   keyring on exit. Do not export passphrases into later steps.
4. Compose both inputs with `scripts/compose-pages.mjs` and upload/deploy one
   artifact only if all validation succeeds. A failed build leaves live Pages
   unchanged; never publish a website-only artifact over the package repository.

## Compatibility Guards

`dists/`, `pool/`, both public key files and `gomap.list` retain their URLs and
bytes from the signed APT input. The composer rejects web collisions, symlinks,
missing signatures/indexes/packages, overlapping paths and existing output. It
stages composition and hashes all original APT files before making output
available. The old instructions move from the root HTML to `/gomap/apt/`;
the root becomes the portal, with new `/gomap/install/` and documentation routes.

The composer verifies byte preservation, not GPG trust. Release/deployment QA
must separately verify `InRelease` with the existing trusted key and exercise a
clean APT install. Keep private keys and raw lab reports out of source/artifacts.

## Rollback

Use GitHub Pages' previous successful deployment when available, or revert the
website/publishing change through the protected branch PR flow and dispatch the
same workflow on `main`. Do not move release tags, replace signing keys, remove
package paths or modify client APT source entries to roll back a visual change.
