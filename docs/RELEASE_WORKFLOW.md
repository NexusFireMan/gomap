# GoMap Release Workflow

This document describes how maintainers publish GoMap releases, binaries, Debian packages, container images, and the GitHub Pages APT repository.

GoMap's `main` branch is protected. Normal changes should land through a pull request with the required checks passing. Maintainers should create tags only from reviewed and merged commits on `main`.

## Release Inputs

A release is driven by a semantic version tag:

```bash
git checkout main
git pull --ff-only origin main
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

Use patch releases for backwards-compatible fixes, minor releases for backwards-compatible features, and major releases for breaking changes.

Before tagging, confirm:

- `CHANGELOG.md` has a section for the release version.
- `cmd/gomap/version.go` has the matching fallback version.
- The release commit is already merged into `main`.
- Required checks on `main` have passed.
- No generated binaries, private notes, credentials, lab logs, or local scan outputs are committed.

## GitHub Release And Binaries

The `Release` workflow runs on tags matching `v*.*.*`.

Workflow file:

- `.github/workflows/release.yml`

Release builder:

- GoReleaser, configured in `.goreleaser.yml`

GoReleaser performs:

- `go mod tidy`
- `go test ./...`
- static Go builds with `CGO_ENABLED=0`
- embedded version metadata via ldflags:
  - `cmd/gomap.Version`
  - `cmd/gomap.Commit`
  - `cmd/gomap.Date`

Published archive targets:

- Linux `amd64`
- Linux `arm64`
- macOS `amd64`
- macOS `arm64`
- Windows `amd64`
- Windows `arm64`

Archive formats:

- `.tar.gz` for Linux and macOS
- `.zip` for Windows

Each archive includes:

- `gomap`
- `README.md`
- `CHANGELOG.md`

## Debian Packages

GoReleaser also builds Debian packages through its `nfpms` configuration.

Published package targets:

- `gomap_<version>_linux_amd64.deb`
- `gomap_<version>_linux_arm64.deb`

Package behavior:

- Installs the binary at `/usr/bin/gomap`.
- Installs documentation under `/usr/share/doc/gomap/`.
- Uses the repository license and maintainer metadata from `.goreleaser.yml`.

Users can install a release asset directly:

```bash
sudo dpkg -i gomap_<version>_linux_amd64.deb
```

## Checksums

GoReleaser publishes `checksums.txt` with release assets.

Maintainers and users can verify downloaded artifacts with:

```bash
sha256sum -c checksums.txt
```

Only verify files downloaded from the matching GitHub release page.

## GHCR Container Images

The `Container` workflow publishes GoMap images to GitHub Container Registry.

Workflow file:

- `.github/workflows/container.yml`

Registry image:

- `ghcr.io/nexusfireman/gomap`

Triggers:

- push to `main`
- push of tags matching `v*.*.*`
- manual `workflow_dispatch`

Platforms:

- `linux/amd64`
- `linux/arm64`

Tag behavior:

- branch builds publish branch and SHA tags.
- release tag builds publish the release tag and `latest`.

The Docker build embeds:

- release version or `dev`
- git commit SHA
- UTC build date

## APT Repository On GitHub Pages

The `APT Repository` workflow publishes a signed APT repository to GitHub Pages after the `Release` workflow completes successfully.

Workflow file:

- `.github/workflows/apt-repo.yml`

Public repository URL:

- `https://nexusfireman.github.io/gomap`

The workflow:

1. Downloads non-draft, non-prerelease `.deb` assets from GitHub Releases.
2. Builds repository metadata with `scripts/build-apt-repo.sh`.
3. Publishes packages under `pool/main/g/gomap/`.
4. Generates `Packages`, `Packages.gz`, and `Release` metadata for `amd64` and `arm64`.
5. Exports the public key as:
   - `gomap-archive-keyring.gpg`
   - `gomap-archive-keyring.asc`
6. Signs the repository metadata as:
   - `dists/stable/InRelease`
   - `dists/stable/Release.gpg`
7. Deploys the generated repository through GitHub Pages.

The published APT source entry is:

```text
deb [signed-by=/usr/share/keyrings/gomap-archive-keyring.gpg] https://nexusfireman.github.io/gomap stable main
```

## APT Signing Secrets

The APT workflow requires repository secrets:

- `APT_GPG_PRIVATE_KEY`
- `APT_GPG_PASSPHRASE`

Security notes:

- Do not commit private keys, passphrases, exported secret key material, or temporary `GNUPGHOME` contents.
- Rotate the signing key if a secret is exposed.
- Keep only the public key published through GitHub Pages.
- Use GitHub Actions secrets for private signing material.

## Release Notes

Use the matching `CHANGELOG.md` section as the source for release notes.

Release notes should mention:

- user-facing changes
- bug fixes
- distribution changes
- known operational notes
- security-relevant packaging or signing changes

Avoid including:

- private infrastructure details
- secret names beyond documented repository secret names
- credentials or tokens
- local lab logs
- unsupported target details

## Post-Release Verification

After a release, verify:

- the GitHub Release exists and is not a draft
- archives and `.deb` assets are uploaded
- `checksums.txt` is present
- the `Release` workflow passed
- the `Container` workflow passed
- the `APT Repository` workflow passed
- `ghcr.io/nexusfireman/gomap:<version>` exists
- `ghcr.io/nexusfireman/gomap:latest` points to the latest tagged release
- `apt update` resolves `InRelease` and `Packages` from GitHub Pages
- `apt install gomap` installs the expected version in a clean lab environment

Example verification commands:

```bash
gh release view vX.Y.Z --repo NexusFireMan/gomap
docker pull ghcr.io/nexusfireman/gomap:vX.Y.Z
curl -fsSL https://nexusfireman.github.io/gomap/dists/stable/InRelease | gpg --show-keys
```

Use authorized lab systems for installation checks.
