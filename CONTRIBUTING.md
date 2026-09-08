# Contributing

Thanks for taking the time to improve GoMap.

GoMap is a security tool, so contributions should be practical, well-scoped, and safe to discuss publicly. Please keep examples limited to labs, owned systems, or targets where you have explicit authorization.

## Good First Steps

- Check existing issues and pull requests before opening a new one.
- For bugs, include the command, target type, expected behavior, actual behavior, and GoMap version.
- For features, explain the use case and how it should behave from the CLI.
- Keep pull requests focused on one topic.

## Local Checks

Run the standard checks before opening a pull request:

```bash
make lint
make test
make test-race
make coverage
make ci
```

If `golangci-lint` is not available in your `PATH`, use the pinned binary installed in `./bin` when present:

```bash
./bin/golangci-lint run ./...
```

## Lab Tests

Integration tests are opt-in and require live lab hosts:

```bash
export GOMAP_RUN_LAB_TESTS=1
export GOMAP_LAB_WINDOWS_IP=10.0.11.6
export GOMAP_LAB_LINUX_IP=10.0.11.9
go test ./pkg/app -run LabIntegration -v
```

Do not run integration tests against systems you are not authorized to scan.

## Pull Request Expectations

- Add or update tests when behavior changes.
- Update `README.md` or `CHANGELOG.md` for user-facing changes.
- Keep public documentation focused on users.
- Avoid unrelated refactors in feature or bugfix pull requests.
- Do not commit generated binaries, private notes, credentials, lab logs, or local scan outputs.

## Protected Branch Workflow

`main` and `dev` are the two permanent branches. Both require pull requests and passing `Branch Policy`, `Lint`, and `Test` checks; do not push directly, force-push, or delete them. `main` is the stable release branch; `dev` integrates reviewed changes.

Recommended flow:

```bash
git checkout dev
git pull --ff-only origin dev
git checkout -b issue-<number>-short-description

# make focused changes

git add <changed-files>
git commit -m "type: concise description"
git push origin issue-<number>-short-description
```

Open the issue branch's PR into `dev`, link the related issue, and prefer squash merge for small changes. Delete the temporary branch after merging. Temporary branches are expected while work is in progress; only `main` and `dev` remain long-lived.

When integration is ready, open a PR from this repository's `dev` into `main`. Include the release summary, validation results, and `Closes #N` references for completed issues (automatic issue closure happens on the default branch). Use a **merge commit**, not squash or rebase, to preserve ancestry between permanent branches. Never delete `dev` after merging.

If `main` has commits missing from `dev`, open a synchronization PR from `main` into `dev` and use a merge commit there too. Prepare hotfixes through the same reviewed flow; do not bypass branch protection.

## Release Notes

Maintainers handle tagging and releases. Use conventional commit style where possible:

- `feat:` for new functionality
- `fix:` for bug fixes
- `docs:` for documentation-only changes
- `test:` for test-only changes
- `chore:` for maintenance

Release, package, GHCR, checksum, and APT repository publishing steps are documented in [GoMap Release Workflow](docs/RELEASE_WORKFLOW.md).
