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

## Release Notes

Maintainers handle tagging and releases. Use conventional commit style where possible:

- `feat:` for new functionality
- `fix:` for bug fixes
- `docs:` for documentation-only changes
- `test:` for test-only changes
- `chore:` for maintenance
