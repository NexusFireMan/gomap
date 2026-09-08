# Repository Guidelines

## Project Structure & Module Organization

GoMap is a Go 1.24 module (`github.com/NexusFireMan/gomap/v2`). The root `main.go` starts the CLI. Command parsing, versioning, updates, and installation diagnostics live in `cmd/gomap/`. Scan orchestration belongs in `pkg/app/`; protocol probes, port logic, CIDR discovery, SYN/UDP engines, and source-IP handling live in `pkg/scanner/`; rendering and structured reports are under `pkg/output/`.

Tests sit beside production code as `*_test.go`. Golden output fixtures are in `pkg/output/testdata/`. Release and package automation lives in `.github/workflows/`, `.goreleaser.yml`, `Dockerfile`, and `scripts/`. User and maintainer documentation is kept in `README.md`, `CONTRIBUTING.md`, and `docs/`.

## Build, Test, and Development Commands

- `go run . -s -p 22,80 10.0.11.6`: run a local authorized-lab scan.
- `go build -o gomap .`: build the CLI binary.
- `make test`: run all unit and regression tests.
- `make test-race`: run tests with Go's race detector.
- `make coverage`: generate `coverage.out` and enforce at least 10% total coverage.
- `make lint`: run the configured `golangci-lint` checks.
- `make ci`: run lint, tests, race tests, and coverage locally.

Live lab tests are opt-in; follow `CONTRIBUTING.md` and set `GOMAP_RUN_LAB_TESTS=1` only for authorized hosts.

## Coding Style & Naming Conventions

Use `gofmt` and `goimports`; CI also checks `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`, and spelling. Follow idiomatic Go naming: exported identifiers use `PascalCase`, internal identifiers use `camelCase`, and package names remain short and lowercase. Keep protocol parsing pure where practical, network timeouts bounded, and refactors narrowly scoped.

## Testing Guidelines

Write deterministic table-driven tests named `TestBehaviorDescription`. Do not depend on public targets, exact timestamps, or external scanners. Prefer local fixtures, buffers, fake backends, and loopback listeners. Update golden files only when an intentional output change is reviewed.

## Commit & Pull Request Guidelines

Never push directly to protected `main`. Update `main`, create a short-lived branch such as `issue-12-fix-dns-probe`, and open a PR. Use conventional subjects (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). PRs must explain scope, include relevant validation, link issues with `Closes #N`, update documentation for user-facing changes, and pass `Lint` and `Test`. Prefer squash merge.

## Security & Responsible Use

Use only owned systems, private fixtures, or explicitly authorized lab targets. Never commit credentials, private scan logs, generated binaries, or sensitive target data. Keep scanner functionality native to Go unless a dependency is explicitly justified and reviewed.
