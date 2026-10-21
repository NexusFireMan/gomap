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

`make coverage` and CI require at least **40% total statement coverage**. The
25% and 40% roadmap milestones are enforced by this floor; 60% remains the next
target, not the current requirement. Total coverage does not establish protocol
accuracy or replace deterministic negative cases and isolated lab validation.

If `golangci-lint` is not available in your `PATH`, use the pinned binary installed in `./bin` when present:

```bash
./bin/golangci-lint run ./...
```

## Lab Tests

Linux subprocess tests exercise `SIGINT` and `SIGTERM` cleanup with a fake address backend:

```bash
go test -race ./pkg/scanner -run '^TestManagedSignalCleanupProcess$' -v
```

They verify reverse cleanup order, preservation of pre-existing addresses, error reporting, and signal-derived exit codes. They do not change NIC addresses.

An opt-in kernel socket lifecycle test requires a separate user/network namespace containing only loopback:

```bash
test_dir=$(mktemp -d)
go test -c -o "$test_dir/scanner.test" ./pkg/scanner
unshare -Urn env GOMAP_RUN_ISOLATED_TESTS=1 "$test_dir/scanner.test" -test.run '^TestIsolatedRawSocketLifecycle$' -test.v
unshare -Urn env GOMAP_RUN_ISOLATED_TESTS=1 "$test_dir/scanner.test" -test.run '^TestIsolatedUDPStates$' -test.v -test.count=3
rm -r "$test_dir"
```

This test refuses the initial network namespace or a namespace with other interfaces. It opens an idle raw TCP socket, verifies its read deadline and closure, and checks the native netlink missing-interface error. It sends no packets and adds or removes no addresses. Systems that disable unprivileged user namespaces cannot run it; do not substitute the host network namespace.

Successful lifecycle tests do not establish end-to-end SYN discovery accuracy or native netlink address rollback. Those remain separate validation tasks in a disposable, disconnected lab.

`TestIsolatedUDPStates` separately requires the same guards, brings up loopback only inside that disposable namespace, and creates local positive/silent UDP fixtures. It validates `open`, `open|filtered`, and `closed`, and observes a correlated kernel ICMP destination-unreachable/port-unreachable quotation ([RFC 792](https://www.rfc-editor.org/rfc/rfc792.html)). It changes no host NIC addresses and contacts no external targets. These Linux IPv4 results do not establish behavior under packet loss, firewall filtering, IPv6, other operating systems, or remote lab conditions.

Fragment handling has a separate Linux kernel test, guarded by the same
loopback-only namespace restrictions:

```bash
test_dir=$(mktemp -d)
go test -c -o "$test_dir/scanner.test" ./pkg/scanner
unshare -Urn env GOMAP_RUN_ISOLATED_TESTS=1 "$test_dir/scanner.test" -test.run '^TestIsolatedUDPIPFragments$' -test.v -test.count=3
rm -r "$test_dir"
```

This sends synthetic IPv4/IPv6 fragments only to loopback inside the disposable
namespace. It validates in-order/out-of-order delivery, missing fragments,
mixed IDs and invalid UDP checksums through the production UDP socket reader.
Raw sockets are used by the test injector only, never by normal UDP scans.
No host NIC, route, firewall or VM configuration is changed. NetBIOS UDP/138
query/reassembly regressions run without privileges:

```bash
go test -race ./pkg/scanner -run '^TestNetBIOSDatagram' -count=3
go test ./pkg/scanner -run '^$' -fuzz '^FuzzNetBIOSDatagramAssembly$' -fuzztime=10s -parallel=2
```

Deterministic transport and cleanup tests run without VM targets, root, or changes to interface addresses:

```bash
go test -race ./pkg/scanner -run 'Test(AttemptLimiter|SYN|Managed|Cleanup)'
```

These use virtual clocks, packet fixtures, and fake address backends. They cover shared pacing, invalid SYN responses, rollback, idempotent cleanup, and preservation of multiple cleanup errors. They do not validate real raw sockets, netlink permissions, or signal handling in the kernel.

Privileged validation remains a separate, opt-in task in a disposable Linux VM or isolated network namespace with no external route. Check permission failures, response correlation, interruption cleanup, and preservation of pre-existing addresses; retain only redacted results. Do not mark this validation complete on the strength of simulated tests alone.

Integration tests are opt-in and require live lab hosts:

```bash
export GOMAP_RUN_LAB_TESTS=1
export GOMAP_LAB_WINDOWS_IP=10.0.11.6
export GOMAP_LAB_LINUX_IP=10.0.11.9
go test ./pkg/app -run LabIntegration -v
```

Do not run integration tests against systems you are not authorized to scan.

Optional SNMPv3 interoperability tests use a real Net-SNMP agent in a disposable
Docker container with no network other than its own loopback. They are skipped
by normal CI, generate private temporary credentials and remove their container:

```bash
docker build -t gomap-snmp-agent:local scripts/lab/snmp
GOMAP_RUN_SNMP_AGENT_TESTS=1 GOMAP_SNMP_AGENT_IMAGE=gomap-snmp-agent:local \
  go test ./pkg/app -run '^TestSNMPAgentInterop$' -count=3 -v
```

Building the fixture image requires package downloads; runtime has no external
route or published ports. See [SNMP sessions](docs/SNMP_SESSIONS.md) for the
supported algorithm matrix and limitations. Never publish generated keys or
agent state. Docker is a test-fixture dependency, not a GoMap runtime dependency.

Optional Memcached interoperability runs the agent and CLI in one disconnected
container, without host ports, cache-item requests or host-network changes:

```bash
docker pull memcached:1.6-alpine
GOMAP_RUN_MEMCACHED_AGENT_TESTS=1 GOMAP_MEMCACHED_AGENT_IMAGE=memcached:1.6-alpine \
  go test ./pkg/app -run '^TestMemcachedAgentInterop$' -count=3 -v
```

Image downloading needs network access; runtime uses `--network none` and a
read-only filesystem. The test removes its container. Docker is only a lab
fixture dependency; GoMap uses native Go for the query and reassembly.

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
