GO ?= go
MIN_COVERAGE ?= 10.0
GOLANGCI_LINT ?= $(firstword $(wildcard ./bin/golangci-lint) $(wildcard $(HOME)/go/bin/golangci-lint) $(shell command -v golangci-lint 2>/dev/null))

.PHONY: test test-race coverage lint ci

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

coverage:
	$(GO) test -covermode=atomic -coverprofile=coverage.out ./...
	@total="$$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%","",$$3); print $$3}')"; \
	echo "Total coverage: $${total}%"; \
	awk -v total="$$total" -v min="$(MIN_COVERAGE)" 'BEGIN { if (total+0 < min+0) { exit 1 } }'

lint:
	@test -n "$(GOLANGCI_LINT)" || (echo "golangci-lint not found. Install it or add it to PATH."; exit 1)
	$(GOLANGCI_LINT) run ./...

ci: lint test test-race coverage
