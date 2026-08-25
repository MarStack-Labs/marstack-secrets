BINARY := marsec
BIN_DIR := bin
PKG := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GITLEAKS_VERSION := 8.30.1
VM := marsec-dev
VM_DIR := $(CURDIR)

.PHONY: help check build run clean fmt fmt-check vet test test-race cover arch-check security govulncheck gitleaks hooks vm-up vm-test vm-shell vm-down

help:
	@echo "check        run every gate that CI runs"
	@echo "build        build $(BIN_DIR)/$(BINARY)"
	@echo "run          run the server in insecure local development mode"
	@echo "test         run unit tests"
	@echo "test-race    run unit tests with the race detector"
	@echo "cover        run unit tests and report coverage"
	@echo "arch-check   enforce module boundaries"
	@echo "security     run govulncheck and gitleaks"
	@echo "hooks        install the pre-commit hook"
	@echo "vm-up        start the linux test vm"
	@echo "vm-test      run the test suite inside the linux vm"
	@echo "vm-shell     open a shell in the linux vm"
	@echo "vm-down      stop and delete the linux vm"

check: fmt-check vet arch-check test-race security

build:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) ./cmd/$(BINARY)

run: build
	MARSEC_ALLOW_INSECURE_HTTP=true \
	MARSEC_ALLOW_UNPROTECTED_MEMORY=true \
	MARSEC_DATA_DIR=$(CURDIR)/.data \
	MARSEC_LOG_LEVEL=debug \
	./$(BIN_DIR)/$(BINARY) server

clean:
	rm -rf $(BIN_DIR) .data coverage.out

fmt:
	gofmt -s -w .

fmt-check:
	@unformatted=$$(gofmt -s -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "these files are not gofmt-clean:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet:
	go vet $(PKG)

test:
	go test $(PKG)

test-race:
	go test -race $(PKG)

cover:
	go test -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out | tail -n 1

arch-check:
	@sh scripts/check-architecture.sh

security: govulncheck gitleaks

govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

gitleaks:
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks dir . --redact --no-banner; \
	else \
		echo "gitleaks is not installed"; \
		echo "install v$(GITLEAKS_VERSION) from https://github.com/gitleaks/gitleaks/releases"; \
		exit 1; \
	fi

hooks:
	@printf '#!/bin/sh\nexec make check\n' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "pre-commit hook installed"

vm-up:
	limactl start --name=$(VM) --tty=false lima/$(VM).yaml

vm-test:
	limactl shell $(VM) bash -lc 'cd $(VM_DIR) && go vet ./... && go test -race ./...'

vm-shell:
	limactl shell $(VM) bash -lc 'cd $(VM_DIR) && exec bash'

vm-down:
	limactl delete --force $(VM)
