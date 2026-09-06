BINARY := marsec
BIN_DIR := bin
PKG := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GITLEAKS_VERSION := 8.30.1
VM := marsec-dev
VM_DIR := $(CURDIR)

GOBIN ?= $(shell go env GOPATH)/bin
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
SHA256 := $(shell command -v sha256sum >/dev/null 2>&1 && echo "sha256sum" || echo "shasum -a 256")
GOSEC_EXCLUDE := G115,G202,G204,G304,G404

.PHONY: help check build dist site run clean fmt fmt-check vet test test-race cover arch-check drill security govulncheck staticcheck gosec gitleaks tools hooks vm-up vm-test vm-shell vm-down

help:
	@echo "check        run every gate that CI runs"
	@echo "build        build $(BIN_DIR)/$(BINARY)"
	@echo "dist         build release archives for every platform"
	@echo "site         bring the shared theme into the landing page"
	@echo "run          run the server in insecure local development mode"
	@echo "test         run unit tests"
	@echo "test-race    run unit tests with the race detector"
	@echo "cover        run unit tests and report coverage"
	@echo "arch-check   enforce module boundaries"
	@echo "drill        save, verify and restore a snapshot end to end"
	@echo "security     run govulncheck, staticcheck, gosec and gitleaks"
	@echo "tools        install the scanners the gates use"
	@echo "hooks        point git at the tracked pre-commit hook"
	@echo "vm-up        start the linux test vm"
	@echo "vm-test      run the test suite inside the linux vm"
	@echo "vm-shell     open a shell in the linux vm"
	@echo "vm-down      stop and delete the linux vm"

check: fmt-check vet arch-check test-race drill security

build:
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) ./cmd/$(BINARY)

dist:
	rm -rf dist && mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		echo "building $(BINARY) $(VERSION) for $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(BINARY) ./cmd/$(BINARY) || exit 1; \
		tar -czf dist/$(BINARY)_$(VERSION)_$${os}_$${arch}.tar.gz -C dist $(BINARY) \
			-C .. LICENSE README.md CHANGELOG.md || exit 1; \
		rm dist/$(BINARY); \
	done
	cd dist && $(SHA256) *.tar.gz > SHA256SUMS

site:
	cp internal/modules/ui/assets/meridian.css site/meridian.css

run: build
	MARSEC_ALLOW_INSECURE_HTTP=true \
	MARSEC_ALLOW_UNPROTECTED_MEMORY=true \
	MARSEC_DATA_DIR=$(CURDIR)/.data \
	MARSEC_LOG_LEVEL=debug \
	./$(BIN_DIR)/$(BINARY) server

clean:
	rm -rf $(BIN_DIR) dist .data coverage.out

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

drill: build
	@sh scripts/restore-drill.sh $(BIN_DIR)/$(BINARY)

security: govulncheck staticcheck gosec gitleaks

govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

staticcheck:
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck $(PKG); \
	else \
		$(GOBIN)/staticcheck $(PKG); \
	fi

gosec:
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -quiet -severity medium -confidence medium -exclude=$(GOSEC_EXCLUDE) $(PKG); \
	else \
		$(GOBIN)/gosec -quiet -severity medium -confidence medium -exclude=$(GOSEC_EXCLUDE) $(PKG); \
	fi

gitleaks:
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks dir . --redact --no-banner; \
	else \
		echo "gitleaks is not installed"; \
		echo "install v$(GITLEAKS_VERSION) from https://github.com/gitleaks/gitleaks/releases"; \
		exit 1; \
	fi

tools:
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest

hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit
	@echo "git will run .githooks/pre-commit"

vm-up:
	limactl start --name=$(VM) --tty=false lima/$(VM).yaml

vm-test:
	limactl shell $(VM) bash -lc 'cd $(VM_DIR) && go vet ./... && go test -race ./...'

vm-shell:
	limactl shell $(VM) bash -lc 'cd $(VM_DIR) && exec bash'

vm-down:
	limactl delete --force $(VM)
