GO ?= go
GOFMT ?= gofmt
PROTOC ?= protoc
BUILD_DIR ?= build
COVERAGE_DIR ?= coverage
COVERAGE_MIN ?= 95
GO_FILES := $(shell find apps internal gen -type f -name '*.go' -print)

.DEFAULT_GOAL := build

.PHONY: build test adversarial coverage lint check dev tools generate install install-dev clean help

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o "$(BUILD_DIR)/shudo" ./apps/cli/cmd/shudo
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o "$(BUILD_DIR)/shudod" ./apps/daemon/cmd/shudod

test:
	$(GO) test ./...

adversarial:
	$(GO) test -race ./internal/... -run '^TestAdversarial' -count=1

coverage:
	mkdir -p "$(COVERAGE_DIR)"
	$(GO) test ./internal/... -covermode=atomic -coverprofile="$(COVERAGE_DIR)/coverage.out"
	@$(GO) tool cover -html="$(COVERAGE_DIR)/coverage.out" -o "$(COVERAGE_DIR)/coverage.html"
	@awk -v minimum="$(COVERAGE_MIN)" 'NR > 1 { total += $$2; if ($$3 > 0) covered += $$2 } END { percentage = 100 * covered / total; printf "Core unit coverage: %.2f%% (%d/%d statements; required: %.2f%%)\n", percentage, covered, total, minimum; if (percentage + 0.000001 < minimum) exit 1 }' "$(COVERAGE_DIR)/coverage.out"

lint:
	@test -z "$$($(GOFMT) -l $(GO_FILES))" || { echo "Go files need formatting; run: gofmt -w apps internal gen" >&2; exit 1; }
	$(GO) vet ./...

check: test lint coverage

dev: build
	@echo 'Build complete. Start the development daemon with a clean root environment:'
	@echo '  sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin $(CURDIR)/scripts/dev.sh'

tools:
	mkdir -p .tools/bin
	GOBIN=$(CURDIR)/.tools/bin $(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
	GOBIN=$(CURDIR)/.tools/bin $(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2

generate:
	PATH="$(CURDIR)/.tools/bin:$$PATH" $(PROTOC) \
		--go_out=. --go_opt=module=shudo.local/shudo \
		--go-grpc_out=. --go-grpc_opt=module=shudo.local/shudo \
		proto/shudo/v1/shudo.proto
	gofmt -w gen/shudov1

install:
	@echo 'Refusing source-tree root installation. Build a reviewed, checksummed package as documented in docs/production-deployment.md.' >&2
	@exit 1

install-dev:
	@test "$$(id -u)" -eq 0 || { echo "Development-only target: build first, then run sudo make install-dev" >&2; exit 1; }
	@test -x "$(BUILD_DIR)/shudo" -a -x "$(BUILD_DIR)/shudod" || { echo "Missing build artifacts; build them without root before sudo make install-dev" >&2; exit 1; }
	SHUDO_UNSAFE_LOCAL_INSTALL=1 SHUDO_REPO_ROOT="$(CURDIR)" ./deploy/systemd/install-local.sh

clean:
	@case "$(abspath $(BUILD_DIR))" in "$(CURDIR)"/*) rm -rf -- "$(abspath $(BUILD_DIR))" ;; *) echo "Refusing to clean outside the repository" >&2; exit 1 ;; esac

help:
	@printf '%s\n' \
		'make build     Build static shudo and shudod binaries in build/' \
		'make test      Run all Go tests' \
		'make adversarial  Run privilege-boundary attack tests with the race detector' \
		'make coverage  Enforce 95% coverage for handwritten internal packages' \
		'make lint      Check formatting and run go vet' \
		'make check     Run tests, lint, and the coverage gate' \
		'make tools     Install pinned protobuf generators under .tools/' \
		'make generate  Regenerate protobuf Go sources' \
		'make dev       Build and print the clean-environment development launch command' \
		'make install   Refuse unsafe source-tree production installation' \
		'make install-dev  Explicit development-only source-tree install (requires root)' \
		'make clean     Remove build outputs'
