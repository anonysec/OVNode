# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

.PHONY: setup test check check-cli check-bash check-installer lint format verify clean

setup:
	go mod download

test:
	go test ./...

# Every shell file in the tree, found rather than listed: a list drifts and a
# file that escaped the check is a file nobody checked.
SHELL_FILES = find . -name '*.sh' -not -path './.git/*' -not -path './.slim/*' -not -path './data/*'

check: check-bash check-installer
check-bash:
	@$(SHELL_FILES) -exec bash -n {} \;
	@echo "bash syntax OK"

# Fresh-install and existing-install paths, end to end, with the release
# fixture instead of the network.
check-installer:
	@bash scripts/test-installer-go.sh

lint:
	@$(SHELL_FILES) -exec bash -n {} \;
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt: not formatted:"; echo "$$out"; exit 1; fi
	go vet ./...

format:
	gofmt -w .

check-version:
	@v=$$(grep -m1 'var Version' internal/version/version.go | cut -d'"' -f2); \
	grep -q "VERSION=\"$$v\"" internal/assets/ovnode.sh || { echo "ovnode.sh version mismatch ($$v)"; exit 1; }; \
	grep -q "badge/version-$$v-blue" README.md || { echo "README badge mismatch ($$v)"; exit 1; }; \
	echo "version parity OK: $$v"

verify: lint check-version
	go run ./cmd/ovnode version
	@echo "Version parity: binary reports above"

clean:
	rm -f ovnode
	rm -rf out
