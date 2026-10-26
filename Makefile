# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

.PHONY: setup test check check-cli check-bash lint format verify clean

setup:
	go mod download

test:
	go test ./...

# Every shell file in the tree, found rather than listed: a list drifts and a
# file that escaped the check is a file nobody checked.
SHELL_FILES = find . -name '*.sh' -not -path './.git/*' -not -path './.slim/*' -not -path './data/*'

check: check-bash
check-bash:
	@$(SHELL_FILES) -exec bash -n {} \;
	@echo "bash syntax OK"

lint:
	@$(SHELL_FILES) -exec bash -n {} \;
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt: not formatted:"; echo "$$out"; exit 1; fi
	go vet ./...

format:
	gofmt -w .

verify: lint
	go run ./cmd/ovnode version
	@echo "Version parity: binary reports above"

clean:
	rm -f ovnode
	rm -rf out
