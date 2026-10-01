# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

.PHONY: setup test check check-cli check-bash lint format verify openapi clean

setup:
	uv sync --frozen

# The full suite: 51s. This venv has no pytest-xdist, so it is serial — adding
# it would help only on a box with more than one core to spare. Run before a
# commit, not on every save.
test:
	uv run pytest tests/ -q

# The inner loop. 12s against 51s, covering everything manager.sh and
# scripts/lib/ print or dispatch — which is nearly every change to either.
check: check-cli check-bash

check-cli:
	uv run pytest -q -p no:cacheprovider \
	  tests/test_cli_shape.py tests/test_manager_sh.py

check-bash:
	uv run pytest -q -p no:cacheprovider \
	  tests/test_ui_output.py tests/test_no_duplicate_functions.py

lint:
	ruff check core/ tests/
	ruff format --check core/ tests/
	bash -n install.sh manager.sh scripts/lib/*.sh

format:
	ruff format core/
	ruff check --fix core/

verify: lint
	uv run python -c "from core.app import api; print('App imports OK')"
	uv run python -c "from core.config import settings; print('Config loads OK')"

openapi:
	uv run python scripts/export_openapi.py

clean:
	rm -rf .pytest_cache .ruff_cache
	find core tests -name '__pycache__' -type d -prune -exec rm -rf {} +
