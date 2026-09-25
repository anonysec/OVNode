# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

.PHONY: setup test lint format verify openapi clean

setup:
	uv sync --frozen

test:
	uv run pytest tests/ -q

lint:
	ruff check core/
	ruff format --check core/

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
