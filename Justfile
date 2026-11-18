# https://github.com/casey/just

dev-sync:
    uv sync --all-extras --cache-dir .uv_cache

prod-sync:
	uv sync --all-extras --no-dev --cache-dir .uv_cache

install-hooks:
	uv run pre-commit install

format:
	uv run ruff format

lint:
	uv run ruff check --fix
test:
	uv run pytest --verbose --color=yes tests

validate: format lint test

format-check:
	uv run ruff format --check

lint-check:
	uv run ruff check

# CI runs this: it fails on format and lint problems instead of fixing them
check: format-check lint-check test

dockerize:
	docker build -t python-repo-template .

# Use it like:
# just run 10
run number:
	uv run main.py --number {{number}}