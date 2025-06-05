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
	uv run mypy --ignore-missing-imports --install-types --non-interactive --package python_repo_template

test:
	uv run pytest --verbose --color=yes tests

validate: format lint test

dockerize:
	docker build -t python-repo-template .

# Use it like:
# just run 10
run number:
	uv run main.py --number {{number}}