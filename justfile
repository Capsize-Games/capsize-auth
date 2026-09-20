set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

setup:
    uv sync --extra dev

build:
    uv build

test:
    uv run pytest -q

lint:
    uv run ruff check .

format:
    uv run ruff format .

typecheck:
    uv run mypy src/capsize_auth

ci: lint typecheck test build
