.PHONY: help install up down build logs migrate seed test lint fmt typecheck

help:
	@echo "Security Guardian — dev commands"
	@echo "  make up         Start the full stack (db, redis, api, worker)"
	@echo "  make down       Stop the stack"
	@echo "  make build      Rebuild images"
	@echo "  make logs       Tail service logs"
	@echo "  make install    Editable install with dev extras (local venv)"
	@echo "  make migrate    Apply DB migrations (alembic upgrade head)"
	@echo "  make seed       Bootstrap tenant/admin/customer/plans"
	@echo "  make test       Run the test suite"
	@echo "  make lint       Ruff lint"
	@echo "  make fmt        Ruff format"
	@echo "  make typecheck  mypy"

install:
	pip install --upgrade pip
	pip install -e ".[dev]"

up:
	docker compose up --build

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f --tail=100

migrate:
	alembic upgrade head

seed:
	python -m guardian_api.seed

test:
	pytest

lint:
	ruff check .

fmt:
	ruff format .

typecheck:
	mypy packages services workers
