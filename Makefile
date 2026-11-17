.PHONY: install lint typecheck security test coverage build validate docs clean help

help:
	@echo "Available targets:"
	@echo "  install    - Install runtime and development dependencies"
	@echo "  lint       - Run ruff checks on scripts, tests, and routing"
	@echo "  typecheck  - Run mypy in strict mode"
	@echo "  security   - Run bandit security scan on scripts"
	@echo "  test       - Run unit tests"
	@echo "  coverage   - Run tests with coverage report (min 75%)"
	@echo "  build      - Run offline build to dist/"
	@echo "  validate   - Validate configs and output artifacts"
	@echo "  docs       - Regenerate the format reference in docs/DATA_FORMATS.md"
	@echo "  clean      - Remove build artifacts and coverage data"
	@echo ""
	@echo "Example: make install lint test build"

install:
	python -m pip install -r requirements.txt
	python -m pip install -r requirements-dev.txt

lint:
	python -m ruff check scripts tests routing

typecheck:
	python -m mypy

security:
	python -m bandit -q -r scripts --severity-level medium

test:
	python -m unittest discover -s tests

coverage:
	python -m coverage run -m unittest discover -s tests
	python -m coverage report --fail-under=75

build:
	python scripts/build.py --offline --output dist

validate:
	python scripts/validate_config.py
	python scripts/validate_outputs.py dist

docs:
	python scripts/gen_docs.py

clean:
	python -m coverage erase
	rm -rf dist/* incoming/* previous/*
