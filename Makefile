PYTHON := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: bootstrap bootstrap-locked bootstrap-micro test lint benchmark

bootstrap:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

bootstrap-locked:
	python3 -m venv .venv
	$(PIP) install -r requirements-cpu-lock.txt
	$(PIP) install -e . --no-deps

bootstrap-micro: bootstrap
	$(PIP) install numpy
	$(PIP) install torch --index-url https://download.pytorch.org/whl/cpu

test:
	$(PYTHON) -m pytest -q

lint:
	.venv/bin/ruff format --check src scripts tests
	.venv/bin/ruff check src scripts tests

benchmark:
	$(PYTHON) scripts/benchmark_corpus.py --files 1000 --repeats 5