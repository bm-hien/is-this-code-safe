PYTHON := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: bootstrap bootstrap-locked bootstrap-micro test test-web web web-assets web-model web-model-train lint benchmark

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

test-web: web-assets
	npm run test:web

web:
	python3 -m http.server 8000 --directory web

web-assets:
	npm run build:web

web-model:
	$(PYTHON) scripts/train_web_model.py

web-model-train:
	$(PYTHON) scripts/build_micro_dataset.py
	$(PYTHON) scripts/train_web_model.py --train

lint:
	.venv/bin/ruff format --check src scripts tests
	.venv/bin/ruff check src scripts tests

benchmark:
	$(PYTHON) scripts/benchmark_corpus.py --files 1000 --repeats 5