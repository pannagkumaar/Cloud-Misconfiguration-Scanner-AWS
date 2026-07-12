.PHONY: install dev test lint demo demo-html clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest --cov=cloudscan --cov-report=term-missing

lint:
	ruff check cloudscan tests

demo:
	python demo/seed_demo_account.py

demo-html:
	python demo/seed_demo_account.py --output html --output-file report.html

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .coverage htmlcov build dist *.egg-info
