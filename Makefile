.PHONY: help install dev test lint format clean docker

help:  ## Show this help message
	@echo "VES Development Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install production dependencies
	pip install -e .

dev:  ## Install development dependencies
	pip install -e ".[dev,test,cli,api,web]"
	pre-commit install

test:  ## Run test suite
	pytest tests/ -v --cov=src/ves --cov-report=html

lint:  ## Run linting
	ruff check src/ tests/
	black --check src/ tests/

format:  ## Format code
	black src/ tests/
	ruff --fix src/ tests/

clean:  ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete

docker:  ## Build Docker images
	docker build -f docker/Dockerfile.cli -t ves-cli .
	docker build -f docker/Dockerfile.api -t ves-api .

deploy-local:  ## Deploy locally with Docker Compose
	docker-compose -f docker-compose.yml up -d