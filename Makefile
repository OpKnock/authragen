.PHONY: help install test test-ci lint typecheck security build docker-build docker-up docker-down docker-logs clean demo demo-python bench docs docs-dev release

# Default target
help:
	@echo "AuthraGen - Agent Passport Trust Layer"
	@echo ""
	@echo "Available targets:"
	@echo "  install       - Install dependencies"
	@echo "  test          - Run tests (Node.js)"
	@echo "  test-ci       - Run tests in clean temp dir (CI mode)"
	@echo "  test-python   - Run Python tests"
	@echo "  lint          - Run ESLint"
	@echo "  lint:fix      - Run ESLint with auto-fix"
	@echo "  typecheck     - Run Node.js type checking"
	@echo "  security      - Run security audits"
	@echo "  build         - Build npm package"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-up     - Start production stack"
	@echo "  docker-dev    - Start development stack"
	@echo "  docker-down   - Stop all containers"
	@echo "  docker-logs   - View container logs"
	@echo "  demo          - Run JS demo"
	@echo "  demo-python   - Run Python demo"
	@echo "  bench         - Run benchmarks"
	@echo "  docs-dev      - Start documentation dev server"
	@echo "  docs-build    - Build documentation"
	@echo "  release       - Create release (tags + pushes)"
	@echo "  clean         - Clean build artifacts"

# Install dependencies
install:
	npm ci

# Run tests
test:
	npm test

test-ci:
	AUTHRA_DATA=$$(mktemp -d) npm test

test-python:
	python -m pytest sdk_python/ -v

# Linting
lint:
	npm run lint

lint-fix:
	npm run lint:fix

# Type checking
typecheck:
	npm run typecheck

# Security
security:
	npm run security:audit
	npm run security:deps

# Build
build:
	npm pack --dry-run

# Docker
docker-build:
	docker build -t authragen:latest .

docker-build-multi:
	docker buildx build --platform linux/amd64,linux/arm64 -t authragen:latest --load .

docker-up:
	docker-compose up -d

docker-dev:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

# Demos
demo:
	npm run demo

demo-python:
	npm run demo:python

# Benchmarks
bench:
	npm run bench

# Documentation
docs-dev:
	npm run docs:dev

docs-build:
	npm run docs:build

# Release
release:
	@read -p "Version (patch/minor/major): " version; \
	npm version $$version --no-git-tag-version; \
	git add package.json; \
	git commit -m "chore: release v$$version"; \
	git tag v$$version; \
	git push origin master --tags

# Clean
clean:
	rm -rf node_modules
	rm -rf dist
	rm -rf build
	rm -rf coverage
	rm -rf *.tgz
	rm -rf .pytest_cache
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Development helpers
dev:
	npm run dev

start:
	npm start

# Health check
health:
	curl -f http://localhost:8787/health

# Generate OpenAPI spec
openapi:
	node scripts/generate-openapi.js > openapi.json

# Verify audit chain
audit-verify:
	node -e "const {verifyAuditChain}=require('./src/audit.js'); verifyAuditChain().then(r=>console.log(r))"