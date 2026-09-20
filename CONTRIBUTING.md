# Contributing to AuthraGen

Thank you for contributing! This document outlines the process for contributing to AuthraGen.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/authragen.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Install dependencies: `npm ci`
5. Run tests: `npm test`

## Development Workflow

### Branch Naming
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation changes
- `refactor/description` - Code refactoring
- `test/description` - Test additions/changes
- `chore/description` - Maintenance tasks

### Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `security`

Examples:
```
feat(api): add approval quorum support
fix(policy): empty arrays now match nothing
docs(readme): update quickstart example
test(authorize): add replay attack test case
```

### Pull Request Process

1. Ensure all tests pass: `npm test`
2. Run linting: `npm run lint`
3. Run type checking: `npm run typecheck`
4. Update documentation if needed
5. Add tests for new functionality
6. Open PR against `main` branch
7. Address review feedback
8. Squash and merge (maintainers)

## Code Standards

### JavaScript/Node.js
- ESLint flat config (see `eslint.config.js`)
- Strict mode (`'use strict'`)
- Async/await over callbacks
- JSDoc for public APIs
- No `console.log` in production code (use structured logging)

### Python
- Ruff for linting/formatting
- Type hints for public functions
- mypy for static analysis
- Follow PEP 8

### Security
- Never commit secrets, keys, or credentials
- All crypto uses libsodium/Ed25519 via noble-ed25519
- Input validation on all endpoints
- Rate limiting on all public endpoints

## Testing Requirements

- Unit tests for all new functions
- Integration tests for API endpoints
- Adversarial tests for security features
- Minimum 90% coverage for critical paths
- Tests must be deterministic and isolated

Run tests:
```bash
npm test           # Node.js tests
npm run test:ci    # Clean temp-dir tests (CI)
python -m pytest sdk_python/ -v  # Python tests
```

## Documentation

- Update README.md for user-facing changes
- Update PROTOCOL.md for protocol changes
- Update CHANGELOG.md for releases
- Add JSDoc/docstrings for new APIs
- Update OpenAPI spec if API changes

## Release Process

Maintainers only:
1. `npm version patch|minor|major`
2. `git push origin main --tags`
3. GitHub Actions builds and publishes to npm/PyPI/Docker

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) for responsible disclosure process.

## Questions?

Open a discussion or issue. We're happy to help!