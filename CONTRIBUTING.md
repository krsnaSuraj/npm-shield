# Contributing to npm-shield

Thank you for your interest in contributing to npm-shield! This document
covers everything you need to know to get involved.

## Quick Start

```bash
git clone https://github.com/krsnaSuraj/npm-shield.git
cd npm-shield
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest tests/ -q
```

## Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Implement your change with tests
4. Run the full suite: `pytest tests/ -v`
5. Check linting: `ruff check . && ruff format --check .`
6. Commit with conventional format: `feat: add X` or `fix: resolve Y`
7. Push and open a pull request

## Testing

Run all tests:
```bash
pytest tests/ -v --tb=short
```

Run a specific test file:
```bash
pytest tests/test_engine.py -v
```

Coverage:
```bash
pytest tests/ --cov=npm_shield --cov-report=html
```

## Adding New Signatures

1. Edit `npm_shield/data/signatures.json`
2. Add the hash/marker/pattern with proper metadata
3. Add corresponding tests in `tests/test_signatures.py`
4. Update `CHANGELOG.md`

## Code Style

- Python 3.9+ compatible
- 4-space indentation
- Type hints required
- All public functions must have docstrings
- Maximum line length: 88 characters (Ruff default)

## Security Disclosures

**DO NOT** create public GitHub issues for security vulnerabilities.
Email `the GitHub issue tracker` instead.
See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
MIT License that is present in the repository.
