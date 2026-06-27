# Contributing to Cloud Guard

## Development Setup

```bash
git clone https://github.com/username/cloud-guard.git
cd cloud-guard
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pre-commit install
```

## Code Standards

- Format with `ruff format`
- Lint with `ruff check`
- Type check with `mypy src/`
- Security scan with `bandit -r src/`

## Testing

```bash
pytest --cov=cloud_guard
```

## Pull Requests

1. Fork the repo and create a feature branch
2. Write tests for new functionality
3. Ensure all checks pass: `ruff check && mypy src/ && pytest`
4. Submit a PR with a clear description

## Security

Report security vulnerabilities privately via GitHub Security Advisories.
