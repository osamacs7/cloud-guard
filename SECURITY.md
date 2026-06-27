# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities through GitHub Security Advisories rather than public issues.

1. Go to the Security tab of this repository
2. Click "Report a vulnerability"
3. Provide a description with steps to reproduce

We aim to respond within 48 hours and provide a fix within 7 days for critical issues.

## Security Practices

- All dependencies are scanned weekly via GitHub Actions
- SAST scanning with Bandit and Semgrep on every PR
- Container images scanned with Trivy
- Secret scanning with TruffleHog
- RBAC enforced on all API endpoints
- JWT tokens with configurable expiry
- Passwords hashed with bcrypt
- All database queries use parameterized statements via SQLAlchemy ORM
