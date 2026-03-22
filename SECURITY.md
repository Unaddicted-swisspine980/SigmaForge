# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in SigmaForge, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities
2. Email the details to the repository owner
3. Include steps to reproduce the vulnerability
4. Allow reasonable time for a fix before public disclosure

## Security Considerations

SigmaForge is a detection rule generator designed for local/lab use. Please note:

- The Flask development server is **not** intended for production deployment
- Rule files are stored locally in the `rules/` directory
- No authentication is implemented by default
- If deploying in a shared environment, add appropriate access controls

## Dependencies

This project uses minimal dependencies:
- Flask 3.1.0
- PyYAML 6.0.2

Dependencies are monitored via GitHub Dependabot for known vulnerabilities.
