# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email security findings to the maintainer or use [GitHub's private vulnerability reporting](https://github.com/msaad00/cloud-security/security/advisories/new).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgement**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix**: Critical vulnerabilities patched within 14 days

## Security practices in this repo

- All credentials are loaded from environment variables, never hardcoded
- CSPM skills use read-only cloud permissions (SecurityAudit / Viewer roles)
- Remediation skills use least-privilege IAM with explicit deny policies on protected accounts
- S3 artifacts are KMS-encrypted
- Cross-account access is scoped by `aws:PrincipalOrgID`
- All Lambda functions run in VPC with no public internet access (unless NAT required)

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest main | Yes |
| Feature branches | No |
