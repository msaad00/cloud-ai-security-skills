# Contributing

Contributions are welcome. This repo follows a skills-based structure — each security automation is a self-contained skill under `skills/`.

## Adding a new skill

1. Create a directory under the layered skill tree that matches the work:
   - `skills/ingestion/<skill-name>/`
   - `skills/detection/<skill-name>/`
   - `skills/evaluation/<skill-name>/`
   - `skills/view/<skill-name>/`
   - `skills/remediation/<skill-name>/`
2. Add a `SKILL.md` with the required frontmatter:

```yaml
---
name: your-skill-name
description: >-
  One-paragraph description of what this skill does and when to use it.
license: Apache-2.0
compatibility: >-
  Runtime requirements (Python version, cloud SDKs, permissions needed).
metadata:
  author: your-github-handle
  version: 0.1.0
  frameworks:
    - Framework names this skill maps to
  cloud: aws | gcp | azure | multi
---
```

3. Put source code in `src/` within your skill directory
4. Put infrastructure-as-code in `infra/` only when the skill needs it
5. Put tests in `tests/` — every skill should have tests
6. Add a `REFERENCES.md` that links only to the official docs, schemas, APIs, or benchmark sources the skill depends on
7. Make sure `SKILL.md` explicitly includes both `Use when...` and `Do NOT use...`
8. Document whether the skill is read-only, dry-run capable, HITL-gated, or side-effectful
9. Add tests for malformed input, provider quirks, and any deprecated API shape you are intentionally supporting during migration
10. Add your skill to the catalog in `README.md` and `skills/README.md`

## Code standards

- Python 3.11+ with type hints
- No hardcoded credentials — use environment variables or AWS Secrets Manager
- Least-privilege IAM — document every permission your skill needs
- Tests use `pytest` with `moto` for AWS mocking
- Map to compliance frameworks where applicable (CIS, MITRE, NIST, OWASP)
- Prefer only official vendor docs, schemas, and APIs in `REFERENCES.md`
- Put structured results on `stdout`, debug/warning detail on `stderr`, and fail closed on invalid input
- Follow [`docs/SKILL_CONTRACT.md`](docs/SKILL_CONTRACT.md) for the minimum shipped-skill bar
- Design for all execution modes up front: CLI, CI, MCP, and persistent/serverless wrappers should not require different skill code
- If the skill can write state, require dry-run-first behavior and document the approval/audit model

## Pull request process

1. Fork the repo and create a feature branch
2. Add or modify skills following the structure above
3. Ensure tests pass: `pytest skills/<layer>/your-skill/tests/ -v`
4. Ensure linting passes: `ruff check .`
5. Ensure shared validators pass: `python scripts/validate_skill_contract.py`, `python scripts/validate_skill_integrity.py`, and `python scripts/validate_safe_skill_bar.py`
6. Open a PR against `main` with a clear description

## Security

If you find a security vulnerability, do NOT open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
