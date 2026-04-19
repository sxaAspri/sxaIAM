# Contributing to iamspy

First off — thanks for taking the time to contribute. iamspy is an open source project
and every contribution helps the security community.

## How to contribute

### Reporting bugs
Open an issue describing: what you ran, what you expected, what happened instead.
Include your Python version and the iamspy version (`iamspy --version`).

### Suggesting escalation techniques
iamspy's value is in the breadth of IAM privilege escalation techniques it models.
If you know of a technique not yet covered, open an issue with:
- The technique name
- Which IAM permissions it requires
- A link to documentation or research (e.g. Rhino Security Labs, AWS docs)

### Submitting code

1. Fork the repository and create a branch from `main`.
2. Set up your dev environment:
   ```bash
   git clone https://github.com/tu-usuario/iamspy
   cd iamspy
   python -m venv .venv && source .venv/bin/activate
   pip install -e ".[dev]"
   ```
3. Make your changes. Add tests. All new code must have unit tests using `moto` for
   AWS mocking — no tests that require real AWS credentials.
4. Run the full suite before opening a PR:
   ```bash
   ruff check iamspy/
   mypy iamspy/
   pytest
   ```
5. Open a pull request with a clear description of what you changed and why.

## Architecture principles

Three rules that keep iamspy scalable. Please respect them:

1. **Extensible node types** — the graph engine works against node types, not specific
   entities. Adding a new node type (e.g. S3Bucket) should not require changes to the
   path finder.

2. **Strict separation** between the policy resolver and the graph engine. The resolver
   computes effective permissions. The graph engine models relationships. They must
   remain independently testable.

3. **Escalation techniques as configuration** — never hardcode escalation logic directly
   in the graph engine. Techniques live in `iamspy/findings/techniques.py` as pluggable
   classes, so adding a new technique is adding a class, not modifying the engine.

## Code style

- Formatter and linter: `ruff`
- Type checker: `mypy` (strict mode)
- All public functions must have type annotations and docstrings.
