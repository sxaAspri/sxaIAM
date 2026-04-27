# Contributing

Contributions are welcome — especially new escalation techniques, bug fixes,
and improvements to the documentation.

## Setup

```bash
git clone https://github.com/sxaAspri/sxaIAM
cd sxaIAM
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running tests

```bash
# All tests (no AWS credentials needed)
pytest

# Only unit tests
pytest tests/unit/

# With coverage report
pytest --cov=sxaiam --cov-report=term-missing
```

## Adding a new escalation technique

This is the most common contribution. The architecture is designed to make this easy —
you only need to touch two files.

### Step 1 — Create the technique class

In `sxaiam/findings/techniques.py`, add a new class that inherits from `EscalationTechnique`:

```python
class MyNewTechnique(EscalationTechnique):

    @property
    def technique_id(self) -> str:
        return "my-new-technique"

    @property
    def name(self) -> str:
        return "MyNewTechnique description"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    @property
    def required_actions(self) -> list[str]:
        return ["iam:SomeAction"]

    @property
    def description(self) -> str:
        return "One paragraph explaining the attack vector."

    def check(
        self,
        identity: ResolvedIdentity,
        snapshot: IAMSnapshot,
    ) -> list[TechniqueMatch]:
        matches = []

        # 1. Check if the identity has the required permissions
        if not identity.can("iam:SomeAction", "*"):
            return []

        # 2. Find viable targets in the snapshot
        for target in snapshot.users:  # or roles, groups, policies
            if target.arn == identity.arn:
                continue

            # 3. Build evidence and return a TechniqueMatch
            evidence = self._build_evidence(identity, ["iam:SomeAction"])
            matches.append(TechniqueMatch(
                technique_id=self.technique_id,
                technique_name=self.name,
                severity=self.severity,
                origin_arn=identity.arn,
                origin_name=identity.name,
                target_arn="sxaiam::admin",
                target_name=target.name,
                description=self.description,
                evidence=evidence,
                attack_steps=[
                    f"1. Call iam:SomeAction with ...",
                    f"2. Result: escalated to admin",
                ],
            ))

        return matches
```

### Step 2 — Register the technique

At the bottom of `techniques.py`, add your class to `ALL_TECHNIQUES`:

```python
ALL_TECHNIQUES = [
    CreatePolicyVersionTechnique,
    # ... existing techniques ...
    MyNewTechnique,  # ← add here
]
```

### Step 3 — Write tests

In `tests/unit/findings/test_techniques.py`, add a test class:

```python
class TestMyNewTechnique:

    def test_detects_attack(self) -> None:
        # Build a minimal snapshot with the vulnerable configuration
        policy = make_policy("MyPolicy", "arn:aws:iam::123:policy/MyPolicy", "iam:SomeAction")
        user = IAMUser(name="attacker", arn="arn:aws:iam::123:user/attacker", ...)
        snapshot = make_snapshot(users=[user], policies=[policy])
        identity = resolve_user(user, snapshot)

        matches = MyNewTechnique().check(identity, snapshot)
        assert len(matches) >= 1
        assert matches[0].severity == Severity.HIGH

    def test_no_match_without_permission(self) -> None:
        # Verify it doesn't fire when the permission is absent
        ...
```

### Step 4 — Add Terraform (optional but recommended)

If you want to validate the technique against a real AWS account, add a
`path{N}_your_technique.tf` file in `terraform/modules/vulnerable_identities/`.

### Step 5 — Update the technique count test

In `test_techniques.py`, update `TestAllTechniques.test_registry_has_nine_techniques`
to reflect the new count.

---

## Architecture principles

Before submitting a PR, make sure your contribution respects these rules:

1. **Extensible node types** — don't assume the graph only has users and roles
2. **Resolver and graph are separate** — the technique never calls the resolver directly
3. **Technique knowledge stays in techniques.py** — no escalation logic in the graph engine or builder

## Code style

```bash
ruff check sxaiam/   # linting
mypy sxaiam/         # type checking
```

PRs should pass both without errors.

## References

- [Rhino Security Labs — AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [AWS IAM documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/)