# Contributing to Blackline

Thanks for contributing. Blackline is an authorized-security-workflow project;
please keep changes safe, testable, and easy to review.

## Getting started

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the checks before opening a pull request:

```bash
python -m compileall -q blackline
python -m pytest -q
```

Optional local hooks can be enabled with:

```bash
pre-commit install
```

## Guidelines

- Keep the architecture boundary clear: CLI presents, core defines domain
  behavior, tools adapt external commands, and storage persists data.
- Add or update tests for behavior changes.
- Avoid committing generated runtime data, secrets, scan output, or personal
  target information.
- Keep pull requests focused and explain user-visible behavior in the
  description.
- Never use Blackline changes to facilitate unauthorized access or scanning.

## Pull requests

Use a descriptive branch name, complete the pull-request template, and make
sure CI is passing. Maintainers may request changes for correctness, safety,
security, or maintainability.
