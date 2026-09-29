# Security Engineering Lab

A small collection of security engineering experiments and utilities built while developing practical skills in networking, Linux, Python, and application security.

The repository is organized as a working lab rather than a collection of unrelated scripts. Each addition should solve a specific problem, include tests where practical, and document the reasoning behind the implementation.

## Current work

### Module 01 — HTTP Security Header Inspection

The first module implements a passive HTTP security header inspector.

It checks for a small set of commonly used defensive response headers:

- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

The tool validates the target URL, follows redirects, applies a configurable request timeout, handles request and HTTP errors, and reports the inspection results either as human-readable output or JSON.

It is intentionally limited to passive inspection. It does not exploit endpoints, submit payloads, or attempt to bypass controls.

## Project layout

```text
security-engineering-lab/
├── src/
│   └── security_engineering_lab/
│       ├── __init__.py
│       ├── headers.py
│       └── cli.py
├── tests/
│   └── test_headers.py
├── .github/
│   └── workflows/
│       └── tests.yml
├── .gitignore
├── pyproject.toml
└── README.md
```

## Run

Create a virtual environment and install the project in editable mode:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Inspect a URL:

```bash
python -m security_engineering_lab.cli https://example.com
```

Use JSON output:

```bash
python -m security_engineering_lab.cli https://example.com --json
```

Set a custom request timeout:

```bash
python -m security_engineering_lab.cli https://example.com --timeout 5
```

Run the test suite:

```bash
pytest
```

## Engineering coverage

Module 01 covers:

- URL validation
- HTTP requests
- redirect handling
- request timeouts
- HTTP error handling
- structured result objects
- CLI design
- JSON serialization
- unit testing
- mocked network boundaries
- GitHub Actions CI

## Scope

This repository is for defensive learning and controlled experimentation. Network-facing features should only be used against systems you own or are authorized to assess.

## Direction

The lab will grow gradually across:

- network security
- Linux and system security
- application security
- security automation
- AI security
- LLM security

The focus is on understanding how systems behave, identifying weaknesses responsibly, and turning that understanding into maintainable engineering work.
