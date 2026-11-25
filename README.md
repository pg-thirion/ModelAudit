# ModelAudit

Security regression testing for authorised LLM applications. Run reproducible evaluations against an application endpoint or a local simulated target, then use the results as a CI release gate.

## Quick start

Requires Python 3.11+. No runtime dependencies.

```sh
python -m venv .venv
# Activate the virtual environment for your shell, then:
python -m pip install -e .
modelaudit --demo secure --output reports/secure.json
modelaudit --demo vulnerable --output reports/vulnerable.json
python -m unittest discover -s tests -v
```

The vulnerable demo intentionally fails the release gate. Both demos are entirely offline and are simulations, not evaluations of a real model.

## Evaluate an application

Only evaluate systems you own or have explicit permission to test. Use a staging endpoint, synthetic data, disabled or sandboxed tools and an isolated test account. Never provide real credentials, customer data or production secrets as test fixtures.

```sh
modelaudit --endpoint https://staging.example.com/evaluate --suite suites/application.json --repeat 3 --output reports/staging.json
```

The generic HTTP adapter sends a JSON object with a single `prompt` string and expects a JSON object with a `response` string. Set the optional bearer credential in the environment variable `MODELAUDIT_TOKEN`; it is never written to a report. HTTPS is required except for explicit localhost development endpoints. Redirects are disabled. Requests run sequentially with bounded timeouts and response sizes.

For an OpenAI-compatible chat completions endpoint use `--adapter chat --model MODEL_NAME` and provide the complete endpoint URL. The adapter sends only a user message, so the test environment must supply the application policy itself. A raw model endpoint is not equivalent to an application.

## Suite format

`suites/application.json` contains illustrative, synthetic fixtures. Adapt these to your actual staging policy and seed the relevant fictional canaries in the application before running. Each case includes:

- Unique ID, category, severity, prompt and optional rationale.
- One or both lists: `required` (all markers must appear) and `forbidden` (none may appear).
- A positive control checks that ordinary requests still work.

Markers are case-insensitive literal substrings. They are intentionally deterministic, not an LLM judge. A failed required marker can indicate an availability or policy mismatch rather than an exploit. An absent forbidden marker does not prove a vulnerability is absent. Do not use the sample score as a security certification.

## Reports and release gates

Reports contain per-case and per-trial status, matched marker indexes (not values), latency, category summaries and aggregate pass rates. Prompts, raw model replies, credentials and endpoint URLs are excluded by default. Exit codes: 0 all trials pass, 1 one or more fail, 2 invalid configuration or evaluation error. Any error is fail-closed. Use `--repeat 1..10` to examine nondeterministic behaviour. A case is considered passing only when all its trials pass.

## Architecture

`suite.py` validates test definitions; `adapters.py` isolates target I/O; `engine.py` applies deterministic assertions and aggregates outcomes; `cli.py` handles execution and JSON reporting. Unit tests use only synthetic or local mock targets.

See [security methodology](docs/methodology.md) for limitations and OWASP category mapping.
