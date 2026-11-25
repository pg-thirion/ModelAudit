# Evaluation methodology

ModelAudit is a regression harness, not a penetration testing service or a certification. Run it only on authorised staging systems. The bundled tests use invented values and harmless marker-based assertions. Configure the application with the matching test policy and fictional markers before evaluating.

## Risk coverage

The suite illustrates OWASP Top 10 for LLM Applications (2025) categories LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency, and LLM07 System Prompt Leakage. Coverage is partial, not an OWASP endorsement. A text-only tool assertion cannot determine whether a side effect actually occurred. Verify tool calls against sandbox audit logs separately.

Reference: https://genai.owasp.org/llm-top-10/

## Interpretation

A required marker tests a documented response contract. A forbidden marker tests whether a synthetic value or action acknowledgement is present. Literal matching may miss transformed or paraphrased output and may flag quotations or harmless explanations. Review failures manually. Repeat trials to expose variability, and compare identical suite versions and deployment configurations. The pass rate is the proportion of cases passing every trial, not the probability that an application is secure.

## Operational safeguards

Use a staging account, synthetic records and disabled or mock tool execution. Do not send confidential data, third-party secrets or real production credentials in prompts. The CLI is opt-in, sequential, does not discover targets and follows no redirects. Credentials are supplied through an environment variable. Reports omit prompts and replies, but case identifiers and categories may still be sensitive if you choose inappropriate names. Store reports in restricted locations. HTTP timeouts are socket-operation timeouts, not a guaranteed total wall-clock deadline.

## Future work

Add structured tool-event assertions, statistical baselines, signed report provenance, richer semantic evaluators and authenticated multi-turn application adapters. These are not implemented in v0.1.
