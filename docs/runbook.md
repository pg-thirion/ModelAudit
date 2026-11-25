# Operator runbook

1. Obtain written authorisation and define the staging environment, test window and request budget.
2. Create isolated synthetic users, seed the fictional markers used in your suite, configure read-only or mocked tools, and independently verify the fixtures. Never use real personal information.
3. Instrument your generic endpoint to return {"response":"text","events":["audit_read"]}. Event identifiers must come from the actual sandbox execution trace and be scoped to the request. Use an empty list only when instrumentation confirms no events.
4. Run a positive control for each instrumentation and data-access path. Adjust expected markers to the application's documented contract. Do not assume a refusal proves fixture readiness.
5. Set MODELAUDIT_TOKEN in your secret store if needed. Run the CLI with --confirm-fixtures and --target-label, and save a JSON report. Do not use the bundled generic event suite with a raw chat endpoint.
6. Gate deployment on exit code zero. Investigate assertion failures and evaluation errors before release. Compare against a baseline produced with identical suite, trial count and target configuration. Baselines are not signed, so protect them from tampering.
7. Review application-side audit logs, check for false positives and false negatives, and track remediation separately.
8. Delete synthetic test records and revoke temporary credentials according to your team's policy.

## Operational constraints

Sequential requests, maximum 200 cases and 10 trials per case. The timeout is per socket operation, not an overall deadline. Use a job-level timeout in CI and enforce rate and cost limits at the target. No automatic retries, to avoid accidentally duplicating actions. No real tool execution is necessary for the default suite.
