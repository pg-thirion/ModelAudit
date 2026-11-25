# Security policy

Supported version: current main branch (pre-1.0).

Report vulnerabilities privately using GitHub's private vulnerability reporting if available. If unavailable, contact the repository owner privately before publishing details. Do not include real model credentials, customer records, raw model output or confidential prompts in public issues.

ModelAudit runs tests only against an explicitly chosen authorised endpoint. Use isolated staging accounts and synthetic fixtures. Do not expose the CLI as a hosted arbitrary-URL service. Do not pass credentials in endpoint URLs. Use environment variables or your CI secret store. HTTPS certificate verification is enabled by the Python standard library. Redirects and ambient HTTP proxies are disabled.

Reports omit prompt and response content. Case identifiers, labels and file locations remain operator-controlled and must be non-sensitive. Restrict report access and define retention. The tool cannot independently establish fixture readiness, event completeness or application authorisation. A passing suite does not certify an application as secure.
