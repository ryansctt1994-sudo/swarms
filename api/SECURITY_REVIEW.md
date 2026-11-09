# Swarms Agent API security review (candidate, not production qualification)

This draft addresses missing route authentication and owner binding in
`api/main.py`. Every agent endpoint is required to authenticate an API key,
and operations on a specific agent must verify server-side owner identity or
an explicitly flagged administrator before reading, mutating, executing,
cloning or deleting it. Agent IDs must not substitute for authorization.
New agent names are restricted to safe ASCII filename components to protect
autosave paths. CORS defaults to no cross-origin origins; an operator may
explicitly set a comma-delimited `SWARMS_CORS_ORIGINS` list without `*`.

The stdlib regression workflow checks the pure ownership decision and
inspects the actual route syntax for authentication/owner guards. These are
**not end-to-end authenticated HTTP request tests** and make no runtime
security assurance about deployed servers, reverse proxies or multi-worker
processes.

**Major remaining blockers:** public user self-registration issues an initial
API key; API keys and ownership records live only in process memory; there is
no durable encrypted credential store, rate limiting, hardened onboarding,
external identity provider, robust concurrency policy, or independent security
assessment. Actual LLM calls can incur costs and must not run in smoke tests.
No external integrations, host resources or live model endpoints are exercised
by this review-only CI. Keep deployment prohibited pending separate hardening.
