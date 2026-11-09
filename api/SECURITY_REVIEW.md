# Swarms Agent API security review (candidate, not production qualification)

This draft addresses missing route authentication and owner binding in
`api/main.py`. Every agent endpoint is required to authenticate an API key,
and operations on a specific agent must verify server-side owner identity or
an explicitly flagged administrator before reading, mutating, executing,
cloning or deleting it. Agent IDs must not substitute for authorization.
New agent names are restricted to safe ASCII filename components to protect
autosave paths. CORS defaults to no cross-origin origins; an operator may
explicitly set a comma-delimited `SWARMS_CORS_ORIGINS` list without `*`.

The regression workflow checks the pure ownership decision, validates
route syntax on Python 3.11–3.13, and separately exercises **real FastAPI
HTTP requests** under a test client using an in-process fake Agent, without
calling a live model. These tests cover cross-user access denial, owner-only
listing, clone/delete behavior, unsafe filenames and CORS defaults. They do
**not** exercise a deployed server, production credentials, external networks,
reverse proxies, multi-worker processes, real LLM execution or load tests.

**Major remaining blockers:** public user self-registration issues an initial
API key; API keys and ownership records live only in process memory; there is
no durable encrypted credential store, rate limiting, hardened onboarding,
external identity provider, robust concurrency policy, or independent security
assessment. Actual LLM calls can incur costs and must not run in smoke tests.
No external integrations, host resources or live model endpoints are exercised
by this review-only CI. Keep deployment prohibited pending separate hardening.
