# PharmaPlatformShell

PharmaPlatformShell is the front door for the virtual pharma platform. It gives every service one login with roles, one API gateway (port 5100) that checks who is calling and what they are allowed to do, a live registry of which services exist and whether they are up, and a 21 CFR Part 11 style e-signature. Every change made through the gateway is written to AuditTrailService under the real user's name, and if the audit service is down the event is kept in a local tamper-evident file and sent later, so nothing is lost. It closes three gaps in the current portfolio: no login or roles anywhere, AuditTrailService barely called, and every app on its own port.

Build #2 of the gap map ("Platform shell: identity, gateway, audit by default"). Python package `platform_shell`, Flask 3, SQLite.

## What it links

| Existing repo | How it links | Files involved |
|---|---|---|
| AuditTrailService (gxp-audit-platform, :5056) | HTTP: `POST /log` with **form fields**; hash chain vendored so the offline spool is byte-identical | upstream `audittrail/model.py`, `audittrail/app.py`; here `platform_shell/audit.py`, `platform_shell/_vendor/audittrail_chain.py` |
| portfolio-agent | Data contract: reads `registry/registry.yaml` and `registry/*/agent.yaml` and turns them into a live registry; drop-in replacements for its scaffold | upstream `scaffold/app/auth.py`, `scaffold/app/audit_client.py`, `scaffold/agent.yaml`; here `platform_shell/service_registry.py`, `scaffold/app/*` |
| CDMOAgentContracts | Data contract: e-signatures are emitted exactly as Common 1.0.0 `signature`; user ids use the Common `identifier` pattern | upstream `schemas/Common/1.0.0.json`; vendored at `platform_shell/_vendor/common_1_0_0.json` |
| CGTDataModel (cgt-data-model, :5053) | HTTP via gateway; registered as `cgt-data-model` with alias `cdmo-semantic-layer` (portfolio-agent's name) | `examples/services/cgt-data-model.yaml` |
| GxPAIGovernance, DataAccessAnomalyMonitor | Contract: they read AuditTrailService; the gateway now feeds it logins, failed logins, access denials, e-signatures and every mutation with a real actor | audit `detail` JSON described below |
| AIAgentFleetMonitor (ml-ops-monitoring) | HTTP: services self-register and heartbeat; `GET /services` gives fleet status | `/services` endpoints |
| AssetProgramRegistry, PharmaEventBus, ProgramDirectorAgent, AssetValuationDataRoom | HTTP via `/gw/<capability>/...`; scopes per service and per route | `examples/services/*.yaml` |

Vendored code is pinned by commit (see `platform_shell/_vendor/__init__.py`). At runtime the installed `audittrail` package is used instead when it is importable.

## Quick start

```bash
pip install -e ".[dev]"
export PLATFORM_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
platform-shell init-db
platform-shell add-user tim.maguire --name "Tim Maguire" --roles program_director,bd   # prompts for password
platform-shell list-services                     # reads examples/services
platform-shell serve --port 5100                 # gateway

curl -s localhost:5100/auth/token -H 'Content-Type: application/json' \
     -d '{"username":"tim.maguire","password":"..."}'
curl -s localhost:5100/gw/asset-registry/assets/AST-000001 -H "Authorization: Bearer $TOKEN"
```

Run AuditTrailService on :5056 to receive audit events; without it, events go to `data/audit_spool.jsonl` and `platform-shell replay-audit` sends them later.

## Roles and scopes

| Role | Scopes (summary) |
|---|---|
| admin | `admin` (satisfies every check) |
| program_director | registry read/write, bus read/publish, gates read/write/sign, valuation read, dataroom read, audit read, cgt read, esign |
| cmc_lead | registry read/write, bus read/publish, gates read, cgt read/write, audit read, esign |
| clinical_lead | registry read/write, bus read/publish, gates read, esign |
| qa | registry read, bus read, gates read/sign, audit read/write, cgt read, esign |
| bd | registry read, gates read, valuation read/write, dataroom read/write, esign |
| finance | registry read, valuation read/write, dataroom read, esign |
| viewer | read-only across registry, bus, gates, valuation, services |
| partner | `dataroom:read` only (licensees, CROs, CDMOs) |
| service | machine accounts: services read/write, audit write, bus publish |

Every role except partner also has `services:read`. The full map is `ROLE_SCOPES` in `platform_shell/identity.py`.

## API reference (gateway, port 5100)

| Method and path | Scope | What it does |
|---|---|---|
| `POST /auth/token` | none | Password login (JSON or form `username`, `password`). Returns an HS256 token (iss, aud, exp, iat, sub, roles, scopes). 401 bad credentials, 423 locked |
| `GET /auth/me` | any token | The caller: sub, name, roles, scopes, auth method |
| `POST /auth/esign` | `esign:sign` | Body: `meaning` (authored, reviewed, approved, verified, released), `reason`, `resource`, and `password` (local users) or `reauth_token` (Entra users, fresh login within 5 minutes). Returns `{signature, resource, reason, audit}` |
| `GET /services[?status=up]` | `services:read` | Live registry with status |
| `GET /services/<capability>` | `services:read` | One descriptor (aliases resolve) |
| `POST /services/register` | `services:write` | Self-registration: capability, base_url, health_path, scopes, routes, ttl_seconds. A service account may only register its own capability (`svc.<capability>`) |
| `POST /services/<capability>/heartbeat` | `services:write` | Keeps a self-registered service up; missing the TTL marks it down |
| `POST /services/<capability>/check` | `services:write` | Runs the health check now |
| `ANY /gw/<capability>/<path>` | per descriptor | Authenticated, scoped, audited proxy |
| `GET /healthz`, `GET /openapi.json` | none | Liveness and contract |

**Proxy rules.** GET, HEAD and OPTIONS need the service's read scope; other methods need its write scope, unless a `routes` entry in the descriptor matches first (for example `POST /gates` on program-director needs `gates:sign`; `/dataroom` on asset-valuation needs `dataroom:read` or `dataroom:write`). The upstream receives `X-Platform-User`, `X-Platform-Roles`, `X-Request-Id`, `X-Forwarded-For`, `X-Forwarded-Prefix` and `X-Platform-Assertion` (a 60 second HS256 token for that capability only). The caller's `Authorization` and `Cookie` headers are removed, and any client-supplied `X-Platform-*` header is overwritten. Upstream `Set-Cookie` is not returned. Responses carry `X-Request-Id`, and mutations carry `X-Platform-Audit: delivered | spooled`.

**Audit by default.** Every non-read call through the gateway produces an AuditTrailService `AUTO_LOG` event with `actor` = the real user, `actor_type` = human (or automated_process for service accounts), `resource` = `asset:AST-xxxxxx` when the path or JSON body (`asset_id`, `correlation_id`, `payload.asset_id`) names an asset, otherwise `service:<capability>`, and `detail` = `{"method","path","status","request_id","capability"}`. Also recorded: logins, failed logins (actor `platform-shell`, so a failed attempt is never attributed to the claimed user), lockouts, access denials, failed signing attempts, service registrations, and e-signatures (`HUMAN_APPROVED` for approved and released, `HUMAN_REVIEWED` for reviewed and verified, `AUTO_LOG` for authored, with the signature and reason in `detail`).

## CLI reference

| Command | Purpose |
|---|---|
| `platform-shell init-db` | Create the user store |
| `platform-shell add-user <id> --name N --roles r1,r2 [--email E]` | Create a user. Password from `PLATFORM_NEW_USER_PASSWORD` or a no-echo prompt, never a CLI argument |
| `platform-shell list-users` / `unlock-user <id>` | User admin |
| `platform-shell list-services [dir or registry.yaml ...] [--json]` | Show descriptors |
| `platform-shell serve [--host --port]` | Run the gateway (development server) |
| `platform-shell replay-audit` | Send spooled audit events to AuditTrailService, in order |
| `platform-shell verify-audit-spool` | Check the spool's hash chain |

## Configuration

| Env var | Default | Notes |
|---|---|---|
| `PLATFORM_ENV` | dev | dev, test, staging, prod |
| `PLATFORM_SECRET` | none | Required (32+ chars) in staging and prod; the gateway refuses to start without it. In dev an ephemeral secret is generated with a warning |
| `PLATFORM_ISSUER`, `PLATFORM_AUDIENCE` | platform-shell, pharma-platform | Token iss and aud |
| `PLATFORM_TOKEN_TTL` | 1800 | Seconds |
| `PLATFORM_DB` | data/platform_shell.db | SQLite user store |
| `PLATFORM_LOCKOUT_THRESHOLD`, `PLATFORM_LOCKOUT_MINUTES` | 5, 15 | 0 minutes means locked until an admin unlocks |
| `PLATFORM_AUDIT_URL`, `PLATFORM_AUDIT_SPOOL` | http://localhost:5056, data/audit_spool.jsonl | Empty URL means offline (spool only) |
| `PLATFORM_SERVICES_DIR` | examples/services | Descriptor directory loaded at start |
| `PLATFORM_HEARTBEAT_TTL` | 90 | Default TTL for self-registered services |
| `PLATFORM_RATE_LIMIT_PER_MIN` | 0 | Per-user token bucket on `/gw`; 0 disables |
| `PLATFORM_OIDC_ISSUER`, `PLATFORM_OIDC_AUDIENCE`, `PLATFORM_OIDC_JWKS_URL`, `PLATFORM_OIDC_TENANT_ID` | none | Enables Entra ID tokens (RS256) at the gateway |
| `PLATFORM_OIDC_ROLE_MAP`, `PLATFORM_OIDC_DEFAULT_ROLE` | none | JSON or a YAML file; see `examples/entra_role_map.example.yaml` |

## Data model

* **User** (SQLite `users`): user_id (Common identifier pattern, so it is a valid `signer_id`), name, email, roles, scrypt hash with per-user salt and stored cost parameters, active, failed_attempts, locked_until.
* **Platform token** (HS256 JWT): iss, aud, iat, nbf, exp, jti, sub, name, roles, scopes, amr.
* **Gateway assertion**: same claims plus `typ: assertion`, `request_id`, `aud = "<audience>/<capability>"`, 60 second life.
* **Service descriptor**: portfolio-agent `agent.yaml` fields (capability, canonical_repo, agent, gxp, invocation, entities, depends_on, skill) plus optional `aliases` and a `runtime` block (base_url, health_path, scopes {read, write}, routes [{methods, path_prefix, scope}], ttl_seconds, proxy).
* **Signature** (CDMOAgentContracts Common 1.0.0): `{"signer_id","signer_name","meaning","signed_at" (RFC 3339, Z),"method":"electronic"}`. Nothing else, so it validates against the contract's `additionalProperties: false`.
* **Audit spool** (JSONL, one event per line): seq, ts, source_system, actor, actor_type, action, resource, detail, related_event_id, prev_hash, hash, spool_reason. `hash = sha256("\x1f".join([prev_hash, ts, source_system, actor, actor_type, action, resource, detail, related_event_id or ""]))`, genesis `"0"*64`, the same as AuditTrailService. Delivery state is kept in `<spool>.delivered` so the chained file is never rewritten. On replay the original local ts, seq and hash are appended to `detail` as `[spooled ts=... seq=... local_hash=...]` so the service record ties back to the local chain.

## How an existing service adopts it

1. **Copy two files.** Replace your `app/auth.py` and `app/audit_client.py` with `scaffold/app/auth.py` and `scaffold/app/audit_client.py` from this repo, and add `pyjwt[crypto]` to your dependencies. The function names and signatures are unchanged (`require_user`, `verify_token`, `audit(action, entity, entity_id, before=, after=, reason=)`), plus a new `require_scope("registry:write")` decorator.
2. **Set three env vars.** `PLATFORM_SECRET` (the gateway's value, from Key Vault), `APP_AUDIT_PLATFORM_URL` (AuditTrailService), and `PLATFORM_AUDIT_SPOOL` (a writable path). Decorate every mutating route with `@require_user` or `@require_scope(...)` and call `audit(...)` after each regulated change.
3. **Register.** Add a descriptor to the gateway's services directory (copy one from `examples/services/`), or have the service call `POST /services/register` at start-up with a `svc.<capability>` account and heartbeat inside its TTL. Clients then call it as `/gw/<capability>/...` on port 5100 instead of its own port.

### What was wrong in portfolio-agent's scaffold

* `scaffold/app/audit_client.py` posts **JSON** (`httpx.post(..., json=event)`) with fields `service`, `entity`, `entity_id`, `before`, `after`. AuditTrailService's `/log` reads **form fields** (`source_system`, `actor`, `actor_type`, `action`, `resource`, `detail`, `related_event_id`) and only accepts its five action values, so every event from a service built on the scaffold would be rejected. Because AuditTrailService answers a rejection with HTTP 200 and an HTML error banner, `raise_for_status()` never noticed. The replacement posts form fields, maps verbs like `approve` to `HUMAN_APPROVED`, detects the banner, and spools instead of losing the event.
* `scaffold/app/auth.py` `verify_token` is a placeholder that returns `{"sub": "unknown"}` for any non-empty string, so every caller was authenticated and attributed to "unknown". The replacement checks signature, expiry, issuer and audience against the shared secret (or an Entra JWKS) and accepts the gateway's per-service assertion.

## Tests

`pytest -q` runs 74 offline tests: password hashing and lockout, token issue, verify, expiry and wrong audience, Entra RS256 with a locally generated key and in-memory JWKS, RBAC allow and deny on the proxy, header injection and credential stripping, mutation audit with the real user, audit spool, tamper detection and replay, e-signatures validated against the vendored Common schema, registry load, registration, heartbeat expiry and health checks, the scaffold drop-ins, and the CLI. Two extra tests run only where checkouts of AuditTrailService and portfolio-agent exist locally, to prove compatibility with the real code; CI skips them.

## What's next

* **Azure Entra ID app registration**: define app roles matching the table above, assign groups, set `PLATFORM_OIDC_*`, and move day-to-day sign-in to Entra (the gateway already validates Entra RS256 tokens and maps roles). Add the browser sign-in flow (authorization code with PKCE), which v1 does not include.
* **Move the user store to Entra**, keeping local accounts only for break-glass admin and service accounts; e-signature for Entra users already uses a fresh re-login (`auth_time` within 5 minutes).
* **Azure API Management or Front Door in production** for TLS termination, WAF and global rate limits, with this gateway behind it for platform-specific scope and audit rules.
* **mTLS between services** (Container Apps or a service mesh) so upstreams accept traffic only from the gateway, in addition to the signed assertion.
* Registry persistence (it is in memory; static descriptors reload at start and live services re-register), token revocation lists, password expiry and history rules, and an admin UI.
