# ADR-0004: Unified Error Model — Request-Id Echo, Retry-After Header, and Module-Prefixed Error Codes (R04)

- Status: Accepted

- Date: 2026-09-28

- Related code: `src/error.rs` (the six-tuple / `prefixed_code` / `retry_after_secs` / `RateLimited`), `src/context/request_id.rs` (task-local), `src/web/request_id.rs`, `src/web_actix/request_id.rs`, `src/web_warp/request_id.rs` (the three framework middlewares), `src/server/middleware.rs` (429 wiring), `src/server/oauth2_routes.rs` (the OIDC Retry-After header)

## Context

Before the R04 absorption items landed, the HTTP error response of `GarrisonError` carried only `error_code` (the legacy `UPPER_SNAKE_CASE` code) + `message`, with three gaps:

1. **Errors cannot be correlated with requests**: when a client reports an issue, there is no way to map an error response to the specific request in the server logs (no request-id echo).
2. **Rate limiting has no backoff guidance**: the 429 response carries no `Retry-After`, so clients can only retry blindly (the `server` rate-limit middleware built its own `{"error": "rate_limited"}` envelope, drifting from the unified error-body shape).
3. **Error codes lack the module dimension**: the legacy code is a flat string, which cannot express cross-module search or alert aggregation (grouping by `auth.*` / `sms.*`).

The absorption involved five compatibility decisions that had to be adjudicated in advance (old/new coexistence, header names, seconds format, error-body injection mechanism, public API surface).

## Decision

### Decision 1: old and new error codes coexist (the legacy codes are not deprecated)

- The legacy `error_code` (`NOT_LOGIN` etc.) is **frozen at its original values** and continues to be emitted; all existing consumers break zero.
- The new field `error_id` carries the module-prefixed code, formatted `<module>.<snake>` (e.g. `auth.not_login` / `sms.rate_limit_exceeded` / `ratelimit.rate_limited`), consistent in naming style with the existing miette dotted-code precedent `garrison.not_login`.
- The module segment of the `OAuth2` variant is `oauth` (not `oauth2`): the `<module>` segment's format constraint `^[a-z]+(_[a-z]+)*$` forbids digits, so the protocol-domain root `oauth` is used (`error_id` = `oauth.error`).
- **Single source of truth**: the `parts_and_msg_key` private function grew from a five-tuple to a six-tuple (adding `error_id: &'static str`), with every arm **manually and explicitly written statically** (no auto-derivation — a derivation rule would produce ambiguous mappings for conditional code reuse like `EXCEPTION`, and the derivation logic itself would become a second source of truth).
- The three sub-arms of the `Exception` variant (business codes -1 / -2 / other) carry `error_id` values `exception.not_login` / `exception.not_permission` / `exception.default` — they do not reuse `auth.*` (keeping `prefixed_code()` pairwise-unique across all variants, isomorphic with the existing precedent that `code()` is fixed at `EXCEPTION`).
- The old → new mapping table is written into the error-model section of [API_REFERENCE.md](API_REFERENCE.md).
- Public API: `pub fn prefixed_code() -> &'static str`; the public signatures of `code()`, `response_parts`, and `response_parts_i18n` are unchanged.

### Decision 2: the body field name is `request_id`, omitted when absent (omitempty)

The field name aligns with the pocket-id `ErrorDto` convention. When the current request has a request id (task-local), the unified error body carries the `request_id` field; when it does not (non-HTTP paths, direct test calls), **the field is omitted entirely** — no empty string or null is emitted.

### Decision 3: `Retry-After` uniformly uses delta-seconds (integer seconds, floor of 1)

No dual HTTP-date format — the upstream value, limiteron's `RateLimitSnapshot.reset_secs`, is already in seconds; a dual format would only fork parsing. `GarrisonError::retry_after_secs()` returns `Some(max(1, secs))`; a value of 0 is forced up to 1 (0 seconds would mislead clients into retrying immediately and saturating the rate-limit window). Only the `RateLimited` variant returns `Some`; all other variants return `None` (`SmsRateLimitExceeded` / `EmailRateLimitExceeded` are send-window rate limits, not gateway rate-limit semantics, and do not carry the header).

`Retry-After` is an **advisory header**: between the allow decision of the `server` rate-limit middleware and the subsequent second snapshot (`remaining()`) there is a refill window, and the OIDC `/oauth2/token` bridge path can only take the rate limiter's configured window upper bound as a conservative hint — both header values are **allowed to be stale** (advisory, not a precise promise). OIDC rate-limit errors (the token handler's `OAuth2("rate_limited: ...")` message-prefix contract) are bridged to `RateLimited` in `server::oauth2_routes` and then emit the header via the unified `with_retry_after`.

### Decision 4: header names are constants, not configuration

`X-Request-ID` / `Retry-After` are compile-time constants (`REQUEST_ID_HEADER` / `RETRY_AFTER_HEADER`), **not config items**: once header names are configurable, reverse-proxy rules, monitoring instrumentation, and client parsing all drift per deployment. The inbound `X-Request-ID` validation (non-empty, length ≤ 128, all visible ASCII `0x21..=0x7E`) is likewise built in. The inbound id is **untrusted input**: if invalid it is discarded and regenerated as a UUID v4 (defending against CRLF / header / log injection), never escaped and preserved.

### Decision 5: how `GarrisonError` is extended and the public API surface

A new `RateLimited { retry_after_secs: u64 }` variant is added (a core variant, not feature-gated; the single `u64` field does not bloat the enum, and the `size_of::<GarrisonError>() ≤ 64B` anchor is preserved). Existing variants gain no fields (that would break every construction site), and the public signatures `code()` / `response_parts()` / `response_parts_i18n()` are untouched (the six-tuple is a private internal function).

### The three frameworks differ in injection mechanics (warp back-fills)

The request id propagates via a tokio `task_local!` (`REQUEST_ID: Arc<str>`, the same mechanism as `stp`'s `CURRENT_TOKEN`); the three framework middlewares set it at the request entrance:

- **axum**: inside `middleware::from_fn`, `REQUEST_ID.scope` wraps `next.run(req)` — the handler and the unified error-body rendering (`to_json_body`) both run inside the scope, so **upfront rendering** reads the task-local directly.
- **actix-web**: the Transform/Service wraps `inner.call`. Note that actix renders `Err(Error)` at the dispatch layer (outside the scope) — the middleware calls `error_response()` itself inside the scope and renders it as `Ok(ServiceResponse)`, keeping the body's `request_id` consistent with the header; the retained clone of `HttpRequest` uses actix-web 4's official cheap Arc semantics (the historical BUG #8 Rc/match_info_mut panic belonged to the actix 3.x era and does not apply to 4.12).
- **warp**: `wrap_fn` can only compose Filters and **cannot wrap the inner filter's execution in a custom future** — the handler (which renders the error body) necessarily runs outside the scope. The adopted approach is **post-hoc back-fill**: inside `and_then` the id is generated and `scope` wraps the post-processing; for 4xx/5xx responses with `content-type: application/json`, the body is collected, parsed as JSON, and `request_id` is injected via the shared function `inject_request_id_into_error_body` before reassembly (successes and non-JSON error responses pass through with zero buffering). All three frameworks converge to the same final output shape. The defensive path is explicit and swallows no semantics: if body collection fails (stream error), the **original status code and response headers** are kept (including `Retry-After` / `X-Request-ID`) and only the body is replaced with the unified error body; if the body exceeds 4KB (matching the axum IntoResponse truncation threshold) or parses as non-JSON, injection is skipped and the response passes through unchanged.

## Consequences

**Positive:**

- Client reports can be precisely correlated with server logs via `request_id` (both the middleware span and events carry the field).
- 429 responses carry backoff guidance, and the `server` rate-limit middleware converges with the unified error-body shape (the self-built envelope is removed).
- `error_id` lets logs/monitoring aggregate by module; old/new codes coexist at zero migration cost.

**Negative / cost:**

- When adding a new variant, `parts_and_msg_key` needs the `error_id` filled in manually (the sentinel test `prefixed_code_covers_all_variants_unique_and_well_formed` enforces coverage + format validation).
- The warp path pays one body buffer + re-serialization for error responses (only 4xx/5xx JSON; success responses are zero-buffer).
- The OIDC endpoints keep their self-built error bodies (the RFC 6749 envelope) with body keys untouched; the `/oauth2/token` 429 is bridged via the `rate_limited` prefix into `RateLimited` and then gains the `Retry-After` header (the other 4 endpoints — `/oauth2/authorize`, `/oauth2/authorize/resume`, `/oauth2/revoke`, `/oauth2/introspect` — also apply `with_retry_after` but have no rate-limit source, making the header a defensive no-op) — the coexistence of the two error-body shapes (OAuth2 `error` vs the unified `error_code`) is a pre-existing contract, not introduced by this change.

**Test anchors:** sentinel counts 29/33/30/34 (four cfg combinations), the full legacy-code freeze table (`legacy_error_codes_frozen_at_original_values` covering every arm's status code / error_code / `code()`, row count aligned with `all_variant_samples()`), `prefixed_code` uniqueness + format across all variants, the `retry_after_secs` floor, size ≤64B, the three-framework X-Request-ID / request_id / Retry-After parity assertion sets, the OIDC 429 Retry-After header assertion, and the rate-limit log-degradation warn assertion.
