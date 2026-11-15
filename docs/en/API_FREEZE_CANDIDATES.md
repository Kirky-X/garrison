# Garrison v1.0 API Freeze Candidate List

> This document is the companion review material for [API_STABILITY.md](./API_STABILITY.md): it itemizes "the surfaces protected by semver after 1.0" versus "the experimental surfaces that may still change". It is not an announcement that the freeze is complete; the current version is still `0.9.x`, and the 0.x stage allows breaking changes.

## Tiering Criteria

| Tier | Commitment after 1.0 | Basis for classification |
|------|---------------------|--------------------------|
| Stable | Breaking changes only in majors; minors add but never change | Entry points appearing in README / API_REFERENCE / CONFIGURATION / USER_GUIDE |
| Stable-with-feature | Same as above, but only present when the feature is enabled; the feature name itself is API | Protocol/security/adapter layers marked with a feature in the docs |
| Experimental | May change in minors; no cross-minor compatibility promise | Appears only in CHANGELOG, source comments, or advanced configuration |
| Internal | Not API; may be removed at any time | `#[doc(hidden)]`, test mocks, testing modules |

## Stable Candidates

| Module / entry | Key public items | Must-fix before freeze |
|-------------|-----------|-----------|
| `manager` | `GarrisonManager`, builder, `build` / `build_explicit` | Re-review builder method signatures and defaults |
| `stp` | `GarrisonCore` and the login/session/permission sub-traits | Re-review object safety after the super-trait split |
| `session` | `GarrisonSession`, session key format | Freeze the `token:session:{sha256}` format |
| `dao` | `GarrisonDao`, `InMemoryDao`, `GarrisonDaoOxcache` | New trait methods must have default implementations |
| `config` | `GarrisonConfig`, defaults, `COOKIE_SAME_SITE_VALUES` | Freeze config key names and defaults |
| `error` | `GarrisonError`, `GarrisonResult`, `prefixed_code()` | Error prefix codes add but never change; evaluate `#[non_exhaustive]` |
| `prelude` | `garrison::prelude::*` | Add-only, never remove |

## Stable-with-feature Candidates

| feature family | Modules | Must-fix before freeze |
|-----------|------|-----------|
| `protocol-*` | `protocol::{jwt, oauth2, sso, oidc, saml, webauthn, ...}` | Freeze feature names and trait signatures; prefer default impls for new methods |
| `secure-*` | `secure::{ct_eq, masking, totp, xss, sanitize, ...}` | Freeze the constant-time comparison primitive signature |
| `web-*` | `web_axum` / `web_actix` / `web_warp` | Keep the three adapter traits and middleware names consistent |
| `account-*` | `account::{credential, policy, authflow, password_reset}` | Freeze the Credential SPI and policy signatures |
| `abac` | `abac::{AbacEngine, EntityLoader}` | Freeze the Cedar version and the policy input structure |
| `oauth2-server` | `oauth2_server::*` | Freeze the scope/claim contract |
| `rate-limit-redis` | `limiteron::{LimiterBackend, LimiterRuntime}` | Freeze the backend enum and config keys |
| `firewall-*` | `strategy::firewall::*` | Freeze policy constructor signatures and key prefixes |

## Experimental / Internal

| Surface | Tier | Notes |
|----|------|------|
| `config-distributed` | Experimental | Distributed config passthrough; may change in minors |
| `db-saga` / `db-sharding` | Experimental | Advanced database orchestration; may change in minors |
| `backend-kit` | Experimental | trait-kit typestate DI; may change in minors |
| `cli-ops` | Experimental | `garrison-cli` output format may change |
| `firewall-{gcra,tower,admission,event,monitoring,parallel}` | Experimental | limiteron advanced passthrough surfaces |
| `dao::testing` / `stp::mock` / `manager::mock` | Internal | Test helpers, no promises |
| `#[doc(hidden)]` items | Internal | Not API |

## Pre-Freeze Must-Fix Checklist

| # | Item | Acceptance evidence | Status |
|---|----|---------|------|
| 1 | Tier every public item | `logs/api-surface.txt` + the tables in this document | In progress |
| 2 | `#[non_exhaustive]` audit | Review records for `GarrisonError`, config enums, `RateLimitBackend` | To do |
| 3 | Error-code freeze | Prefix-code list of `prefixed_code()` | To do |
| 4 | Config-key freeze | Key-name list in `docs/en/CONFIGURATION.md` | To do |
| 5 | Feature-name freeze | Public-surface list of `Cargo.toml [features]` | To do |
| 6 | Storage key-format freeze | Session/rate-limit key format specification | To do |
| 7 | MSRV policy | Window policy for `rust-version` changes | To do |
| 8 | Trait object safety | `cargo check` + `dyn` use cases | To do |
| 9 | Prelude freeze | Add-only review of the prelude | To do |

## API Diff Workflow

```bash
# Generate the current public surface
bash scripts/api_surface.sh

# Compare against the baseline, emit structured JSON (logs/api-surface-diff.json)
bash scripts/api_surface.sh --diff logs/api-surface.baseline.txt
```

- The PR-level diff runs automatically in `.github/workflows/api-surface-diff.yml`, **report-only**, artifacts retained for 30 days.
- The baseline file is not committed to the repository (`logs/` is ignored); before a release, archive the artifact to the release assets or an internal artifact store.
- When the freeze flips to blocking: at the 1.0-rc stage; 0.x remains report-only.

## Related Documents

- [API_STABILITY.md](./API_STABILITY.md): tiering principles, freeze checklist, deprecation workflow
- [ROADMAP.md](./ROADMAP.md): v1.0 gate status
- [CHANGELOG.md](./CHANGELOG.md): API-related changes in this round
