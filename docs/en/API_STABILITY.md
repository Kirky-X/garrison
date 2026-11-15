# 🧱 Garrison API Stability Tiers (v1.0 Gate Artifact Complete)

> **Positioning statement**: this document is the **repository-side artifact** of the v1.0 "API freeze" gate (stability tiering, freeze checklist, public-surface baseline capture methodology, and PR-level report-only diff), and it is complete; **it does not mean the 1.0 API freeze has been declared** — the current version is still `0.9.0-rc.x`, the 0.x stage allows breaking changes per the [SemVer policy](./ROADMAP.md), and the 1.0.0 release must wait for external conditions such as a third-party audit (see the ROADMAP "v1.0.0 Stable" gate table). This document first writes "which surfaces are semver-protected after 1.0 and which remain experimental" into a reviewable checklist, and provides the capture methodology for the public-surface baseline.

## 📋 Table of Contents

- [Stability Tiers](#-stability-tiers)
- [Module Tier List](#-module-tier-list)
- [Freeze Checklist](#-freeze-checklist)
- [Public-Surface Baseline Capture](#-public-surface-baseline-capture)
- [Deprecation Workflow](#-deprecation-workflow)
- [Related Documents](#-related-documents)

---

## 🎯 Stability Tiers

| Tier | Commitment after 1.0 | Typical objects |
|------|-----------|---------|
| **Stable** | Protected by semver: breaking changes only in majors; minors add but never change | `GarrisonManager` / `GarrisonUtil` / `GarrisonConfig` / `GarrisonDao` / `GarrisonError` / the session and permission core traits |
| **Stable-with-feature** | Same as above, but only present when the feature is enabled; the feature name itself is API | Protocol layer (`protocol-*`), security layer (`secure-*`), Web adapters (`web-*`), `account-*`, `abac`, `oauth2-server` |
| **Experimental** | May change in minors; no cross-minor compatibility promise | `config-distributed` / `db-saga` / advanced `firewall-*` passthrough / `backend-kit` / `garrison-testing` / `cli-ops` |
| **Internal** | Not API; may be removed at any time | `#[doc(hidden)]` items, `src/dao/testing`, `src/stp/mock`, `src/manager/mock` |

> Classification principle: **entry points appearing in user docs (README / API_REFERENCE / CONFIGURATION) = Stable candidates**; capabilities appearing only in the CHANGELOG or source comments = Experimental.

---

## 🧩 Module Tier List

| Module / entry | Tier | Notes |
|-------------|------|------|
| `manager` (`GarrisonManager` / builder) | Stable | `build` / `build_explicit` signatures need re-review before freeze |
| `stp` (login / session / permission / token sub-traits) | Stable | The `GarrisonCore` super-trait has been split |
| `session` (`GarrisonSession`) | Stable | Stored key format is digested; a format change is a major |
| `dao` (`GarrisonDao` / `InMemoryDao` / `GarrisonDaoOxcache`) | Stable | New trait methods need default implementations, otherwise major |
| `config` (`GarrisonConfig` / `RateLimitBackend`) | Stable-with-feature | `rate_limit_backend` is gated by `rate-limit-redis` |
| `error` (`GarrisonError` / `GarrisonResult`) | Stable | Freeze list of error-code prefixes and variant semantics below |
| `protocol::*` | Stable-with-feature | The feature name of each protocol module is API |
| `secure::*` | Stable-with-feature | The constant-time comparison primitive `secure::ct_eq` is Stable |
| `web_axum` / `web_actix` / `web_warp` | Stable-with-feature | Adapter traits and middleware names |
| `account::*` | Stable-with-feature | Credential SPI / password policy / lockout policy |
| `abac` / `oauth2_server` | Stable-with-feature | Cedar / OAuth2 Server |
| `limiteron` (`LimiterBackend` / `LimiterRuntime`) | Stable-with-feature | Added in rc.4; `RedisLimiterBackend` gated by `rate-limit-redis` |
| `strategy::firewall::*` | Stable-with-feature | Policy constructor signatures such as `RateLimitStrategy` / `BruteForceStrategy` |
| `cli-ops` | Experimental | Ops binary; output format may change |
| `config-distributed` / `db-saga` / `backend-kit` | Experimental | In-house library passthrough surfaces |
| `dao::testing` / `stp::mock` | Internal | Test helpers, no promises |

---

## ✅ Freeze Checklist

Every item must be closed before 1.0; this round only establishes the checklist and baseline, with no bulk code changes.

- [ ] **Public-item list**: generate the baseline with `scripts/api_surface.sh` and mark each item Stable / Experimental / Internal.
- [ ] **`#[non_exhaustive]` audit**: for public enums/structs that may gain variants (especially `GarrisonError`, config enums, `RateLimitBackend`), evaluate adding `#[non_exhaustive]`.
- [ ] **Error-code freeze**: the prefix codes of `GarrisonError::prefixed_code()` (`stp-*` / `config-*` / `strategy-*` etc.) are frozen as a monitoring contract; new codes add but never change.
- [ ] **Config-key freeze**: key names appearing in `docs/CONFIGURATION.md` are frozen; deprecated keys migrate via the R12 registry, and from 1.0 unmigrated keys are rejected.
- [ ] **Feature-name freeze**: the public feature names in `Cargo.toml [features]` are API; the internal `http` bridge feature is marked `[INTERNAL]` in the docs.
- [ ] **Storage key-format freeze**: changes to session keys (`token:session:{sha256}`) and rate-limit keys (`fw:*` / `rl:*`) require a major + migration guide.
- [ ] **MSRV policy**: `rust-version` changes only in minors; after 1.0 keep at least one minor as the upgrade window.
- [ ] **Trait object safety**: re-review `dyn` usability of all public traits before 1.0; prefer default implementations for new methods.
- [ ] **Prelude freeze**: `garrison::prelude` is add-only; removal requires a major.

---

## 📏 Public-Surface Baseline Capture

```bash
# Requires nightly (rustdoc JSON)
cargo +nightly rustdoc --features full --lib -- -Zunstable-options --output-format json
bash scripts/api_surface.sh                 # emits logs/api-surface.txt
bash scripts/api_surface.sh --diff <baseline>
bash scripts/api_surface.sh --help          # usage and exit-code semantics (no rustdoc build triggered)
```

- `scripts/api_surface.sh` invokes `scripts/api_surface.py` to parse the rustdoc JSON and emit a sorted "kind + public path + signature fingerprint" list with counts. Signature fingerprints cover function params/returns, public struct fields and inherent methods, trait method signatures, and type alias / constant / static types — **signature-level changes are detectable by diff** (kind-only comparison misses breaking signature changes of existing public items).
- The structured JSON from `--diff` (`logs/api-surface-diff.json`, path overridable via `API_SURFACE_DIFF_JSON`) contains `added` / `removed` / `modified` categories; `modified` further marks `kind_changed` and `signature_changed`. **Report-only**, does not block CI.
- `.github/workflows/api-surface.yml` triggers weekly + manually and uploads the `api-surface.txt` artifact; **report-only**, does not block CI.
- The baseline file is not committed to the repository (`logs/` is in `.gitignore`); before a release, archive the artifact to the release assets or an internal artifact store.

---

## 🔁 Deprecation Workflow

1. Declare the replacement and removal version in the CHANGELOG `Deprecated` section.
2. Add `#[deprecated(since = "...", note = "...")]` to the code and link the migration guide in the docs.
3. Keep for at least one minor cycle; removal after 1.0 requires a major.
4. Config keys go through the R12 deprecated-key registry (`config::deprecation`): warn at startup, reject from 1.0.

---

## 📚 Related Documents

| Document | Description |
|------|------|
| [🗺️ Roadmap](ROADMAP.md) | v1.0 four-gate status and version policy |
| [📘 API Reference](API_REFERENCE.md) | Modular quick reference of the public API |
| [⚙️ Configuration](CONFIGURATION.md) | Config key list and semantics |
| [📋 Changelog](CHANGELOG.md) | Breaking changes and deprecation records |
