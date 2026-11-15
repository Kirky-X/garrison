# OWASP ASVS 4.0 Self-Assessment — Garrison

> **Positioning statement**: this document is Garrison's **self-assessment record** for the OWASP Application Security Verification Standard 4.0 **V2 (Authentication) and V3 (Session Management)** chapters — a self-assessment is not a certification and provides no third-party guarantee. As a **framework** (not the final application), the assessment scope is "capabilities/default behavior provided by the framework"; a rating of "not applicable" means the control belongs to the final application or the deployer, outside what a framework SDK can cover.
>
> Rating legend: ✅ satisfied (provided by the framework and tested) | 🔶 partially satisfied (the framework provides the foundation; the business must configure/combine) | ⚪ not applicable (application/deployer responsibility)
>
> Related: [SECURITY.md](SECURITY.md) | [THREAT.md](./THREAT.md) | ADR-0001/0002/0003 (password hashing / CSPRNG / constant-time comparison)

## V2 Authentication

### V2.1 Password Security

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 2.1.1 | User-set passwords must meet strength requirements | 🔶 | The `account-policy` password policy engine (`src/account/policy/`, length/complexity rules configurable); thresholds set by the business |
| 2.1.2 | Passwords ≥64 bytes must be supported (no truncation) | 🔶 | Passwords are passed to `PasswordHasher` as `&str` with no framework-level truncation; upper-bound policy belongs to the business |
| 2.1.3 | Passwords free of control characters / normalization applied | ✅ | `unicode-normalization` NFC normalization participates in credential processing; `secure-confusable` provides homoglyph detection |
| 2.1.6 | Password change must verify the old password | 🔶 | The credential verification primitive is provided by `account-credential`; the change-flow orchestration belongs to the business (`account-authflow` provides the foundation) |
| 2.1.7 | Weak-password dictionary / breach-corpus check | ✅ | `policy-hibp` (HIBP k-anonymity range query, never leaks the original password) + pluggable policy rules |
| 2.1.9 | Password hashing: salted + slow hash (Argon2id etc.) | ✅ | `Argon2Hasher` (Argon2id m=19456/t=2/p=1, PHC self-describing salt); locking tests + ADR-0001 |
| 2.1.11 | Password hash algorithm and parameters upgradeable | ✅ | PHC strings self-describe parameters and verify parses from the string (ADR-0001 Decision 4); the `password_hasher` section controls parameters (floor validation) |

### V2.2 General User Security

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 2.2.1 | Anti-automation: exposed login/reset/registration control planes must have anti-automation measures | ✅ | `firewall-bruteforce` (IP-level failure-count bans, CWE-307) + `firewall-ratelimit`; API Key verification failures count per IP (`protocol-apikey` + `with_current_ip`) |
| 2.2.2 | Login-failure messages must not distinguish "user does not exist / wrong password" | 🔶 | The error-message i18n system (`GarrisonError` structured) supports unified wording; the specific copy is configured by the business |
| 2.2.4 | Registration credentials must be checked against known breach corpora | 🔶 | `policy-hibp` can be enabled in the registration orchestration; whether to enforce it is the business's decision |

### V2.3 Authenticator Lifecycle

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 2.3.1 | New authenticators must verify user identity (including reset flows) | 🔶 | The `account-authflow` condition engine (IP allowlists etc.) + `protocol-invitation` invitation-code directed registration (one-shot/TTL/brute-force protection); the full identity-verification chain is orchestrated by the business |
| 2.3.3 | Invalidate old sessions after credential updates | ✅ | The `listener/audit` Replaced event + login displacement/replacement semantics (`stp/session`, ReplacedLoginExitMode configurable kick policy) |

### V2.5 General Authenticators

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 2.5.1 | The system must resist brute-force attacks | ✅ | `firewall-bruteforce` + `account-lockout` + `firewall-ratelimit` (GCRA/sliding window); `rate-limit-redis` wires cross-instance counting for the login hook + `RateLimitStrategy` (rc.4, candidate B) |
| 2.5.2 | Security verification codes (OTP) must be generated securely by the system | ✅ | Backup codes/verification codes use `getrandom::fill` (OS CSPRNG, ADR-0002); email verification codes of `email-verification` share the same source |

### V2.7 Single Sign-On / MFA

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 2.7.1 | Authentication policy for federated SSO (CSRF protection, anti-redirect abuse) | 🔶 | `protocol-sso-server` (SsoServer/channel subscription model), OIDC one-shot `state` + TTL; SP-side policy belongs to the business |
| 2.7.3 | MFA binding must verify possession | 🔶 | `secure-totp` (TOTP binding-verification primitive); MFA flow orchestration belongs to the business |

### V2.8 TOTP / Time-Based OTP

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 2.8.1 | TOTP keys ≥20 bytes, unique per account | ✅ | `TotpHandler::new` errors on keys <10 bytes (totp-rs constraint + framework validation); keys are generated by the caller (CSPRNG recommended) |
| 2.8.2 | TOTP algorithm consistency (RFC 6238) | ✅ | Locked by the official RFC 6238 Appendix B test vectors (SHA1/SHA256/SHA512, `src/secure/totp/tests.rs`) |

## V3 Session Management

### V3.1 Fundamentals

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 3.1.1 | Session tokens should follow user permissions and be revocable | ✅ | Sessions are stored centrally in the DAO (`backend-embedded`/`backend-remote`); `enable_jwt_revocation` + the JWT Mixin pattern guard against stateless orphaning; Stateless + no revocation requires the explicit risk acceptance `allow_stateless_jwt_no_revocation` |
| 3.1.2 | Token generation must resist prediction (CSPRNG) | ✅ | Token/authorization-code/refresh generation uniformly uses `getrandom::fill` (ADR-0002); `secure-simple-token` returns Err from generate when signing is not enabled (fail-closed) |

### V3.2 Session Creation

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 3.2.1 | Login must generate a new session token (session-fixation defense) | ✅ | Login/replacement semantics generate a new token (`stp/session`, the old session handled per the Replaced policy) |
| 3.2.2 | No session may be created before credential verification | ✅ | verify_token sits on the pre-session-creation path (`stp/session/helpers.rs` flow) |

### V3.3 Session Termination

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 3.3.2 | Any session can be terminated by the user/administrator (logout) | ✅ | Logout/kick APIs (`stp/session` + Manager API); the Kickout mode of `session-hijack-detection` |
| 3.3.3 | Sessions invalidate server-side after timeout | ✅ | `timeout`/`active_timeout` (config) drive DAO expiry; `session-extra` dynamic active-timeout |

### V3.4 Cookie Configuration (Web Adapter Layer)

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 3.4.1 | cookie `SameSite` configuration | ✅ | Cookie security attributes are consolidated into the single construction point `src/context/cookie.rs::build_set_cookie_value`: `HttpOnly` is always emitted; `SameSite` takes `cookie_same_site` (allowlist Lax/Strict/None, default Lax; `SameSite=None` downgrades to `Lax` in non-Secure contexts); `Secure` takes `cookie_secure` — default `true` for non-`development` profiles (`src/config/mod.rs::DEFAULT_COOKIE_SECURE`), default `false` for the `development` profile to support local HTTP debugging (both explicitly overridable via `GarrisonConfig`); `production` + Secure context resolves `__Host-` / `__Secure-` prefixes. Regression tests in `tests/web_security.rs` (default tiers, explicit overrides, None→Lax downgrade) |
| 3.4.2 | Cookie domain and path minimization | ⚪ | Deployers configure per application domain (`CookieType::path` / `domain` supplied by the caller; the framework only validates the values, rejecting `;` and control-character injection) |

### V3.5 Token-Based Sessions

| # | Control | Rating | Evidence |
|---|--------|------|------|
| 3.5.1 | Bearer tokens carried via the Authorization header and never in URLs | 🔶 | The framework supports header carriage and parsing; client behavior belongs to the business |
| 3.5.3 | JWTs must verify signature and algorithm consistency | ✅ | `JwtHandler` key-type-aware allowlist (KeyMaterial, `validate_algorithm_match`) + alg-confusion adversarial tests locked; config-layer algorithm allowlist `JWT_ALGORITHMS` |
| 3.5.4 | Replay/expired tokens rejected | ✅ | `leeway=0`, mandatory `exp`/`nbf` verification; refresh-token replay handled by `RefreshTokenRotation` reuse detection (a startup warn alerts explicitly when not injected) |
| 3.5.5 | Token lifetimes minimized | 🔶 | timeout/active_timeout/remember_me_timeout configurable (defaults 30d/90d; SECURITY.md recommends tightening); default choices are a business trade-off |

## Self-Assessment Conclusions and Gaps

**Coverage strengths**: password hashing (V2.1), brute-force protection (V2.2/2.5), token generation and verification (V3.1/3.5), session termination (V3.3), cookie security defaults (V3.4) — all with code-level evidence and regression tests.

**Enhancements pending within the framework boundary (recorded as ROADMAP candidates)**:

1. The V2.7 MFA orchestration foundation can be further abstracted (the TOTP primitive is ready).

**Enhancement items closed this round**:

- V3.4 cookie security attributes safe-by-default: delivered — cookie security defaults are consolidated into the single construction point `src/context/cookie.rs` (profile-aware `Secure`, constant `HttpOnly`, `SameSite=None` downgraded to `Lax` in non-Secure contexts, `production` prefix resolution); regression in `tests/web_security.rs`; the corresponding entry in the `docs/en/ROADMAP.md` candidate pool is marked delivered.

**Explicitly out of framework scope**: the final application's user-UI interactions, deployment-layer TLS, and the business authorization rules themselves.
