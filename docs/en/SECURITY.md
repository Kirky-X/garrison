# 🔒 Garrison Security Document

Garrison is a one-stop authentication and authorization framework for the Rust ecosystem; security is one of the project's core values. This document describes the supported version range, the vulnerability reporting process, response commitments, and security-configuration recommendations.

> **License**: the project is open source under Apache-2.0. Vulnerability reporting and disclosure follow the coordinated disclosure process described in this document.
> For deployment hardening see the [🚀 Deployment Guide](DEPLOYMENT.md); for configuration items see the [⚙️ Configuration Guide](CONFIGURATION.md).

## 📋 Table of Contents

- [Supported Versions](#-supported-versions)
- [Reporting a Vulnerability](#-reporting-a-vulnerability)
- [Response Commitments](#️-response-commitments)
- [Disclosure Policy](#-disclosure-policy)
- [Security Configuration Recommendations](#️-security-configuration-recommendations)
- [Supply Chain and Gates](#️-supply-chain-and-gates)
- [Known Security Considerations](#️-known-security-considerations)
- [Related Documents](#-reporting-a-vulnerability)

---

## 📌 Supported Versions

Garrison provides security fixes only for released versions; the development branch (`main`) promises no backports.

| Version                       | Support status       | Notes                                       |
| -------------------------- | -------------- | ------------------------------------------ |
| 0.9.x (currently `0.9.0`)      | ✅ Maintained      | Current stable version (finalized 2026-11-14), accepts security fixes |
| 0.8.x                      | 🔶 Limited maintenance    | Critical vulnerabilities only                             |
| 0.7.x                      | 🔶 Limited maintenance    | Critical vulnerabilities only                             |
| < 0.7                      | ❌ Unsupported      | No security fixes                             |

> After a new release, older versions enter the "limited maintenance" state of critical-only fixes for at least 6 months.

---

## 🐛 Reporting a Vulnerability

### Do not file public issues

**Never disclose security vulnerabilities through public GitHub Issues, Pull Requests, Discussions, or any public channel.** Public filing may lead to exploitation before a fix, endangering all users.

### Reporting channels

Report through these private channels:

1. **Preferred — GitHub Security Advisory**: submit via the [GitHub Security Advisory](https://github.com/Kirky-X/garrison/security/policy) (repo page **Security → Report a vulnerability**; supports encrypted communication and CVE requests)
2. **Alternative — email**: only when the preferred channel is unavailable, email <Kirky-X@outlook.com> (handled by Kirky.X)

### What to include

For fast triage and fixing, please include in the report:

- **Vulnerability description**: clearly state the vulnerability class and nature (e.g. privilege escalation, token forgery, session fixation).
- **Affected versions**: explicitly note the Garrison version you tested and the enabled feature combination (e.g. `--features "full"` or `--features "production"`).
- **Reproduction steps**:
  - A minimal reproducible code snippet or test case.
  - Relevant configuration (a `garrison.toml` snippet, with secrets redacted).
  - The runtime environment (OS, Rust version, dependency versions).
- **Impact assessment**:
  - What an attacker can achieve (e.g. unauthorized reads, identity forgery, DoS).
  - Trigger conditions (login required? specific configuration required?).
  - Estimated user-impact scope.
- **Suggested fix** (optional): if you have studied a fix direction, it is welcome.

---

## ⏱️ Response Commitments

| Phase     | Time window                    | Action                                                     |
| -------- | --------------------------- | -------------------------------------------------------- |
| Acknowledgement | **within 48 hours**               | A maintainer confirms receipt and assigns an owner                    |
| Initial assessment | within 7 days                      | Grade the vulnerability (Critical / High / Medium / Low) and its impact |
| Fix plan | within 14 days                     | Communicate the fix approach and release plan with the reporter                           |
| Fix release | within 90 days (adjusted by severity) | Critical / High get an urgent patch release first                  |

After the fix ships, the reporter will be publicly thanked in the GitHub Security Advisories (if they agree).

---

## 📢 Disclosure Policy

Garrison follows a **responsible disclosure** policy:

1. **Embargo**: from the report until the fix release, both sides keep vulnerability details confidential.
2. **Coordinated release**: when the fixed version ships, the vulnerability details and CVE (if applicable) are published in sync.
3. **Credit**: the reporter is thanked in the security advisory (if they agree).
4. **Early disclosure**: if the reporter agrees, vulnerability details may be shared with affected key downstream users before the fix ships so they can prepare.

> If the reporter wants public disclosure, coordinate the timing with the maintainers so publication follows the fixed release.

---

## 🛡️ Security Configuration Recommendations

When deploying Garrison in production, the following configuration items **must be changed** or watched closely:

### 1. JWT key (must change)

- **Use a strong random string**, length **≥ 32 bytes** (256 bits).

  ```bash
  # generate a 32-byte random key (base64 encoded)
  openssl rand -base64 32
  ```

- Inject it via the `GARRISON_JWT_SECRET` environment variable; **never hard-code it into code or config files**.
- Weak keys (e.g. `secret`, `123456`, the project name) are forbidden.
- Reusing one key across environments is forbidden (dev/test/production must be independent).

### 2. Redis connection (must change in production)

- Production **must enable `cache-redis`** rather than `cache-memory`.
  - `cache-memory` is oxcache's in-memory cache — lost on process restart, and multi-instance deployments cannot share session state.
  - `cache-redis` reaches Redis through oxcache, supporting distributed deployment and session sharing.
- Configure the Redis connection via `GARRISON_REDIS_URL`; TLS and password authentication are recommended.

  ```env
  GARRISON_REDIS_URL=rediss://:password@redis-host:6379/0
  ```

### 3. Environment-variable management

- The `GARRISON_JWT_SECRET` environment variable **must never enter version control**.
  - ✅ Correct: inject via environment variables, a secret manager (Vault, AWS Secrets Manager), or a `.env` file (with `.env` excluded by `.gitignore`).
  - ❌ Wrong: writing the secret in plaintext into `garrison.toml` or source code.
- Check: before committing, confirm no secrets leak in `git diff`; CI should have secret scanning (git-secrets, trufflehog, etc.).

### 4. TLS termination

- **HTTPS must be terminated at a reverse proxy** (Nginx, Caddy, AWS ALB, etc.); Garrison itself does not handle TLS.
- Ensure the link between the reverse proxy and Garrison is a trusted network (same host, intranet, or Service Mesh mTLS).
- The reverse proxy should enforce HSTS and disable legacy TLS (≤ 1.1).

### 5. Key rotation

- **Rotate API Keys and the JWT key regularly**:
  - Rotate the JWT key every 90 days; rotate immediately upon suspected leakage.
  - Multi-key transition is supported: the new key signs while the old key only verifies; retire the old key after a transition of ≥ 7 days.
  - Rotate API Keys every 180 days; proactively revoke long-unused keys.

### 6. Session timeouts

- Configure `timeout` and `active_timeout` sensibly; avoid overly long-lived session tokens.
- In high-security scenarios, shorten `active_timeout` (e.g. 3600 seconds = 1 hour).

### 7. Least privilege and auditing

- When configuring RBAC, grant only the minimum permissions needed for the business; avoid wildcard permissions (e.g. `*`).
- Enable the `listener` and `tracing-log` features to record critical authentication/authorization events for later forensics.

### 8. API Key security (`protocol-apikey`)

Garrison's API Keys (`protocol-apikey`) use the following security design:

- **Credential format**: the two-part `key_id.key_secret` (32 hex each, `.` separated). `key_id` is a public identifier, safe to log for auditing; `key_secret` is the confidential part, returned only once at generation.
- **Hashed storage (CWE-916)**: `key_secret` is **never stored** — only its `sha256` hash is stored, verified with constant-time comparison (`subtle::ConstantTimeEq`). Even a KV/database leak cannot recover the secret.
  - Rationale: API Keys are high-entropy random values (244 bits), so deterministic SHA-256 is used instead of Argon2 to keep O(1) lookups and avoid per-request slow-hash costs; this choice presumes the generation-time high-entropy invariant.
- **IP-level failure rate limiting (CWE-307)**: with `firewall-bruteforce` enabled and the client IP injected via `with_current_ip` in the web middleware, `check_api_key` counts failures per IP into brute-force protection (failure counting only; success writes nothing), banning beyond the threshold. Extract the IP via `extract_client_ip` (with trusted_proxies protection against X-Forwarded-For forgery).
- **Multi-tenant isolation (IDOR)**: `verify_with_namespace` enforces the key's namespace — a namespace-A key cannot pass in namespace B; with `tenant-isolation` enabled the DAO layer adds per-tenant key prefixes automatically for physical isolation. `ApiKeyInfo.owner_id` records the owning subject (defaulting to `login_id`) for auditing.
- **Persistence**: API Keys are stored in the DAO backend. Production **must enable `cache-redis`** rather than `cache-memory` (the latter loses all keys on process restart); enable AOF on Redis (`appendfsync everysec`) and do not rely on RDB snapshots alone, or a crash loses recent generation/revocation operations. For ACID and foreign-key-grade persistence, use a relational backend instead (`db-postgres` / `db-mysql`, via `GarrisonDaoDbnexus`), persisting API Keys to the relational database on the business side.
- **Key management**: `last_used_at` usage tracking (enabled via `with_last_used_tracking(true)`, throttled writes), `get_keys_older_than` stale-key identification (rotation policy), per-key `rate_limit`, and `with_allowed_scopes` generation-time scope-allowlist validation.
- **Backward compatibility**: the old single-token format (v0.4.1/v0.4.2, without `secret_hash`) still verifies (by existence), aging out naturally with its TTL; rotating to the new two-part format promptly is recommended.

---

## ⛓️ Supply Chain and Gates

Garrison builds multi-layer supply-chain and security gates into CI and the release process (release-stage gate criteria in the [📦 Release Workflow](RELEASING.md)):

**Dependency and release gates**:

- **`cargo deny check`** (`deny.toml`): security advisories, licenses, banned dependencies, and source verification; runs on every PR in CI (the `ci.yml` deny step), and the release gate requires 0 failures.
- **`cargo audit`**: RustSec advisory scanning, as a **local release precheck** (`scripts/release.sh`, requires 0 CRITICAL), not in CI — CI's equivalent advisory checking is covered by `cargo-deny` above (the ignore lists of `.cargo/audit.toml` and `deny.toml` stay consistent); every ignore entry in `deny.toml` carries a rationale (e.g. RUSTSEC-2023-0071, see [known security considerations](#️-known-security-considerations) below).
- **`cargo vet`** (`supply-chain/`): manual vendor-audit records — the in-house libraries (the CodeNexus family) have `safe-to-deploy` audit entries; **this repository's own crates (`garrison` / `garrison-macros`) are recorded as exempt entries** (cargo-vet takes workspace members as audit roots, so both count as audited dependency nodes and each needs a `safe-to-deploy` credential; "the auditee self-signing its own audit entry" does not constitute an independent audit); third-party exemption lists tighten progressively; audit records are public and reviewable (crowdsourced audit endorsements).
- **SBOM (CycloneDX)**: `security.yml` generates `garrison.cdx.json` over the full feature face (covering optional dependencies) and attaches it as a Release asset (`release.yml`), so downstream can audit the dependency composition.
- **Artifact Attestations**: Release assets get SLSA build provenance (`actions/attest-build-provenance`), verifiable via `gh attestation verify` that artifacts come from this repository's CI.

**Static scanning and fuzzing** (`security.yml`, PR-blocking):

- **Semgrep SAST**: the `p/rust` + `p/secrets` registry rule sets, covering auth-path anti-patterns (unsafe misuse, hard-coded secrets); the `.semgrepignore` excludes test/example fake credentials (aligned with the codeql-config.yml precedent).
- **gitleaks full-history scanning**: CI scans the entire git history on every PR (pre-commit covers staged only), with `.gitleaksignore` holding individually verified fake-credential fingerprints.
- **cargo-fuzz fuzzing**: 4 parsing-entry targets (SAML XML / OIDC discovery / JWT verify / HTTP auth headers), PR corpus regression smoke + deep weekly scans (`fuzz-weekly.yml`); crashes block.

**Basic hygiene**: pre-commit private-key scanning (gitleaks + the `detect-private-key` hook complement each other) and GitHub Actions third-party actions referenced uniformly by 40-character commit SHAs / image digests (`ci.yml` / `security.yml` / `docs.yml` / `codeql.yml`), defending against tag-replacement supply-chain attacks.

For the threat model and attack-defense boundaries see the [🛡️ Threat Model](THREAT.md); for the OWASP Top 10 category mapping see [🗺️ OWASP Top 10](OWASP_TOP10.md); for data compliance and the right to erasure see the [📋 Data Compliance Guide](DATA_COMPLIANCE.md); for cryptographic selection rationale see the [ADRs](adr-0001-argon2id-password-hashing.md).

---

## ⚠️ Known Security Considerations

The following are Garrison's currently known security-relevant considerations; evaluate whether they affect your business scenario.

### 1. The HTTP Digest MD5 algorithm is insecure

- **Description**: if HTTP Digest authentication uses the MD5 hash algorithm — MD5 is proven vulnerable to collision attacks and no longer cryptographically safe.
- **Impact**: if the `protocol-httpdigest` module explicitly selects MD5, it may be exposed to collision or offline dictionary attacks.
- **Recommendation**: use **SHA-256** instead of MD5. The `DigestAlgorithm` enum already supports the `Sha256` variant, selected explicitly via `HttpDigestAuth::new(realm, "SHA256")`.
- **Status**: SHA-256 has been supported since 0.2.0 (`DigestAlgorithm::Sha256`). **Since 0.7.0, `DigestAlgorithm::default()` is `Sha256`** (safe-by-default); only for legacy-client compatibility should MD5 be selected explicitly via `HttpDigestAuth::new(realm, "MD5")`.

### 2. API signature nonce anti-replay window

- **Description**: the `protocol-sign` API signature mechanism defends against replay via nonce + timestamp, with a default time window of **300 seconds** (`sign_window_seconds`).
- **Impact**: within the window, an attacker who captures a legitimately signed request can replay it.
- **Recommendation**:
  - High-QPS scenarios: shorten the window (e.g. 60 seconds).
  - Critical write operations: add idempotency controls at the business layer; do not rely solely on the nonce.
  - The nonce cache must be shared across instances (use `cache-redis`, not `cache-memory`).

### 3. The is_share=true shared-session risk

- **Description**: with `is_share=true`, all of an account's devices share one session token.
- **Impact**: once an attacker steals the session token on any device, they can impersonate the user on all of them.
- **Recommendation**: in high-risk scenarios (finance, payments) disable `is_share` and use per-device independent sessions.

### 4. remember_me extends the session timeout

- **Description**: with `remember_me_enabled = true`, a login request with `remember_me=true` in its params uses `remember_me_timeout` (default 7776000 seconds = 90 days) as the session TTL — far beyond the regular `timeout` (default 2592000 seconds = 30 days).
- **Impact**: a long-lived session token extends the window for exploitation after theft.
- **Recommendation**:
  - Enable `remember_me` only on trusted devices; never on public/shared devices.
  - Adjust `remember_me_timeout` per business risk; high-security scenarios may shorten it to 7 days (604800 seconds) or disable the feature.

### 5. RUSTSEC-2023-0071 (rsa crate Marvin Attack) disposition

- **Description**: the `rsa` crate in the dependency graph has a Marvin Attack timing side-channel advisory (RUSTSEC-2023-0071) with **no patched version** currently.
- **Impact assessment**: every use of `rsa` in Garrison is **private-key signing or public-key verification** — there is no RSA decryption path, while the Marvin Attack is a padding-oracle timing side channel against RSA **decryption**, unreachable via signing/verification paths:
  - `social-alipay`: RSA signing (`SigningKey`/`Signer`, signing Alipay messages).
  - The `protocol-jwt` asymmetric extensions (RS256/RS384/RS512): private-key signing + public-key verification (`JwtHandler::with_rsa_private_pem`; the verification side extracts `(n,e)` via pure pkcs1/pkcs8 DER parsing to construct the `DecodingKey` — garrison code never touches the rsa crate's decryption APIs); the JWKS endpoint exports only public components (`n`/`e`), adding no attack surface.
  - The config layer enforces RSA private keys ≥2048 bits (`validate_core`), ruling out weak-key configurations.
- **Disposition**: `deny.toml` explicitly ignores the advisory with a rationale (no patched version + signing/verification paths unaffected); `rsa` also serves as a dev-dependency for `keycloak-oidc` tests generating RSA key pairs (test environment).
- **Regression anchoring**: if RSA **decryption** capability is ever introduced (e.g. JWE decryption), the advisory must be re-assessed and protections added (constant-time decryption, or upgrading and removing the ignore entry once the rsa crate ships a fix).

### 6. YAML parsing backend dependency (unsafe-libyaml left the graph / serde-saphyr pending audit) risk acceptance

- **The old chain has left the graph (the RUSTSEC-2024-0449 exemption was removed)**: RUSTSEC-2024-0449 (unmaintained; upstream archived read-only 2024-03-25, no published exploitable vulnerabilities) against `unsafe-libyaml` 0.2.11 was reachable via `unsafe-libyaml` ← `serde_yaml_ng` ← `confers` / `dbnexus` / `limiteron` (in-house dependencies). After the in-house crates upgraded to `confers` 0.6.0-rc.11 / `dbnexus` 0.6.0-rc.10 / `limiteron` 0.3.0-rc.8, the YAML parsing backend switched from `serde_yaml_ng` to `serde-saphyr`, and `serde_yaml_ng` with `unsafe-libyaml` is **no longer in the dependency graph**.
- **Disposition**: the advisory's ignore entries were removed from `deny.toml` [advisories] and `.cargo/audit.toml` in sync — keeping them would be dead exemptions matching no crate, for which cargo-deny warns `advisory-not-detected`; the stale exemption entries for `serde_yaml_ng` / `unsafe-libyaml` in `supply-chain/config.toml` were cleaned up together.
- **The new YAML stack (pending-audit risk acceptance)**: the YAML stack currently in the graph is `serde-saphyr` 1.3.0 ← `confers` / `dbnexus` / `limiteron`, whose transitive dependencies include `granit-parser` 1.3.0, `annotate-snippets` 0.12.16, `arraydeque` 0.5.1, `encoding_rs_io` 0.1.8, and `nohash-hasher` 0.2.0. **All are third-party crates (authors bourumir-wyngs / rust-lang / andylokandy / Andrew Gallant / Parity Technologies); the repository has not audited them at source level**; they are recorded in `supply-chain/config.toml` as `safe-to-deploy` exemptions with a pending-audit backlog; the risk nature is "a third-party parser without source audit".
- **Impact assessment** (dependency graph and runtime call sites listed separately, without presuming "not in the graph"):
  - **Dependency-graph level**: `serde-saphyr` enters **all** feature combinations' artifacts via limiteron's **non-optional** dependency chain (`cargo tree --no-default-features -e normal -i serde-saphyr` shows it) — the `config-yaml` face decides whether garrison itself **calls** a YAML source, not whether the YAML parser is in the graph.
  - **Runtime call sites and input sources**:
    - The `config-yaml` face's local config-file parsing — deployer-provisioned local files, **operator input, not end-user input**.
    - The `full` / `config-full` faces' `config-consul` / `config-etcd` remote sources: KV content is fetched, **format-sniffed** (`confers`'s `detect_format_from_content`) and parsed as YAML — **deployer-managed infrastructure input** (an attacker must first obtain Consul/etcd KV write access), not direct external input.
  - **Parsing resource ceilings**: the new stack ships default budgets (`serde-saphyr`'s `max_depth` 64 / `max_nodes` 250 000 / alias-ratio guards / inclusion depth 24); the old stack's recursion-depth limit 128 and event-count cap no longer apply — YAML parsing's known DoS surface (entity expansion / deep-nesting parsing amplification) did not worsen with the stack switch.
  - **Conclusion**: acceptable within the existing capability boundary of "never parse untrusted YAML"; the moment such a capability is introduced (parsing user-uploaded YAML/templates), this section must be re-assessed with input-size and nesting-depth limits added.
- **Regression anchoring**: (1) if garrison introduces "parsing untrusted YAML input" (e.g. user-uploaded YAML/templates), re-assess this section and add protections (input-size and nesting-depth limits); (2) once `serde-saphyr` / `granit-parser` complete a source audit, replace the backlog exemptions in `supply-chain/config.toml` with real audit entries in `supply-chain/audits.toml`; (3) if the upstream YAML backend changes again, verify that the `deny.toml` / `.cargo/audit.toml` ignore sets still match the actual dependency graph.

---

For questions or suggestions about this document (non-vulnerability), use [GitHub Discussions](https://github.com/Kirky-X/garrison/discussions); security vulnerabilities follow the [reporting process](#-reporting-a-vulnerability) and are submitted privately.
