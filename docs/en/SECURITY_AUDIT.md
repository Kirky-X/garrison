# 🛡️ Garrison Security Audit Readiness Package (v1.0 Gate Started)

> **Positioning statement**: this document is the **starting material and evidence index** for the v1.0 "security audit" gate; it is not a third-party audit report and constitutes no certification or compliance conclusion. Internal review rolls continuously; the third-party audit has not started (see the status table at the end). All conclusions rest on reproducible commands and in-repo artifacts.

## 📋 Table of Contents

- [Audit Scope and Assets](#-audit-scope-and-assets)
- [Methodology](#-methodology)
- [Evidence Matrix](#-evidence-matrix)
- [Findings and Remediation](#-findings-and-remediation)
- [ASVS / OWASP Mapping](#-asvs--owasp-mapping)
- [Third-Party Audit Preparation (RFP Checklist)](#-third-party-audit-preparation-rfp-checklist)
- [Status Table](#-status-table)
- [Related Documents](#-related-documents)

---

## 🎯 Audit Scope and Assets

| Asset     | Description                                                                             |
| -------- | -------------------------------------------------------------------------------- |
| Auth core | Login / session / token / permission / MFA orchestration (`src/stp`, `src/session`, `src/manager`) |
| Protocol surface   | OAuth2 / OIDC / SSO / SAML / JWT / API Key / QR-code login / WebAuthn                 |
| Security primitives | Argon2id, CSPRNG, constant-time comparison, at-rest field encryption, audit chain                             |
| Data surface   | `GarrisonDao` + oxcache / dbnexus backends; digested session keys; the rate-limit Redis runtime       |
| Deployment surface   | The `auth_server` reference deployment (TLS, binding, API Key, strict tier), Docker images                |
| Supply chain   | Dependency versions, RustSec advisories, `cargo vet` audits, the release pipeline                             |

**Threat model**: see [THREAT.md](./THREAT.md); the security policy and vulnerability reporting channels are in [SECURITY.md](SECURITY.md).

---

## 🧪 Methodology

| Layer     | Method                                                                               | Frequency                |
| -------- | ---------------------------------------------------------------------------------- | ------------------- |
| SAST     | Semgrep (`p/rust` + `p/secrets`, noise-reduced via `.semgrepignore`); CodeQL (GitHub Actions) | Every PR / weekly      |
| Dependencies     | `cargo audit` + `cargo deny check` + `cargo vet` (`supply-chain/`)                | Every dependency change / weekly |
| Fuzzing | 4 targets: SAML XML / OIDC discovery / JWT verify / HTTP auth headers            | Weekly + manual deep scans     |
| Dynamic     | End-to-end acceptance (auth / protocols / multi-tenancy / concurrency / security attack surface)                             | Every release candidate        |
| Manual     | Security review batches (R01–R18 remediation), ADR reviews, ASVS self-assessment                                  | Rolling                |
| External     | Third-party penetration testing / code audit                                                          | 📋 Not started           |

---

## 📊 Evidence Matrix

| Evidence            | Command / location                                                | Artifact                                               | Current status                         |
| --------------- | ---------------------------------------------------------- | -------------------------------------------------- | -------------------------------- |
| SAST (Semgrep) | `semgrep scan --config p/rust --config p/secrets`          | CI logs / SARIF                                    | Runs with CI (semgrep installed locally) |
| SAST (CodeQL)  | `.github/workflows/codeql.yml`                             | GitHub Security alerts                               | Wired                           |
| Dependency advisories        | `cargo audit`                                              | Terminal output / CI                                      | Wired                           |
| Dependency policy        | `cargo deny check` (license / advisory / ban / source)    | Terminal output                                           | Wired                           |
| Supply-chain audit      | `cargo vet check --locked` (`supply-chain/audits.toml`)   | Terminal output                                           | Wired (tool installed locally)         |
| Fuzzing        | `cargo +nightly fuzz run <target>` (`fuzz/fuzz_targets/`) | `fuzz/artifacts/` / CI                             | Wired (weekly + 60s smoke)       |
| End-to-end security surface    | `bash scripts/e2e_run.sh` (includes the `security::` domain)            | `logs/e2e_final_report.md` / `pentest_report.json` | Reproducible                           |
| Dual-instance rate limiting      | `cargo test --features full --test redis_limiter_backend`  | Test output                                           | Added in rc.4                        |
| ASVS self-assessment       | [SECURITY_ASVS.md](./SECURITY_ASVS.md)                     | Control mapping                                         | Established (rolling)               |
| ADR             | `docs/cn/adr-0001..adr-0004`                                       | Decision records                                           | Established                           |
| Finding ledger        | `.mimosa/finding-ledger/v1`                                | JSON ledger                                          | Local tool state (not committed)           |
| Audit evidence summary    | `bash scripts/security_evidence.sh`                        | `logs/security-evidence.md`                        | Added this round                         |

---

## 🔎 Findings and Remediation

- **Input sources**: internal reviews (diting / tiangang), external security-audit conclusions, CodeQL/Semgrep alerts, dependency advisories, fuzzing crashes, community reports.
- **Grading**: CRITICAL / HIGH / MEDIUM / LOW; CRITICAL/HIGH block releases and require a fix + regression tests + a CHANGELOG entry.
- **Closure requirement**: every finding needs "symptom → root cause → fix → regression evidence → impact surface"; the remediated batches are in the [CHANGELOG](./CHANGELOG.md) (rc.2 / rc.3 / rc.4, all released).
- **Exception management**: dependency advisories that genuinely need an exemption go through `deny.toml` / `supply-chain/config.toml` with a rationale and a re-review date; exemptions without records are forbidden.

---

## 🔐 ASVS / OWASP Mapping

| Framework                 | Mapping document                               | Notes                                  |
| -------------------- | -------------------------------------- | ------------------------------------- |
| OWASP ASVS 4.0 V2/V3 | [SECURITY_ASVS.md](./SECURITY_ASVS.md) | Authentication and session-management self-assessment; rated ✅ / 🔶 / ⚪ |
| OWASP Top 10         | [OWASP_TOP10.md](./OWASP_TOP10.md)     | Risk surfaces and framework-side controls                    |
| Threat model             | [THREAT.md](./THREAT.md)               | STRIDE matrix and trust boundaries                 |

---

## 📝 Third-Party Audit Preparation (RFP Checklist)

Before starting an external audit, prepare:

1. **Scope**: the auth core + protocol surface + cryptographic primitives + multi-tenant isolation + the reference deployment; explicit exclusions (business-defined plugins, downstream application logic).
2. **Deliverables**: an audit report (graded findings + reproduction steps + fix recommendations), retest conclusions, a management summary.
3. **Access**: read-only source-repository access, build/test commands, the `docker-compose.e2e.yml` environment, fuzzing corpora, the ASVS self-assessment and ADRs.
4. **Timing**: recommended after the 1.0 API freeze and before release; reserve windows for remediation and retesting.
5. **Qualifications**: experience auditing Rust-ecosystem and authentication-protocol code; willingness to sign NDAs and follow the vulnerability disclosure policy.
6. **Budget and schedule**: 📋 pending a product decision (not promised unilaterally in this repository).

---

## 📌 Status Table

| Item                         | Status            | Notes                                                 |
| -------------------------- | --------------- | ---------------------------------------------------- |
| Internal security review               | ✅ Established, rolling | R01–R18 remediation landed with rc.3; rc.4 continues fixing the DAO/session surfaces |
| SAST / dependency / fuzzing wiring | ✅ Wired       | CodeQL / cargo audit / deny / vet / fuzz 4 targets   |
| ASVS self-assessment                  | 🔶 Rolling     | See [SECURITY_ASVS.md](./SECURITY_ASVS.md)            |
| Third-party audit                 | 📋 Not started       | Needs a product decision on budget and schedule; this document provides the RFP checklist              |
| Certification / compliance statements            | ⚪ Not applicable       | This repository makes no certification conclusions; deployers assess under their own compliance regimes         |

---

## 📚 Related Documents

| Document                               | Description                                            |
| ---------------------------------- | ----------------------------------------------- |
| [🔒 Security policy](SECURITY.md)      | Vulnerability reporting channels and supported versions                          |
| [🛡️ ASVS self-assessment](./SECURITY_ASVS.md) | V2/V3 control mapping                                |
| [🎯 Threat model](./THREAT.md)         | STRIDE and trust boundaries                               |
| [🧭 ADR-0001](adr-0001-argon2id-password-hashing.md) / [0002](adr-0002-csprng-policy.md) / [0003](adr-0003-constant-time-comparison.md) / [0004](adr-0004-unified-error-model-request-id-retry-after.md) | Password hashing / CSPRNG / constant-time comparison / unified error model |
| [🗺️ Roadmap](./ROADMAP.md)          | v1.0 security-audit gate status                           |
