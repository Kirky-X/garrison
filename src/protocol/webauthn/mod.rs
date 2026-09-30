// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! WebAuthn/Passkey 凭据 SPI 与注册/认证仪式（feature = "protocol-webauthn"）。
//!
//! 基于 `webauthn-rs` 0.5 提供 Passkey 凭据的注册与认证两大仪式，职责边界：
//!
//! - [`challenge`]：仪式态（`PasskeyRegistration` / `PasskeyAuthentication`）
//!   经 [`crate::dao::GarrisonDao`] `set_if_absent`+TTL 暂存，消费用原子读删
//!   （`get_and_delete`），键不存在即判重放——challenge 一次性是整个协议的
//!   反重放根基（assertion 重放 = challenge 已消费）。
//! - [`credential`]：凭据领域模型（公钥/sign_count/backup flags/attestation）
//!   与 SQL 行的双向映射。
//! - [`service`]：仪式编排。注册侧 `ExcludeCredentials` 防同 authenticator
//!   重复绑定（叠加 `credential_id` 唯一约束兜底）；认证侧 sign_count 单调性
//!  （count ≤ 上次 → 克隆嫌疑拒绝）与 backup flags 更新落库。
//!
//! ## RP 配置派生
//!
//! Relying Party 配置从 issuer URL 派生：`rp_id` = URL host，`origins` =
//! [issuer]。issuer 变更后 rp_id 自动跟随，无需独立 RP 配置项。
//!
//! ## key 命名空间
//!
//! - `garrison:webauthn:challenge:<challenge_b64>`：仪式态 JSON，
//!   TTL = `WebauthnConfig::challenge_ttl_secs`。
//!
//! 与 session/qrlogin/sign 等命名空间隔离。
//!
//! ## 安全语义
//!
//! - 仪式态只落服务端存储（`danger-allow-state-serialisation` 的上游文档
//!   认可场景）；绝不可下发到客户端可读位置，否则重放防御失效。
//! - 认证成功后 sign_count 单调推进；回退触发克隆嫌疑拒绝（显性错误，
//!   不静默放行）。
//! - backup_eligible 只升不降（BE 升级单向），backup_state 跟随最新断言。

pub mod challenge;
pub mod credential;
pub mod service;

// 仪式测试经 sqlite 真实库承载凭据/challenge 持久化，production 组合
// （无 db-sqlite）下不编译
#[cfg(all(test, feature = "db-sqlite"))]
mod tests;

use serde::{Deserialize, Serialize};

// ============================================================================
// FactorPurpose / FactorPolicy：passwordless 与 2FA 双 policy
// ============================================================================

/// 凭据准入用途：passwordless（凭据即身份）或 second factor（叠加因子）。
///
/// 双 policy 分立配置（[`WebauthnConfig::passwordless`] /
/// [`WebauthnConfig::second_factor`]）：注册期按用途门控准入，
/// 关闭的用途显性拒绝（不做静默降级）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactorPurpose {
    /// Passwordless：凭据本身完成身份认证（第一因子）。
    Passwordless,
    /// 二次认证因子（MFA 第二因子；完整编排归 stp/mfa 的 MFA 编排基座）。
    SecondFactor,
}

/// 单一用途的准入 policy（构造后不可变）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactorPolicy {
    /// 该用途是否准入。false 时对应用途的注册请求显性拒绝。
    pub enabled: bool,
}

// ============================================================================
// WebauthnConfig：配置（构造后不可变）
// ============================================================================

/// WebAuthn/Passkey 配置。
///
/// 经 [`service::WebauthnService`] 注入，构造后不可变。
/// RP 配置（rp_id/origins）不自立配置项，从 [`WebauthnConfig::issuer`] 派生。
#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    /// RP 派生源：issuer URL（如 `https://sso.example.com`）。
    ///
    /// `rp_id` = URL host，`origins` = [issuer]。issuer 变更后 rp_id 跟随。
    pub issuer: String,

    /// 仪式态 challenge 暂存 TTL（秒），默认 120。
    ///
    /// TTL 过期后 challenge 不可再消费（与重放同样显性拒绝）。
    pub challenge_ttl_secs: u64,

    /// Passwordless 准入 policy。
    pub passwordless: FactorPolicy,

    /// 二次认证因子准入 policy。
    pub second_factor: FactorPolicy,
}

// ============================================================================
// WebauthnCeremonyError：仪式错误词汇表（显性化，不静默）
// ============================================================================

/// WebAuthn 仪式错误：模块自有的错误词汇表，边界处映射为
/// [`crate::error::GarrisonError`]（`InvalidParam` 携带显性 detail）。
///
/// 每个变体对应一个可测试的安全属性（重放/克隆/重复绑定/attestation 非法），
/// 不与 DAO/配置错误混淆。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebauthnCeremonyError {
    /// challenge 不存在或已过期：已消费（重放）、TTL 过期或伪造 challenge。
    ChallengeReplayed,
    /// challenge 存在但类型不符（注册态遇认证响应等）。
    ChallengeKindMismatch,
    /// attestation/签名校验被拒（非法凭据响应、签名不符、origin/RP hash 不符）。
    CeremonyRejected(String),
    /// 同 authenticator（credential_id）重复绑定。
    CredentialAlreadyBound,
    /// sign_count 回退：克隆嫌疑（count ≤ 上次记录值）。
    CloneSuspected {
        /// 上次记录的 sign_count。
        stored: u32,
        /// 本次断言的 sign_count。
        asserted: u32,
    },
    /// 认证目标用户没有任何已绑定凭据。
    NoCredentialBound,
    /// policy 关闭导致准入被拒。
    PolicyDisabled(FactorPurpose),
}
