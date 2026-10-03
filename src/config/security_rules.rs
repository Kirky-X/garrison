// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `config-security-rules` 配置安全规则集（feature 门控）。
//!
//! 吸收 confers `security-rules` 的校验意图，落地为 GarrisonConfig 扁平键
//! 可直接校验的自有规则。不接线 confers `SecurityValidatorRegistry`：其内置
//! 校验器按点分嵌套键（`jwt.secret`/`cors.allowed_origins`/`tls.min_version`/
//! `ssrf.allowed_urls`）读取配置，与本 crate 的扁平键模型不匹配；且
//! GarrisonConfig 无 TLS/SSRF 对应配置对象（TLS 由反向代理终止，见
//! THREAT.md 信任边界）——不虚报能力，文档仅声明 JWT 与 CORS 两类实际校验。
//!
//! 规则汇总（`validate()` 末尾调用，load 与热更新共用同一入口）：
//! - JWT：密钥强度 + 弱密钥黑名单（复用 `validate_jwt_secret` 的 fail-closed 语义）
//! - CORS：credentials+wildcard 硬拒绝（复用 `CorsConfig::validate`，与
//!   `validate_feature_gated` 的常规校验形成双保险）；通配 origin 未开
//!   credentials 落 warn（公开只读 API 是合法场景，不强制拒绝）
//!
//! feature 关闭时本模块整体不编译，`validate()` 零行为变化。

use super::*;
use crate::error::GarrisonResult;

impl GarrisonConfig {
    /// 配置安全规则集校验入口。
    pub(super) fn validate_security_rules(&self) -> GarrisonResult<()> {
        self.validate_jwt_secret()?;
        #[cfg(feature = "web-cors")]
        {
            crate::web::cors::CorsConfig::validate(&self.cors_config)?;
            self.warn_cors_wildcard_without_credentials();
        }
        Ok(())
    }

    /// 通配 origin 未开 credentials 的风险警示（warn 不拒绝）。
    ///
    /// `allowed_origins=["*"]` 且 `allow_credentials=false` 时任意源可读取
    /// 响应；公开只读 API 是合法场景故不强制失败，但暴露敏感数据的部署
    /// 需要显性信号收敛为 origin 白名单。
    #[cfg(feature = "web-cors")]
    fn warn_cors_wildcard_without_credentials(&self) {
        if self.cors_config.allow_credentials {
            return;
        }
        if !self.cors_config.allowed_origins.iter().any(|o| o == "*") {
            return;
        }
        tracing::warn!(
            "config security rules: cors allowed_origins=[\"*\"] without allow_credentials — 任意源可读取响应，暴露敏感数据的部署应改为显式 origin 白名单"
        );
    }
}
