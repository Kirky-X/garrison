// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `config-security-rules` 配置安全规则集（feature 门控）：在 `validate()` 末尾调用（load 与热更新共用入口）。
//!
//! 不接线 confers `SecurityValidatorRegistry`：其校验器按点分嵌套键读取配置，与本 crate 扁平键模型不匹配，且无 TLS/SSRF 配置对象（TLS 由反向代理终止，见 THREAT.md 信任边界）。规则仅含 JWT（密钥强度 + 弱密钥黑名单，复用 `validate_jwt_secret` 的 fail-closed）与 CORS（credentials+wildcard 硬拒绝；通配 origin 未开 credentials 落 warn——公开只读 API 是合法场景）。
//!
//! feature 关闭时本模块不编译，`validate()` 零行为变化。

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

    /// 通配 origin 未开 credentials 的风险警示（warn 不拒绝）：任意源可读取响应，公开只读 API 合法故不强制失败，暴露敏感数据的部署应收敛为 origin 白名单。
    #[cfg(feature = "web-cors")]
    fn warn_cors_wildcard_without_credentials(&self) {
        if self.cors_config.allow_credentials {
            return;
        }
        if !self.cors_config.allowed_origins.iter().any(|o| o == "*") {
            return;
        }
        tracing::warn!(
            "{}",
            crate::i18n::translate_detail("logs-config-cors-wildcard-without-credentials", &[])
        );
    }
}
