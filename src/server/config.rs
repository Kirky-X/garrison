//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use super::AuthServerConfig;

impl AuthServerConfig {
    /// 校验配置合法性。
    ///
    /// 在 server 启动时调用，确保关键配置项已正确设置。
    ///
    /// # 错误
    /// - `internal_api_key` 为空时返回错误，防止 fail-open 风险。
    pub fn validate(&self) -> Result<(), String> {
        if self.internal_api_key.is_empty() {
            return Err("internal_api_key 未配置，内网 API 将拒绝所有请求。\
                 请通过 with_internal_api_key() 设置非空值"
                .to_string());
        }
        Ok(())
    }
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            external_port: 8080,
            internal_port: 8081,
            external_rate_limit_per_ip: 100,
            rate_limit_max_entries: 100_000,
            rate_limit_trusted_proxies: Vec::new(),
            internal_api_key: String::new(),
            external_body_limit: 256 * 1024,  // 256 KB
            internal_body_limit: 1024 * 1024, // 1 MB
        }
    }
}
