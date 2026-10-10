// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

use super::{AuthServerConfig, EXTERNAL_LOGIN_ACK, MIN_INTERNAL_API_KEY_LEN};

/// 判断 IP 是否为内网/环回候选（回环 / RFC1918 / link-local / IPv6 ULA）。
///
/// 从 `AuthServerConfig::validate` 内联的 V4/V6 判断提取，行为不变；
/// 参考部署 bin 的可信代理校验改调本函数（单一实现）。
pub fn is_private_proxy_addr(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
        },
    }
}

/// 读取布尔环境变量开关（接受 "1"/"true"/"yes"/"on"，大小写不敏感）。
///
/// 变量存在但无法识别取值时告警并按 `None` 处理（调用方回退默认值）——
/// 不静默吞掉：配置错误必须显性化。
fn env_flag(key: &str) -> Option<bool> {
    std::env::var(key)
        .ok()
        .and_then(|raw| match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => {
                tracing::warn!(
                    env = key,
                    value = %raw,
                    "unrecognized boolean, falling back to default"
                );
                None
            },
        })
}

/// 读取整数环境变量（非法取值告警并回退默认值，不静默）。
fn env_num<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok().and_then(|raw| match raw.trim().parse::<T>() {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!(env = key, value = %raw, "unrecognized number, falling back to default");
            None
        },
    })
}

impl AuthServerConfig {
    /// 校验配置合法性。
    ///
    /// 在 server 启动时调用，确保关键配置项已正确设置。
    ///
    /// # 错误
    /// - `internal_api_key` 为空时返回错误，防止 fail-open 风险。
    /// - `rate_limit_trusted_proxies` 含非内网/环回地址时返回错误：
    ///   可信代理仅应部署在内网（loopback / RFC 1918 / link-local / IPv6 ULA），
    ///   公网 IP 会被互联网路径上的中间设备伪造，扩大 X-Forwarded-For 信任边界。
    ///
    /// # 严格档专属拒绝（仅 `strict_security = true`）
    /// - `server-internal-api-key-too-short::{len}`：密钥非空但短于
    ///   [`MIN_INTERNAL_API_KEY_LEN`]。
    /// - `server-external-login-unacknowledged::{bind}`：外网登录开启、`external_bind`
    ///   为非回环地址且 `external_login_ack` 未精确匹配
    ///   [`EXTERNAL_LOGIN_ACK`]。
    ///
    /// 非严格档（库层缺省）上述两个条件**不改变返回值**，只输出含迁移动作的
    /// `tracing::warn!`（棘轮：默认路径零行为变化，1.0 起转为拒绝）；通配绑定在
    /// 两档下均不拒绝——容器部署必须绑定 `0.0.0.0` 才能被端口映射，收口绑定面须由
    /// 调用方经 `with_external_bind` / `with_internal_bind` 显式决定。
    pub fn validate(&self) -> Result<(), String> {
        if self.internal_api_key.is_empty() {
            return Err("server-internal-api-key-missing::".to_string());
        }
        // 严格档两条拒绝；非严格档同样条件只告警（棘轮非破坏语义）。
        let key_too_short = self.internal_api_key.len() < MIN_INTERNAL_API_KEY_LEN;
        let login_unacked = self.external_login_enabled
            && !self.external_bind.is_loopback()
            && self.external_login_ack.as_deref() != Some(EXTERNAL_LOGIN_ACK);
        if self.strict_security {
            if key_too_short {
                return Err(format!(
                    "server-internal-api-key-too-short::{}",
                    self.internal_api_key.len()
                ));
            }
            if login_unacked {
                return Err(format!(
                    "server-external-login-unacknowledged::{}",
                    self.external_bind
                ));
            }
        } else {
            if key_too_short {
                tracing::warn!(
                    len = self.internal_api_key.len(),
                    min = MIN_INTERNAL_API_KEY_LEN,
                    "server-internal-api-key-too-short: 内网 API Key 短于下限，1.0 将转为拒绝；请轮换为 ≥32 字节密钥"
                );
            }
            if login_unacked {
                tracing::warn!(
                    bind = %self.external_bind,
                    "server-external-login-unacknowledged: 外网登录端点已暴露且未确认，1.0 将转为拒绝；请传入确认串 external_login_ack"
                );
            }
            if self.external_bind.is_unspecified() || self.internal_bind.is_unspecified() {
                tracing::warn!(
                    external_bind = %self.external_bind,
                    internal_bind = %self.internal_bind,
                    "server-wildcard-bind-default: 未显式配置的通配绑定将在 1.0 变为回环，\
                     容器部署请显式 with_external_bind(0.0.0.0) / with_internal_bind(0.0.0.0)"
                );
            }
        }
        for ip in &self.rate_limit_trusted_proxies {
            if !is_private_proxy_addr(ip) {
                return Err(format!("server-trusted-proxy-not-private::{}", ip));
            }
        }
        Ok(())
    }
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            external_port: 8080,
            // 绑定地址默认 0.0.0.0（框架层向后兼容）；安全收口由调用方
            // 经 with_external_bind/with_internal_bind 显式注入。
            external_bind: std::net::IpAddr::from([0, 0, 0, 0]),
            internal_port: 8081,
            internal_bind: std::net::IpAddr::from([0, 0, 0, 0]),
            external_rate_limit_per_ip: 100,
            rate_limit_max_entries: 100_000,
            rate_limit_trusted_proxies: Vec::new(),
            internal_api_key: String::new(),
            external_body_limit: 256 * 1024,  // 256 KB
            internal_body_limit: 1024 * 1024, // 1 MB
            // C-1: 外网登录端点默认关闭（框架不校验凭证，secure-by-default）
            external_login_enabled: false,
            // GAR-25: API Key 失败锁定默认开启（阈值 10 / 窗口 300s；0 = 禁用）。
            // 环境变量在 Default 读取（而非 bin 接线）：保证 bin 零改动即可
            // 经 GARRISON_* 覆盖默认装配。
            api_key_lockout_threshold: env_num("GARRISON_API_KEY_LOCKOUT_THRESHOLD").unwrap_or(10),
            api_key_lockout_window_secs: env_num("GARRISON_API_KEY_LOCKOUT_WINDOW_SECS")
                .unwrap_or(300),
            // GAR-14: readyz details 默认剥离（可能含内部依赖拓扑），显式 opt-in
            health_details_enabled: env_flag("GARRISON_HEALTH_DETAILS").unwrap_or(false),
            // 棘轮：缺省 false，默认路径只告警不拒绝，1.0 翻转。
            strict_security: env_flag("GARRISON_STRICT_SECURITY").unwrap_or(false),
            external_login_ack: std::env::var("GARRISON_EXTERNAL_LOGIN_ACK")
                .ok()
                .filter(|s| !s.is_empty()),
        }
    }
}
