// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! FirewallContext 实现块（从 mod.rs 迁移）。

use super::FirewallContext;
use crate::error::{GarrisonError, GarrisonResult};

impl FirewallContext {
    /// 创建防火墙上下文，仅指定 IP。
    ///
    /// # IP 校验
    ///
    /// 本构造器**不校验** IP 格式（保持既有签名 `Self`，不破坏调用方），
    /// 仅在 debug 构建下 `debug_assert` IP 可解析。生产代码建议改用
    /// [`try_new`](Self::try_new) 在构造期拒绝畸形 IP（空串、URL 编码、
    /// 带括号 IPv6、任意垃圾字符串等会被下游拼进缓存 key / 封禁目标，
    /// 产生不可预期的限流与封禁行为）。
    pub fn new(ip: impl Into<String>) -> Self {
        let ip = ip.into();
        debug_assert!(
            ip.parse::<std::net::IpAddr>().is_ok(),
            "FirewallContext::new received malformed IP: {:?} (use try_new to validate)",
            ip
        );
        Self {
            ip,
            login_id: None,
            tenant_id: None,
        }
    }

    /// 创建防火墙上下文并校验 IP 格式（IPv4 / IPv6）。
    ///
    /// 与 [`new`](Self::new) 的区别：解析失败返回 `InvalidParam` 而非静默存入，
    /// 防止畸形值流入下游策略（BruteForce count key、封禁目标、限流 key 等）。
    ///
    /// # 错误
    /// - `ip` 不是合法 IPv4/IPv6 地址 → `InvalidParam`
    pub fn try_new(ip: impl Into<String>) -> GarrisonResult<Self> {
        let ip = ip.into();
        if let Err(e) = ip.parse::<std::net::IpAddr>() {
            return Err(GarrisonError::InvalidParam(format!(
                "firewall-context-invalid-ip::{}::{}",
                ip, e
            )));
        }
        Ok(Self {
            ip,
            login_id: None,
            tenant_id: None,
        })
    }

    /// 链式设置 login_id。
    pub fn with_login_id(mut self, login_id: impl Into<String>) -> Self {
        self.login_id = Some(login_id.into());
        self
    }

    /// 链式设置 tenant_id。
    pub fn with_tenant_id(mut self, tenant_id: i64) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// try_new 接受合法 IPv4 / IPv6。
    #[test]
    fn try_new_accepts_valid_ips() {
        assert!(FirewallContext::try_new("192.168.1.1").is_ok());
        assert!(FirewallContext::try_new("::1").is_ok());
        assert!(FirewallContext::try_new("2001:db8::1").is_ok());
    }

    /// try_new 拒绝畸形 IP（空串 / 任意文本 / 带括号 IPv6 / CIDR）。
    #[test]
    fn try_new_rejects_malformed_ips() {
        assert!(FirewallContext::try_new("").is_err());
        assert!(FirewallContext::try_new("not-an-ip").is_err());
        assert!(FirewallContext::try_new("[::1]").is_err());
        assert!(FirewallContext::try_new("0.0.0.0/0").is_err());
        let err = FirewallContext::try_new("%31%2e%31").unwrap_err();
        assert!(
            matches!(&err, GarrisonError::InvalidParam(msg) if msg.contains("invalid-ip")),
            "畸形 IP 应返回 InvalidParam，实际: {:?}",
            err
        );
    }

    /// try_new 与 new 行为一致（合法 IP 时字段相同，builder 链可用）。
    #[test]
    fn try_new_matches_new_for_valid_ip() {
        let a = FirewallContext::try_new("10.0.0.1").unwrap();
        let b = FirewallContext::new("10.0.0.1");
        assert_eq!(a.ip, b.ip);
        assert_eq!(a.login_id, b.login_id);
        assert_eq!(a.tenant_id, b.tenant_id);

        let c = FirewallContext::try_new("10.0.0.2")
            .unwrap()
            .with_login_id("1001")
            .with_tenant_id(7);
        assert_eq!(c.ip, "10.0.0.2");
        assert_eq!(c.login_id.as_deref(), Some("1001"));
        assert_eq!(c.tenant_id, Some(7));
    }
}
