//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! FirewallContext 实现块（从 mod.rs 迁移）。

use super::FirewallContext;

impl FirewallContext {
    /// 创建防火墙上下文，仅指定 IP。
    pub fn new(ip: impl Into<String>) -> Self {
        Self {
            ip: ip.into(),
            login_id: None,
            tenant_id: None,
        }
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
