//! 综合演示示例模块。

#[cfg(all(
    feature = "tenant-isolation",
    feature = "audit-log",
    feature = "decision-trace",
    feature = "keycloak-oidc",
    feature = "social-wechat",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
pub mod v0_5_0_demo;
