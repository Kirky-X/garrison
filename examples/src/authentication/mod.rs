//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 登录认证示例模块。

#[cfg(all(feature = "cache-memory", feature = "web-axum"))]
pub mod basic_login;
#[cfg(feature = "secure-httpbasic")]
pub mod httpbasic_login;
#[cfg(feature = "secure-httpdigest")]
pub mod httpdigest_login;
#[cfg(feature = "protocol-jwt")]
pub mod jwt_login;
#[cfg(all(feature = "protocol-jwt", feature = "cache-memory"))]
pub mod jwt_modes;
#[cfg(all(
    feature = "account-credential",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
pub mod password_login;
#[cfg(feature = "secure-totp")]
pub mod totp_login;
