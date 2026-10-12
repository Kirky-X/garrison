// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! OAuth2 Server 模块，作为授权服务器（AS）角色处理客户端的 authorize / token /
//! revoke / introspect 请求，与 `protocol::oauth2`（客户端 / RP 角色）互补。

/// OAuth2 客户端管理模块。
pub mod client;

/// /oauth2/authorize 端点模块。
pub mod authorize;

/// /oauth2/token 端点模块。
pub mod token;

/// /oauth2/revoke 端点模块（RFC 7009）。
pub mod revoke;

/// /oauth2/introspect 端点模块（RFC 7662）。
pub mod introspect;

/// /oauth2/jwks.json 端点模块（RFC 7517 JWK Set 导出）。
pub mod jwks;

/// OIDC Back-Channel Logout 持久化投递模块（logout token 签发 / 队列 / 禁重定向投递器）；
/// 仅 `backchannel-logout` feature 下编译，队列与投递另需 db 后端 feature。
#[cfg(feature = "backchannel-logout")]
pub mod backchannel;
