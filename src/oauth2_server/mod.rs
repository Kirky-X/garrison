//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 Server 模块，提供完整 OAuth2 授权服务器实现。
//!
//! 作为授权服务器（AS）角色，处理客户端的 authorize / token / revoke / introspect 请求。
//! 与 `protocol::oauth2`（OAuth2 客户端 / RP 角色）互补。
//!
//! ## 子模块
//!
//! - `client`：OAuth2Client struct + OAuth2ClientStore trait + DaoOAuth2ClientStore 实现
//! - `authorize`：/oauth2/authorize 端点（授权码流程 + PKCE）
//! - `token`：/oauth2/token 端点（4 种 grant type）
//! - `revoke`：/oauth2/revoke 端点（RFC 7009）
//! - `introspect`：/oauth2/introspect 端点（RFC 7662）

/// OAuth2 客户端管理模块。
pub mod client;
