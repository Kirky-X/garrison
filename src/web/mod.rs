//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Web 安全中间件模块，提供 WAF / CORS / CSRF 等请求内容校验能力。
//!
//! 各子模块独立 feature-gated：
//! - `web-waf`：WAF 请求内容校验（路径/方法/危险字符检测）
//! - `web-cors`：CORS 跨域资源共享中间件
//! - `web-csrf`：CSRF 跨站请求伪造防护（Double-Submit Cookie 模式）

/// WAF 请求内容校验模块。
#[cfg(feature = "web-waf")]
pub mod waf;
