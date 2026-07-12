//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! axum 框架适配子模块（firewall-waf middleware）。

/// WAF middleware 适配器（T010 实现）。
#[cfg(feature = "firewall-waf")]
pub mod waf;
