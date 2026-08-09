//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 安全模块示例。

#[cfg(feature = "secure-ct-eq")]
pub mod constant_time_eq;
#[cfg(any(
    feature = "secure-masking",
    feature = "secure-xss",
    feature = "secure-sanitize",
    feature = "secure-confusable"
))]
pub mod secure_module;
