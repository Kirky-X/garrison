//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 扩展能力示例模块（plugin / listener / macro / manager / session）。

pub mod auth_logic_impl;
pub mod custom_plugin;
#[cfg(feature = "listener")]
pub mod event_listener;
#[cfg(all(
    feature = "annotation-macros",
    feature = "cache-memory",
    feature = "web-axum"
))]
pub mod macro_annotations;
#[cfg(all(feature = "cache-memory", feature = "web-axum"))]
pub mod manager_lifecycle;
#[cfg(feature = "cache-memory")]
pub mod session_management;
