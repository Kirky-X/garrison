//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! ABAC（Attribute-Based Access Control）策略引擎模块。
//!
//! 基于 `cedar-policy` crate，提供 principal-action-resource 三元组策略求值。
//! ABAC 作为 RBAC 的增量校验层，不替换 RBAC。RBAC 通过后再检查 ABAC。
//!
//! # 核心类型
//!
//! - [`AbacEngine`]：Cedar 策略求值器
//!
//! # Feature 依赖
//!
//! 启用 `abac` feature 时编译，依赖 `cedar-policy` crate。

mod engine;

pub use engine::AbacEngine;
