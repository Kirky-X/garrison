//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! ABAC（Attribute-Based Access Control）策略引擎模块。
//!
//! 基于 `cedar-policy` crate，提供 principal-action-resource 三元组策略求值。
//! ABAC 作为 RBAC 的增量校验层，不替换 RBAC。RBAC 通过后再检查 ABAC。
//!
//! # 核心类型
//!
//! - `AbacEngine`：Cedar 策略求值器（`abac` feature 开启时可用）
//! - `EntityLoader`：Cedar Entities 数据源 trait
//! - `EmptyEntityLoader` / `StaticEntityLoader`：内置实现
//!
//! # 全局引擎管理
//!
//! - `init_abac_engine`：初始化全局 AbacEngine（`abac` feature 开启时可用）
//! - `check_abac_with_policy`：宏入口，RBAC 通过后调用 ABAC 求值
//!
//! # Feature 依赖
//!
//! 启用 `abac` feature 时编译核心引擎，依赖 `cedar-policy` crate。
//! `check_abac_with_policy` 在 `abac` feature 关闭时提供 no-op stub，
//! 确保宏生成的代码在任意 feature 组合下均可编译。

#[cfg(feature = "abac")]
mod engine;

#[cfg(feature = "abac")]
mod loader;

#[cfg(feature = "abac")]
use crate::error::BulwarkResult;

#[cfg(feature = "abac")]
pub use engine::AbacEngine;

#[cfg(feature = "abac")]
pub use loader::{EmptyEntityLoader, StaticEntityLoader};

// ============================================================================
// EntityLoader trait
// ============================================================================

/// Cedar Entities 数据源 trait。
///
/// 抽象实体加载逻辑，让调用方注入实体数据源，支持基于属性的 ABAC 策略
/// （如 `resource.owner == principal.id`）。
///
/// # 内置实现
///
/// - [`EmptyEntityLoader`]：返回空 Entities（向后兼容默认行为）
/// - [`StaticEntityLoader`]：持有预构造 Entities，clone 返回（测试与固定实体场景）
///
/// # 自定义实现
///
/// 生产代码可实现本 trait 从数据库 / 远程服务加载实体，例如：
///
/// ```ignore
/// #[async_trait::async_trait]
/// impl EntityLoader for MyDbEntityLoader {
///     async fn load_entities(&self) -> BulwarkResult<cedar_policy::Entities> {
///         // 从数据库查询实体并构造 Entities
///         todo!()
///     }
/// }
/// ```
///
/// # 缓存语义
///
/// `load_entities` 在每次 `AbacEngine::evaluate` 时调用。决策缓存不主动失效，
/// 调用方需保证 `EntityLoader` 返回稳定实体集合（同一实体集合的多次加载应返回一致结果）。
/// 若 `load_entities` 返回错误，错误通过 `?` 传播，缓存不受污染。
#[cfg(feature = "abac")]
#[async_trait::async_trait]
pub trait EntityLoader: Send + Sync {
    /// 加载 Cedar Entities 集合。
    ///
    /// # 错误
    ///
    /// - 实体加载失败（数据源不可达、解析错误等）：返回 `BulwarkError`
    async fn load_entities(&self) -> BulwarkResult<cedar_policy::Entities>;
}

mod init;
pub use init::*;

#[cfg(all(test, feature = "abac"))]
mod tests;
