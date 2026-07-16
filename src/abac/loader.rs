//! Copyright (c)  2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! EntityLoader 实现：为 AbacEngine 提供 Cedar Entities 数据源。
//!
//! 引入 `EntityLoader` 抽象，让调用方注入实体数据源，
//! 支持基于实体属性的策略（如 `resource.owner == principal.id`）。
//!
//! - `EmptyEntityLoader`：返回空 Entities（默认实现，保持向后兼容）
//! - `StaticEntityLoader`：持有预构造 Entities，每次 clone 返回（测试用）
//!
//! # 缓存语义
//!
//! `EntityLoader::load_entities` 在每次 `evaluate` 时调用。缓存不主动失效，
//! 由调用方保证 `EntityLoader` 返回稳定实体集合（如 `StaticEntityLoader`）。

use crate::error::BulwarkResult;
use async_trait::async_trait;
use cedar_policy::Entities;

use super::EntityLoader;

/// 空实体加载器（默认实现）。
///
/// 始终返回 `Entities::empty()`。用于不依赖实体属性的策略场景，
/// 或作为 `AbacEngine::new` 的占位符。
///
/// # 行为
///
/// - `load_entities` 返回 `Ok(Entities::empty())`
pub struct EmptyEntityLoader;

#[async_trait]
impl EntityLoader for EmptyEntityLoader {
    async fn load_entities(&self) -> BulwarkResult<Entities> {
        Ok(Entities::empty())
    }
}

/// 静态实体加载器（测试与固定实体集合场景用）。
///
/// 持有预构造的 `Entities`，每次 `load_entities` 返回其 clone。
/// 适用于需要基于实体属性求值的策略测试（如 `resource.owner == principal.id`）。
///
/// # 行为
///
/// - `load_entities` 返回 `Ok(self.entities.clone())`
///
/// # 用途
///
/// - 回归测试：验证带属性实体的策略能正确求值
/// - 集成测试场景：构造固定实体集合，避免依赖外部数据源
pub struct StaticEntityLoader {
    entities: Entities,
}

impl StaticEntityLoader {
    /// 创建 `StaticEntityLoader`。
    ///
    /// # 参数
    ///
    /// - `entities`：预构造的 Cedar Entities 集合（调用 `load_entities` 时 clone 返回）
    pub fn new(entities: Entities) -> Self {
        Self { entities }
    }
}

#[async_trait]
impl EntityLoader for StaticEntityLoader {
    async fn load_entities(&self) -> BulwarkResult<Entities> {
        Ok(self.entities.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `EmptyEntityLoader::load_entities` 返回空 Entities。
    ///
    /// `EmptyEntityLoader::load_entities` 返回空实体集合，语义与 `Entities::empty()` 一致。
    #[tokio::test]
    async fn test_empty_entity_loader_returns_empty_entities() {
        let loader = EmptyEntityLoader;
        let entities = loader
            .load_entities()
            .await
            .expect("EmptyEntityLoader 不应返回错误");
        assert_eq!(
            entities.iter().count(),
            0,
            "EmptyEntityLoader 应返回空实体集合"
        );
    }

    /// `StaticEntityLoader::load_entities` 返回构造时持有的 Entities（clone）。
    ///
    /// 验证带属性的实体集合能被正确加载，且多次调用返回一致结果。
    #[tokio::test]
    async fn test_static_entity_loader_loads_entities() {
        // 构造带属性的实体：User "alice" 带 id 属性，Resource "doc1" 带 owner 属性。
        // Cedar 4.x Entities JSON 格式要求 uid 为对象形式 `{"__entity": {"type", "id"}}`。
        let entities_json = r#"[
            {"uid": {"__entity": {"type": "User", "id": "alice"}}, "attrs": {"id": "alice"}, "parents": []},
            {"uid": {"__entity": {"type": "Resource", "id": "doc1"}}, "attrs": {"owner": "alice"}, "parents": []}
        ]"#;
        let entities = Entities::from_json_str(entities_json, None).expect("解析实体 JSON 应成功");
        let loader = StaticEntityLoader::new(entities);

        let loaded_first = loader
            .load_entities()
            .await
            .expect("首次 load_entities 不应返回错误");
        assert_eq!(
            loaded_first.iter().count(),
            2,
            "StaticEntityLoader 应返回 2 个实体（User + Resource）"
        );

        // 多次调用应返回一致结果（clone 语义）
        let loaded_second = loader
            .load_entities()
            .await
            .expect("第二次 load_entities 不应返回错误");
        assert_eq!(
            loaded_second.iter().count(),
            2,
            "第二次调用应返回相同数量的实体"
        );
    }
}
