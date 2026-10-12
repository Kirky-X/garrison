// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! EntityLoader 实现：为 AbacEngine 提供 Cedar Entities 数据源，支持基于实体属性的策略（如 `resource.owner == principal.id`）。
//!
//! `EmptyEntityLoader` 返回空 Entities（默认实现）；`StaticEntityLoader` 持有预构造 Entities、每次 clone 返回（测试用）。缓存不主动失效，由调用方保证返回稳定实体集合。

use crate::error::GarrisonResult;
use async_trait::async_trait;
use cedar_policy::Entities;

use super::EntityLoader;

/// 空实体加载器（默认实现）：始终返回 `Entities::empty()`，用于不依赖实体属性的策略或作 `AbacEngine::new` 占位符。
pub struct EmptyEntityLoader;

#[async_trait]
impl EntityLoader for EmptyEntityLoader {
    async fn load_entities(&self) -> GarrisonResult<Entities> {
        Ok(Entities::empty())
    }
}

/// 静态实体加载器（测试与固定实体集合场景）：持有预构造 `Entities`，每次 `load_entities` 返回其 clone；用于验证带属性实体的策略求值与避免依赖外部数据源的测试。
pub struct StaticEntityLoader {
    entities: Entities,
}

impl StaticEntityLoader {
    /// 创建 `StaticEntityLoader`（`entities` 在 `load_entities` 时 clone 返回）。
    pub fn new(entities: Entities) -> Self {
        Self { entities }
    }
}

#[async_trait]
impl EntityLoader for StaticEntityLoader {
    async fn load_entities(&self) -> GarrisonResult<Entities> {
        Ok(self.entities.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn test_static_entity_loader_loads_entities() {
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
