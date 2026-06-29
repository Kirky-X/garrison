//! DAO 模块，定义持久化数据访问抽象层。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaTokenDao`，
//! 通过 dbnexus 提供多后端（SQLite / PostgreSQL / MySQL）支持。

use crate::error::BulwarkResult;
use async_trait::async_trait;

/// DAO 抽象层 trait，定义 Token 与会话的持久化操作。
///
/// [借鉴 Sa-Token] 对应 `SaTokenDao`，提供 get / set / expire / delete 四元操作。
/// 实现方通过 dbnexus 适配具体数据库后端。
#[async_trait]
pub trait BulwarkDao: Send + Sync {
    /// 获取指定键的值。
    ///
    /// # 参数
    /// - `key`: 存储键。
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        todo!()
    }

    /// 设置键值对。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    async fn set(&self, key: &str, value: &str) -> BulwarkResult<()> {
        todo!()
    }

    /// 设置键的过期时间。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `seconds`: 过期秒数。
    async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
        todo!()
    }

    /// 删除指定键。
    ///
    /// # 参数
    /// - `key`: 存储键。
    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        todo!()
    }
}
