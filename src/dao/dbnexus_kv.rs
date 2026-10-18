// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `DbnexusKvDao` — SQL 持久化 KV（`garrison_kv` 表）：garrison-cli `change-key` / `check-key`
//! 的数据寻址层。`GarrisonDaoDbnexus` 的 KV 委托给进程内实例（如 `InMemoryDao`），跨进程不可
//! 持久化——离线运维命令需要一个把 KV 落在部署库里的委托实现，本模块补齐该空档。
//!
//! `#[cfg(any(db-sqlite, db-postgres, db-mysql))]` 门控（与 [`GarrisonDaoDbnexus`](super::dbnexus_dao) 一致）。
//!
//! # 语义
//!
//! 行为镜像 [`InMemoryDao`](crate::dao::InMemoryDao)：glob `keys`（`*`/`?`）、TTL 过期行在读路径
//! 视为不存在（`update`/`expire` 对其显性 `dao-key-missing`，不复活）、`incr`/`decr` 计数器
//! （`incr` 保留原 TTL、`decr` 到 0 删键）、`compare_and_swap` 的 `expected=None` 语义为键不存在。
//! 差异仅在介质：时间基准为 UTC unix 秒（跨进程可比）。`set_if_absent`（含 `compare_and_swap(None)`
//! 委托）为单语句条件 upsert、过期行接管原子：MySQL 臂以行别名 + 双 `IF` 承载（需 MySQL 8.0.19+，
//! 唯一已知良性边缘为过期行与新 `(v, expire_at)` 完全同值同秒判无变化返回 false，下一秒重试即成功）；
//! SQLite/PG 臂以 `ON CONFLICT (k) DO UPDATE ... WHERE` 过期谓词承载（实际生效即计数，无同值边缘；
//! 旧 `INSERT OR IGNORE` 臂为 SQLite 专属语法、PostgreSQL 不可解析的缺陷随本重写闭合）。
//! 其余读-改-写方法（`incr`/`decr`/`rename`/`get_and_delete`）为两步（调用面为离线 CLI，无并发写者；
//! trait 文档要求的临界区原子性由单语句路径保证）。
//!
//! 结构化表操作与 `eval_lua` 走 trait 默认 `NotImplemented`：前者由
//! [`GarrisonDaoDbnexus`](super::dbnexus_dao) 的 SQL 方法承载，后者属 Redis 后端能力。

use super::GarrisonDao;
use crate::dao::repository::make_statement;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use dbnexus::sea_orm::{ConnectionTrait, DbBackend, Value};
use dbnexus::DbPool;
use std::time::Duration;

/// SQL 持久化 KV DAO：`garrison_kv` 表（k / v / expire_at），语义镜像 `InMemoryDao`。
pub struct DbnexusKvDao {
    pool: DbPool,
}

/// 会话 + 连接获取样板（展开出 `$session`（owned）与 `$conn`（借用）两个绑定）。
macro_rules! kv_session {
    ($self:expr, $op:expr, $session:ident, $conn:ident) => {
        let $session = $self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-kv-{}-session::{}", $op, e)))?;
        let $conn = $session
            .connection()
            .map_err(|e| GarrisonError::Dao(format!("dao-kv-{}-connection::{}", $op, e)))?;
    };
}

impl DbnexusKvDao {
    /// 创建 KV DAO（表由 [`ensure_table`](Self::ensure_table) 幂等创建）。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// 幂等建表（CLI 打开即调；部署库亦可经 `migrate_core` 的 `018_kv_store.sql` 预建）。
    pub async fn ensure_table(&self) -> GarrisonResult<()> {
        kv_session!(self, "ensure-table", session, conn);
        let stmt = make_statement(
            conn,
            "CREATE TABLE IF NOT EXISTS garrison_kv (\
             k VARCHAR PRIMARY KEY, \
             v TEXT NOT NULL, \
             expire_at BIGINT)",
            vec![],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-kv-ensure-table-execute::{e}")))?;
        Ok(())
    }

    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default()
    }

    /// 「未过期」谓词（绑定尾部 `now` 参数后使用）。
    fn live_cond() -> &'static str {
        "(expire_at IS NULL OR expire_at > ?)"
    }

    fn expire_at_from_ttl(ttl_seconds: u64) -> Option<i64> {
        if ttl_seconds == 0 {
            None
        } else {
            Some(Self::now_secs() + ttl_seconds as i64)
        }
    }

    fn remaining_secs(expire_at: Option<i64>) -> Option<Duration> {
        expire_at.map(|at| Duration::from_secs((at - Self::now_secs()).max(0) as u64))
    }

    async fn query_row(
        &self,
        op: &str,
        sql: &str,
        values: Vec<Value>,
    ) -> GarrisonResult<Option<(String, Option<i64>)>> {
        kv_session!(self, op, session, conn);
        let stmt = make_statement(conn, sql, values);
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-kv-{op}-query::{e}")))?;
        match rows.first() {
            None => Ok(None),
            Some(row) => {
                let v = row
                    .try_get::<String>("", "v")
                    .map_err(|e| GarrisonError::Dao(format!("dao-kv-{op}-read-v::{e}")))?;
                let expire_at = row
                    .try_get::<Option<i64>>("", "expire_at")
                    .map_err(|e| GarrisonError::Dao(format!("dao-kv-{op}-read-expire::{e}")))?;
                Ok(Some((v, expire_at)))
            },
        }
    }

    async fn execute(&self, op: &str, sql: &str, values: Vec<Value>) -> GarrisonResult<u64> {
        kv_session!(self, op, session, conn);
        let stmt = make_statement(conn, sql, values);
        let result = conn
            .execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-kv-{op}-execute::{e}")))?;
        Ok(result.rows_affected())
    }

    /// upsert（`expire_at: None` = 永久）；方言分支仅冲突处理子句不同。
    async fn upsert(&self, key: &str, value: &str, expire_at: Option<i64>) -> GarrisonResult<()> {
        kv_session!(self, "upsert", session, conn);
        let sql = match conn.get_database_backend() {
            DbBackend::MySql => {
                "INSERT INTO garrison_kv (k, v, expire_at) VALUES (?, ?, ?) \
                 ON DUPLICATE KEY UPDATE v = VALUES(v), expire_at = VALUES(expire_at)"
            },
            _ => {
                "INSERT INTO garrison_kv (k, v, expire_at) VALUES (?, ?, ?) \
                 ON CONFLICT (k) DO UPDATE SET v = excluded.v, expire_at = excluded.expire_at"
            },
        };
        let stmt = make_statement(
            conn,
            sql,
            vec![
                Value::String(Some(key.to_string())),
                Value::String(Some(value.to_string())),
                Value::BigInt(expire_at),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-kv-upsert-execute::{e}")))?;
        Ok(())
    }

    /// 读取未过期行的 `(v, expire_at)`；过期行顺带惰性删除（与 InMemoryDao 的访问清理一致）。
    async fn live_row(&self, op: &str, key: &str) -> GarrisonResult<Option<(String, Option<i64>)>> {
        let now = Self::now_secs();
        let found = self
            .query_row(
                op,
                &format!(
                    "SELECT v, expire_at FROM garrison_kv WHERE k = ? AND {}",
                    Self::live_cond()
                ),
                vec![
                    Value::String(Some(key.to_string())),
                    Value::BigInt(Some(now)),
                ],
            )
            .await?;
        if found.is_none() {
            self.execute(
                &format!("{op}-cleanup"),
                &format!(
                    "DELETE FROM garrison_kv WHERE k = ? AND {}",
                    Self::expired_cond()
                ),
                vec![
                    Value::String(Some(key.to_string())),
                    Value::BigInt(Some(now)),
                ],
            )
            .await?;
        }
        Ok(found)
    }

    fn expired_cond() -> &'static str {
        "(expire_at IS NOT NULL AND expire_at <= ?)"
    }
}

#[async_trait]
impl GarrisonDao for DbnexusKvDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        Ok(self.live_row("get", key).await?.map(|(v, _)| v))
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
        self.upsert(key, value, Self::expire_at_from_ttl(ttl_seconds))
            .await
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let now = Self::now_secs();
        let affected = self
            .execute(
                "update",
                &format!(
                    "UPDATE garrison_kv SET v = ? WHERE k = ? AND {}",
                    Self::live_cond()
                ),
                vec![
                    Value::String(Some(value.to_string())),
                    Value::String(Some(key.to_string())),
                    Value::BigInt(Some(now)),
                ],
            )
            .await?;
        if affected == 0 {
            return Err(GarrisonError::Dao(format!("dao-key-missing::{key}")));
        }
        Ok(())
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        let now = Self::now_secs();
        let affected = self
            .execute(
                "expire",
                &format!(
                    "UPDATE garrison_kv SET expire_at = ? WHERE k = ? AND {}",
                    Self::live_cond()
                ),
                vec![
                    Value::BigInt(Self::expire_at_from_ttl(seconds)),
                    Value::String(Some(key.to_string())),
                    Value::BigInt(Some(now)),
                ],
            )
            .await?;
        if affected == 0 {
            return Err(GarrisonError::Dao(format!("dao-key-missing::{key}")));
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.execute(
            "delete",
            "DELETE FROM garrison_kv WHERE k = ?",
            vec![Value::String(Some(key.to_string()))],
        )
        .await?;
        Ok(())
    }

    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        kv_session!(self, "set-if-absent", session, conn);
        let now = Self::now_secs();
        // 单语句条件 upsert（过期接管原子）：键不存在或已过期（expired 谓词成立）才写入，存活行拒绝且不动。
        // MySQL 臂以行别名 + 双 IF 承载谓词（需 8.0.19+）；SQLite/PG 臂以 ON CONFLICT ... WHERE 承载。
        let (sql, values) = match conn.get_database_backend() {
            DbBackend::MySql => (
                "INSERT INTO garrison_kv (k, v, expire_at) VALUES (?, ?, ?) AS new_row \
                 ON DUPLICATE KEY UPDATE \
                 v = IF(garrison_kv.expire_at IS NOT NULL AND garrison_kv.expire_at <= ?, new_row.v, garrison_kv.v), \
                 expire_at = IF(garrison_kv.expire_at IS NOT NULL AND garrison_kv.expire_at <= ?, new_row.expire_at, garrison_kv.expire_at)",
                vec![
                    Value::String(Some(key.to_string())),
                    Value::String(Some(value.to_string())),
                    Value::BigInt(Self::expire_at_from_ttl(ttl_seconds)),
                    Value::BigInt(Some(now)),
                    Value::BigInt(Some(now)),
                ],
            ),
            _ => (
                "INSERT INTO garrison_kv (k, v, expire_at) VALUES (?, ?, ?) \
                 ON CONFLICT (k) DO UPDATE SET v = excluded.v, expire_at = excluded.expire_at \
                 WHERE (garrison_kv.expire_at IS NOT NULL AND garrison_kv.expire_at <= ?)",
                vec![
                    Value::String(Some(key.to_string())),
                    Value::String(Some(value.to_string())),
                    Value::BigInt(Self::expire_at_from_ttl(ttl_seconds)),
                    Value::BigInt(Some(now)),
                ],
            ),
        };
        let stmt = make_statement(conn, sql, values);
        let result = conn
            .execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-kv-set-if-absent-execute::{e}")))?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_timeout(&self, key: &str) -> GarrisonResult<Option<Duration>> {
        Ok(self
            .live_row("get-timeout", key)
            .await?
            .and_then(|(_, expire_at)| Self::remaining_secs(expire_at)))
    }

    #[cfg(feature = "dao-key-index")]
    async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
        let now = Self::now_secs();
        kv_session!(self, "keys", session, conn);
        let stmt = make_statement(
            conn,
            &format!(
                "SELECT k, expire_at FROM garrison_kv WHERE {}",
                Self::live_cond()
            ),
            vec![Value::BigInt(Some(now))],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-kv-keys-query::{e}")))?;
        let mut keys = Vec::new();
        for row in &rows {
            let k = row
                .try_get::<String>("", "k")
                .map_err(|e| GarrisonError::Dao(format!("dao-kv-keys-read-k::{e}")))?;
            if super::in_memory::glob_match(pattern, &k) {
                keys.push(k);
            }
        }
        Ok(keys)
    }

    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
        let Some((v, expire_at)) = self.live_row("rename", old_key).await? else {
            return Err(GarrisonError::InvalidParam(format!(
                "dao-key-not-found::{old_key}"
            )));
        };
        self.upsert(new_key, &v, expire_at).await?;
        self.delete(old_key).await?;
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
        let Some((v, _)) = self.live_row("get-and-delete", key).await? else {
            return Ok(None);
        };
        self.delete(key).await?;
        Ok(Some(v))
    }

    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
        let Some((v, expire_at)) = self.live_row("incr", key).await? else {
            self.set(key, "1", ttl_seconds).await?;
            return Ok(1);
        };
        let cur: u64 = v
            .parse()
            .map_err(|_| GarrisonError::Dao(format!("dao-incr-parse-u64::{key}::{v}")))?;
        let new_val = cur
            .checked_add(1)
            .ok_or_else(|| GarrisonError::Dao(format!("dao-incr-overflow-u64::{key}")))?;
        // 保留原 expire_at（不重置 TTL，与 InMemoryDao 语义一致）
        self.upsert(key, &new_val.to_string(), expire_at).await?;
        Ok(new_val)
    }

    async fn decr(&self, key: &str) -> GarrisonResult<u64> {
        let Some((v, expire_at)) = self.live_row("decr", key).await? else {
            return Ok(0);
        };
        let cur: u64 = v
            .parse()
            .map_err(|_| GarrisonError::Dao(format!("dao-decr-parse-u64::{key}::{v}")))?;
        if cur == 0 {
            return Ok(0);
        }
        let new_val = cur - 1;
        if new_val == 0 {
            self.delete(key).await?;
        } else {
            self.upsert(key, &new_val.to_string(), expire_at).await?;
        }
        Ok(new_val)
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        // 先清理过期行（过期视为不存在）
        let now = Self::now_secs();
        self.execute(
            "compare-and-swap-cleanup",
            &format!(
                "DELETE FROM garrison_kv WHERE k = ? AND {}",
                Self::expired_cond()
            ),
            vec![
                Value::String(Some(key.to_string())),
                Value::BigInt(Some(now)),
            ],
        )
        .await?;
        match expected {
            // 单语句原子 CAS：当前值等于 expected 才写入
            Some(expected_value) => {
                let affected = self
                    .execute(
                        "compare-and-swap",
                        "UPDATE garrison_kv SET v = ?, expire_at = ? WHERE k = ? AND v = ?",
                        vec![
                            Value::String(Some(new_value.to_string())),
                            Value::BigInt(Self::expire_at_from_ttl(ttl_seconds)),
                            Value::String(Some(key.to_string())),
                            Value::String(Some(expected_value.to_string())),
                        ],
                    )
                    .await?;
                Ok(affected > 0)
            },
            None => self.set_if_absent(key, new_value, ttl_seconds).await,
        }
    }
}
