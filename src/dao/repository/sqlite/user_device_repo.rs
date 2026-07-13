//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusUserDeviceRepository 实现（app_user_device 表）。

use super::{read_bool, v_i64, v_opt_str, v_str, DbnexusUserDeviceRepository};
use crate::dao::repository::{make_statement, UserDeviceRepository, UserDeviceRow, MAX_DEVICES};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusUserDeviceRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserDeviceRepository for DbnexusUserDeviceRepository {
    async fn register_device(
        &self,
        tenant_id: i64,
        login_id: &str,
        identifier: &str,
        ua: &str,
    ) -> BulwarkResult<String> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device register_device 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device register_device 获取 connection 失败: {}",
                e
            ))
        })?;

        // 1. 检查是否已存在（幂等：相同 tenant_id + login_id + identifier 返回已有 ID）
        let find_sql = "SELECT id FROM app_user_device \
                        WHERE tenant_id = ? AND login_id = ? AND device_identifier = ?";
        let stmt = make_statement(
            conn,
            find_sql,
            vec![v_i64(tenant_id), v_str(login_id), v_str(identifier)],
        );
        let existing = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device 查询已存在失败: {}", e)))?;

        if let Some(row) = existing {
            let existing_id: String = row.try_get("", "id").map_err(|e| {
                BulwarkError::Dao(format!("app_user_device 解析已存在 id 失败: {}", e))
            })?;
            // 更新 last_seen_at（幂等注册视为一次活跃）
            let now = chrono::Utc::now().timestamp();
            let update_sql = "UPDATE app_user_device SET last_seen_at = ? WHERE id = ?";
            let stmt = make_statement(conn, update_sql, vec![v_i64(now), v_str(&existing_id)]);
            conn.execute_raw(stmt).await.map_err(|e| {
                BulwarkError::Dao(format!("app_user_device 更新 last_seen_at 失败: {}", e))
            })?;
            return Ok(existing_id);
        }

        // 2. 检查是否超过 MAX_DEVICES
        let count_sql =
            "SELECT COUNT(*) AS cnt FROM app_user_device WHERE tenant_id = ? AND login_id = ?";
        let stmt = make_statement(conn, count_sql, vec![v_i64(tenant_id), v_str(login_id)]);
        let count_row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device count 查询失败: {}", e)))?
            .ok_or_else(|| BulwarkError::Dao("app_user_device COUNT(*) 未返回行".into()))?;
        let current_count: i64 = count_row
            .try_get("", "cnt")
            .map_err(|e| BulwarkError::Dao(format!("app_user_device 解析 count 失败: {}", e)))?;
        if (current_count as usize) >= MAX_DEVICES {
            return Err(BulwarkError::InvalidParam(format!(
                "用户 (tenant_id={}, login_id={}) 设备数已达上限 {}，无法注册新设备",
                tenant_id, login_id, MAX_DEVICES
            )));
        }

        // 3. 插入新设备
        let device_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        let device_name = parse_device_name(ua);
        let insert_sql = "INSERT INTO app_user_device \
                          (id, tenant_id, login_id, device_identifier, device_name, user_agent, is_blocked, last_seen_at, created_at) \
                          VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)";
        let stmt = make_statement(
            conn,
            insert_sql,
            vec![
                v_str(&device_id),
                v_i64(tenant_id),
                v_str(login_id),
                v_str(identifier),
                v_opt_str(&device_name),
                v_opt_str(&Some(ua.to_string())),
                v_i64(now),
                v_i64(now),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device 插入失败: {}", e)))?;
        Ok(device_id)
    }

    async fn block_device(&self, device_id: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device block_device 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device block_device 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "UPDATE app_user_device SET is_blocked = 1 WHERE id = ?";
        let stmt = make_statement(conn, sql, vec![v_str(device_id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device block 更新失败: {}", e)))?;
        Ok(())
    }

    async fn unblock_device(&self, device_id: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device unblock_device 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device unblock_device 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "UPDATE app_user_device SET is_blocked = 0 WHERE id = ?";
        let stmt = make_statement(conn, sql, vec![v_str(device_id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device unblock 更新失败: {}", e)))?;
        Ok(())
    }

    async fn list_user_devices(
        &self,
        tenant_id: i64,
        login_id: &str,
    ) -> BulwarkResult<Vec<UserDeviceRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_device list 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_device list 获取 connection 失败: {}", e))
        })?;
        let sql = "SELECT id, tenant_id, login_id, device_identifier, device_name, user_agent, \
                  is_blocked, last_seen_at, created_at \
                  FROM app_user_device WHERE tenant_id = ? AND login_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(login_id)]);
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device list 查询失败: {}", e)))?;
        rows.iter().map(parse_user_device_row).collect()
    }

    async fn count_user_devices(&self, tenant_id: i64, login_id: &str) -> BulwarkResult<usize> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_device count 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_device count 获取 connection 失败: {}", e))
        })?;
        let sql =
            "SELECT COUNT(*) AS cnt FROM app_user_device WHERE tenant_id = ? AND login_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(login_id)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device count 查询失败: {}", e)))?
            .ok_or_else(|| BulwarkError::Dao("app_user_device COUNT(*) 未返回行".into()))?;
        let count: i64 = row
            .try_get("", "cnt")
            .map_err(|e| BulwarkError::Dao(format!("app_user_device 解析 count 失败: {}", e)))?;
        Ok(count as usize)
    }
}

/// 解析 app_user_device 行。
fn parse_user_device_row(row: &QueryResult) -> BulwarkResult<UserDeviceRow> {
    Ok(UserDeviceRow {
        id: row
            .try_get("", "id")
            .map_err(|e| BulwarkError::Dao(format!("app_user_device 行解析失败 (id): {}", e)))?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (tenant_id): {}", e))
        })?,
        login_id: row.try_get("", "login_id").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (login_id): {}", e))
        })?,
        device_identifier: row.try_get("", "device_identifier").map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device 行解析失败 (device_identifier): {}",
                e
            ))
        })?,
        device_name: row.try_get("", "device_name").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (device_name): {}", e))
        })?,
        user_agent: row.try_get("", "user_agent").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (user_agent): {}", e))
        })?,
        is_blocked: read_bool(row, "is_blocked"),
        last_seen_at: row.try_get("", "last_seen_at").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (last_seen_at): {}", e))
        })?,
        created_at: row.try_get("", "created_at").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (created_at): {}", e))
        })?,
    })
}

/// 从 User-Agent 字符串解析设备名（简单字符串启发式）。
///
/// 完整 `ua-parser` regex 集需启用 `ua-parser-precompiled` feature（设计 A4 决策延后），
/// 当前用关键字匹配提取 Browser + OS 信息。
fn parse_device_name(ua: &str) -> Option<String> {
    if ua.is_empty() {
        return None;
    }
    let browser = detect_browser(ua);
    let os = detect_os(ua);
    match (browser, os) {
        (Some(b), Some(o)) => Some(format!("{} on {}", b, o)),
        (Some(b), None) => Some(b),
        (None, Some(o)) => Some(o),
        (None, None) => None,
    }
}

/// 从 UA 检测浏览器名。
fn detect_browser(ua: &str) -> Option<String> {
    // 注意：检测顺序重要——Edg 必须在 Chrome 之前（Edge UA 包含 Chrome）
    if ua.contains("Edg/") {
        Some("Edge".into())
    } else if ua.contains("Firefox/") {
        Some("Firefox".into())
    } else if ua.contains("Chrome/") {
        Some("Chrome".into())
    } else if ua.contains("Safari/") {
        Some("Safari".into())
    } else if ua.contains("OPR/") || ua.contains("Opera/") {
        Some("Opera".into())
    } else {
        None
    }
}

/// 从 UA 检测操作系统名。
fn detect_os(ua: &str) -> Option<String> {
    if ua.contains("Windows NT") {
        Some("Windows".into())
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        Some("iOS".into())
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("macOS".into())
    } else if ua.contains("Android") {
        Some("Android".into())
    } else if ua.contains("Linux") {
        Some("Linux".into())
    } else {
        None
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;

    /// register_device 首次注册应返回合法 UUID，且 list 中能查到。
    #[tokio::test(flavor = "multi_thread")]
    async fn register_device_returns_uuid() {
        let pool = setup_db().await;
        let repo = DbnexusUserDeviceRepository::new(pool);

        let device_id = repo
            .register_device(
                1,
                "login-001",
                "fingerprint-abc",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            )
            .await
            .expect("register_device 应成功");

        // 验证返回的是合法 UUID
        let parsed = uuid::Uuid::parse_str(&device_id).expect("返回的 device_id 应为合法 UUID");
        assert_eq!(
            parsed.get_version(),
            Some(uuid::Version::Random),
            "应为 UUID v4"
        );

        // list 中应能查到
        let devices = repo
            .list_user_devices(1, "login-001")
            .await
            .expect("list_user_devices 应成功");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, device_id);
        assert_eq!(devices[0].device_identifier, "fingerprint-abc");
        assert!(!devices[0].is_blocked);
        // device_name 应从 UA 解析（Chrome on Windows）
        assert_eq!(devices[0].device_name.as_deref(), Some("Chrome on Windows"));
    }

    /// register_device 幂等：相同 (tenant, login_id, identifier) 返回同一 ID，且 last_seen_at 更新。
    #[tokio::test(flavor = "multi_thread")]
    async fn register_device_idempotent_returns_same_id() {
        let pool = setup_db().await;
        let repo = DbnexusUserDeviceRepository::new(pool);

        let id1 = repo
            .register_device(1, "login-002", "fp-same", "Firefox/120.0")
            .await
            .expect("首次 register 应成功");

        let id2 = repo
            .register_device(1, "login-002", "fp-same", "Firefox/121.0")
            .await
            .expect("幂等 register 应成功");

        assert_eq!(id1, id2, "幂等注册应返回相同 ID");

        // 仍只有 1 条记录
        let count = repo
            .count_user_devices(1, "login-002")
            .await
            .expect("count 应成功");
        assert_eq!(count, 1, "幂等注册不应新增记录");
    }

    /// register_device 达到 MAX_DEVICES 后拒绝新设备，返回 InvalidParam 错误。
    #[tokio::test(flavor = "multi_thread")]
    async fn register_device_exceeds_max_devices() {
        let pool = setup_db().await;
        let repo = DbnexusUserDeviceRepository::new(pool);

        // 注册 MAX_DEVICES（5）个不同设备
        for i in 0..MAX_DEVICES {
            repo.register_device(
                1,
                "login-max",
                &format!("fp-{}", i),
                "Mozilla/5.0 Chrome/120.0",
            )
            .await
            .expect("注册设备应成功");
        }

        let count = repo
            .count_user_devices(1, "login-max")
            .await
            .expect("count 应成功");
        assert_eq!(count, MAX_DEVICES, "应有 MAX_DEVICES 个设备");

        // 第 6 个设备应被拒绝
        let result = repo
            .register_device(1, "login-max", "fp-overflow", "Chrome/120.0")
            .await;
        assert!(result.is_err(), "超过 MAX_DEVICES 应返回错误");
        let err = result.unwrap_err();
        match err {
            BulwarkError::InvalidParam(msg) => {
                assert!(
                    msg.contains("MAX_DEVICES") || msg.contains("设备数已达上限"),
                    "错误信息应包含设备上限，实际: {}",
                    msg
                );
            },
            other => panic!("应为 InvalidParam 错误，实际: {:?}", other),
        }
    }

    /// block_device / unblock_device 切换 is_blocked 状态。
    #[tokio::test(flavor = "multi_thread")]
    async fn block_and_unblock_device() {
        let pool = setup_db().await;
        let repo = DbnexusUserDeviceRepository::new(pool);

        let device_id = repo
            .register_device(1, "login-block", "fp-block", "Safari/17.0")
            .await
            .expect("register 应成功");

        // 初始状态未阻断
        let devices = repo
            .list_user_devices(1, "login-block")
            .await
            .expect("list 应成功");
        assert!(!devices[0].is_blocked, "初始状态应未阻断");

        // 阻断
        repo.block_device(&device_id)
            .await
            .expect("block_device 应成功");
        let devices = repo
            .list_user_devices(1, "login-block")
            .await
            .expect("list 应成功");
        assert!(devices[0].is_blocked, "阻断后 is_blocked 应为 true");

        // 解除阻断
        repo.unblock_device(&device_id)
            .await
            .expect("unblock_device 应成功");
        let devices = repo
            .list_user_devices(1, "login-block")
            .await
            .expect("list 应成功");
        assert!(!devices[0].is_blocked, "解除后 is_blocked 应为 false");
    }

    /// list_user_devices 按 (tenant_id, login_id) 过滤，不同 login_id 互不干扰。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_user_devices_filters_by_login_id() {
        let pool = setup_db().await;
        let repo = DbnexusUserDeviceRepository::new(pool);

        // login-a 注册 2 个设备
        repo.register_device(1, "login-a", "fp-a1", "Chrome/120.0")
            .await
            .expect("register 应成功");
        repo.register_device(1, "login-a", "fp-a2", "Edge/120.0")
            .await
            .expect("register 应成功");

        // login-b 注册 1 个设备
        repo.register_device(1, "login-b", "fp-b1", "Firefox/120.0")
            .await
            .expect("register 应成功");

        let list_a = repo
            .list_user_devices(1, "login-a")
            .await
            .expect("list login-a 应成功");
        let list_b = repo
            .list_user_devices(1, "login-b")
            .await
            .expect("list login-b 应成功");
        assert_eq!(list_a.len(), 2, "login-a 应有 2 个设备");
        assert_eq!(list_b.len(), 1, "login-b 应有 1 个设备");
    }

    /// count_user_devices 返回正确计数，空用户返回 0。
    #[tokio::test(flavor = "multi_thread")]
    async fn count_user_devices_empty_returns_zero() {
        let pool = setup_db().await;
        let repo = DbnexusUserDeviceRepository::new(pool);

        // 空用户
        let count = repo
            .count_user_devices(1, "nonexistent-login")
            .await
            .expect("count 应成功");
        assert_eq!(count, 0, "空用户设备数应为 0");

        // 注册 1 个后
        repo.register_device(1, "login-count", "fp-1", "Chrome/120.0")
            .await
            .expect("register 应成功");
        let count = repo
            .count_user_devices(1, "login-count")
            .await
            .expect("count 应成功");
        assert_eq!(count, 1, "注册 1 个后应为 1");
    }
}
