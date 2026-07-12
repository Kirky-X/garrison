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
