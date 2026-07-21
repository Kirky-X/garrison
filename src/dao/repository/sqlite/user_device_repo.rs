//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusUserDeviceRepository 实现（app_user_device 表）。

use super::{read_bool, v_i64, v_opt_str, v_str, DbnexusUserDeviceRepository};
use crate::dao::repository::{make_statement, UserDeviceRepository, UserDeviceRow, MAX_DEVICES};
use crate::error::{GarrisonError, GarrisonResult};
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
    ) -> GarrisonResult<String> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!(
                "dao-app-user-device-register-device-session::{}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!(
                "dao-app-user-device-register-device-connection::{}",
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
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-device-query-exists::{}", e)))?;

        if let Some(row) = existing {
            let existing_id: String = row.try_get("", "id").map_err(|e| {
                GarrisonError::Dao(format!("dao-app-user-device-parse-exists-id::{}", e))
            })?;
            // 更新 last_seen_at（幂等注册视为一次活跃）
            let now = chrono::Utc::now().timestamp();
            let update_sql = "UPDATE app_user_device SET last_seen_at = ? WHERE id = ?";
            let stmt = make_statement(conn, update_sql, vec![v_i64(now), v_str(&existing_id)]);
            conn.execute_raw(stmt).await.map_err(|e| {
                GarrisonError::Dao(format!("dao-app-user-device-update-last-seen-at::{}", e))
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
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-device-count-query::{}", e)))?
            .ok_or_else(|| GarrisonError::Dao("dao-app-user-device-count-empty".into()))?;
        let current_count: i64 = count_row
            .try_get("", "cnt")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-device-parse-count::{}", e)))?;
        if (current_count as usize) >= MAX_DEVICES {
            return Err(GarrisonError::InvalidParam(format!(
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
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-device-insert::{}", e)))?;
        Ok(device_id)
    }

    async fn block_device(&self, device_id: &str) -> GarrisonResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-block-device-session::{}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!(
                "dao-app-user-device-block-device-connection::{}",
                e
            ))
        })?;
        let sql = "UPDATE app_user_device SET is_blocked = 1 WHERE id = ?";
        let stmt = make_statement(conn, sql, vec![v_str(device_id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-device-block-update::{}", e)))?;
        Ok(())
    }

    async fn unblock_device(&self, device_id: &str) -> GarrisonResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-unblock-device-session::{}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!(
                "dao-app-user-device-unblock-device-connection::{}",
                e
            ))
        })?;
        let sql = "UPDATE app_user_device SET is_blocked = 0 WHERE id = ?";
        let stmt = make_statement(conn, sql, vec![v_str(device_id)]);
        conn.execute_raw(stmt).await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-unblock-update::{}", e))
        })?;
        Ok(())
    }

    async fn list_user_devices(
        &self,
        tenant_id: i64,
        login_id: &str,
    ) -> GarrisonResult<Vec<UserDeviceRow>> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                GarrisonError::Dao(format!("dao-app-user-device-list-session::{}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-list-connection::{}", e))
        })?;
        let sql = "SELECT id, tenant_id, login_id, device_identifier, device_name, user_agent, \
                  is_blocked, last_seen_at, created_at \
                  FROM app_user_device WHERE tenant_id = ? AND login_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(login_id)]);
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-device-list-query::{}", e)))?;
        rows.iter().map(parse_user_device_row).collect()
    }

    async fn count_user_devices(&self, tenant_id: i64, login_id: &str) -> GarrisonResult<usize> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                GarrisonError::Dao(format!("dao-app-user-device-count-session::{}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-count-connection::{}", e))
        })?;
        let sql =
            "SELECT COUNT(*) AS cnt FROM app_user_device WHERE tenant_id = ? AND login_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(login_id)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-device-count-query::{}", e)))?
            .ok_or_else(|| GarrisonError::Dao("dao-app-user-device-count-empty".into()))?;
        let count: i64 = row
            .try_get("", "cnt")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-device-parse-count::{}", e)))?;
        Ok(count as usize)
    }
}

/// 解析 app_user_device 行。
fn parse_user_device_row(row: &QueryResult) -> GarrisonResult<UserDeviceRow> {
    Ok(UserDeviceRow {
        id: row
            .try_get("", "id")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-device-row-parse-id::{}", e)))?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-row-parse-tenant-id::{}", e))
        })?,
        login_id: row.try_get("", "login_id").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-row-parse-login-id::{}", e))
        })?,
        device_identifier: row.try_get("", "device_identifier").map_err(|e| {
            GarrisonError::Dao(format!(
                "dao-app-user-device-row-parse-device-identifier::{}",
                e
            ))
        })?,
        device_name: row.try_get("", "device_name").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-row-parse-device-name::{}", e))
        })?,
        user_agent: row.try_get("", "user_agent").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-row-parse-user-agent::{}", e))
        })?,
        is_blocked: read_bool(row, "is_blocked"),
        last_seen_at: row.try_get("", "last_seen_at").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-row-parse-last-seen-at::{}", e))
        })?,
        created_at: row.try_get("", "created_at").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-device-row-parse-created-at::{}", e))
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
            GarrisonError::InvalidParam(msg) => {
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

    // ========================================================================
    // 纯函数测试：parse_device_name / detect_browser / detect_os
    // （不依赖数据库，验证 UA 解析逻辑）
    // ========================================================================

    /// parse_device_name 从 Chrome on Windows UA 提取 "Chrome on Windows"。
    #[test]
    fn parse_device_name_chrome_on_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";
        assert_eq!(parse_device_name(ua).as_deref(), Some("Chrome on Windows"));
    }

    /// parse_device_name 从 Firefox on macOS UA 提取 "Firefox on macOS"。
    #[test]
    fn parse_device_name_firefox_on_macos() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Firefox/121.0";
        assert_eq!(parse_device_name(ua).as_deref(), Some("Firefox on macOS"));
    }

    /// parse_device_name 从 Edge UA 提取 "Edge"（Edg/ 必须在 Chrome/ 之前检测）。
    #[test]
    fn parse_device_name_edge_before_chrome() {
        let ua = "Mozilla/5.0 (Windows NT 10.0) Edg/120.0 Chrome/120.0";
        assert_eq!(parse_device_name(ua).as_deref(), Some("Edge on Windows"));
    }

    /// parse_device_name 从 Safari on iOS UA 提取 "Safari on iOS"。
    #[test]
    fn parse_device_name_safari_on_ios() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1";
        assert_eq!(parse_device_name(ua).as_deref(), Some("Safari on iOS"));
    }

    /// parse_device_name 从 Opera UA 提取 "Opera"。
    #[test]
    fn parse_device_name_opera() {
        let ua = "Mozilla/5.0 (Windows NT 10.0) OPR/120.0";
        assert_eq!(parse_device_name(ua).as_deref(), Some("Opera on Windows"));
    }

    /// parse_device_name 从 Android UA 提取浏览器 + Android。
    #[test]
    fn parse_device_name_chrome_on_android() {
        let ua = "Mozilla/5.0 (Linux; Android 14) Chrome/120.0";
        assert_eq!(parse_device_name(ua).as_deref(), Some("Chrome on Android"));
    }

    /// parse_device_name 从 Linux UA 提取。
    #[test]
    fn parse_device_name_firefox_on_linux() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0";
        assert_eq!(parse_device_name(ua).as_deref(), Some("Firefox on Linux"));
    }

    /// parse_device_name 空字符串返回 None。
    #[test]
    fn parse_device_name_empty_returns_none() {
        assert!(parse_device_name("").is_none());
    }

    /// parse_device_name 未知浏览器但有 OS 时仅返回 OS。
    #[test]
    fn parse_device_name_unknown_browser_with_os() {
        let ua = "SomeBot/1.0 (Windows NT 10.0)";
        assert_eq!(parse_device_name(ua).as_deref(), Some("Windows"));
    }

    /// parse_device_name 已知浏览器但无 OS 时仅返回浏览器名。
    #[test]
    fn parse_device_name_browser_without_os() {
        let ua = "Mozilla/5.0 Chrome/120.0";
        assert_eq!(parse_device_name(ua).as_deref(), Some("Chrome"));
    }

    /// parse_device_name 未知浏览器且无 OS 时返回 None。
    #[test]
    fn parse_device_name_unknown_no_browser_no_os() {
        let ua = "curl/8.0";
        assert!(parse_device_name(ua).is_none());
    }

    /// detect_browser 检测 Edge（Edg/ 优先于 Chrome/）。
    #[test]
    fn detect_browser_edge_priority() {
        assert_eq!(
            detect_browser("Edg/120 Chrome/120").as_deref(),
            Some("Edge")
        );
    }

    /// detect_browser 检测 Firefox。
    #[test]
    fn detect_browser_firefox() {
        assert_eq!(detect_browser("Firefox/121").as_deref(), Some("Firefox"));
    }

    /// detect_browser 检测 Chrome。
    #[test]
    fn detect_browser_chrome() {
        assert_eq!(detect_browser("Chrome/120").as_deref(), Some("Chrome"));
    }

    /// detect_browser 检测 Safari。
    #[test]
    fn detect_browser_safari() {
        assert_eq!(detect_browser("Safari/604").as_deref(), Some("Safari"));
    }

    /// detect_browser 检测 Opera（OPR/ 变体）。
    #[test]
    fn detect_browser_opera_opr() {
        assert_eq!(detect_browser("OPR/120").as_deref(), Some("Opera"));
    }

    /// detect_browser 检测 Opera（Opera/ 变体）。
    #[test]
    fn detect_browser_opera_opera() {
        assert_eq!(detect_browser("Opera/120").as_deref(), Some("Opera"));
    }

    /// detect_browser 未知浏览器返回 None。
    #[test]
    fn detect_browser_unknown_returns_none() {
        assert!(detect_browser("Bot/1.0").is_none());
    }

    /// detect_os 检测 Windows。
    #[test]
    fn detect_os_windows() {
        assert_eq!(detect_os("Windows NT 10.0").as_deref(), Some("Windows"));
    }

    /// detect_os 检测 iOS（iPhone）。
    #[test]
    fn detect_os_ios_iphone() {
        assert_eq!(detect_os("iPhone OS 17").as_deref(), Some("iOS"));
    }

    /// detect_os 检测 iOS（iPad）。
    #[test]
    fn detect_os_ios_ipad() {
        assert_eq!(detect_os("iPad CPU OS 17").as_deref(), Some("iOS"));
    }

    /// detect_os 检测 macOS。
    #[test]
    fn detect_os_macos() {
        assert_eq!(detect_os("Mac OS X 10_15").as_deref(), Some("macOS"));
    }

    /// detect_os 检测 macOS（Macintosh 变体）。
    #[test]
    fn detect_os_macos_macintosh() {
        assert_eq!(detect_os("Macintosh").as_deref(), Some("macOS"));
    }

    /// detect_os 检测 Android。
    #[test]
    fn detect_os_android() {
        assert_eq!(detect_os("Android 14").as_deref(), Some("Android"));
    }

    /// detect_os 检测 Linux。
    #[test]
    fn detect_os_linux() {
        assert_eq!(detect_os("Linux x86_64").as_deref(), Some("Linux"));
    }

    /// detect_os 未知 OS 返回 None。
    #[test]
    fn detect_os_unknown_returns_none() {
        assert!(detect_os("UnknownOS").is_none());
    }

    // ========================================================================
    // DB 边界场景测试
    // ========================================================================

    /// register_device 空 UA 字符串时 device_name 为 None，但仍能注册。
    #[tokio::test(flavor = "multi_thread")]
    async fn register_device_with_empty_ua() {
        let pool = setup_db().await;
        let repo = DbnexusUserDeviceRepository::new(pool);

        let _device_id = repo
            .register_device(1, "login-empty-ua", "fp-empty", "")
            .await
            .expect("空 UA register 应成功");

        let devices = repo
            .list_user_devices(1, "login-empty-ua")
            .await
            .expect("list 应成功");
        assert_eq!(devices.len(), 1);
        assert!(
            devices[0].device_name.is_none(),
            "空 UA device_name 应为 None"
        );
        assert!(devices[0].user_agent.as_deref() == Some(""));
    }

    /// block_device / unblock_device 对不存在的 device_id 不报错（幂等）。
    #[tokio::test(flavor = "multi_thread")]
    async fn block_nonexistent_device_is_noop() {
        let pool = setup_db().await;
        let repo = DbnexusUserDeviceRepository::new(pool);

        repo.block_device("nonexistent-device")
            .await
            .expect("block 不存在的设备应为 no-op");
        repo.unblock_device("nonexistent-device")
            .await
            .expect("unblock 不存在的设备应为 no-op");
    }

    /// list_user_devices 查询不存在的 login_id 应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_user_devices_nonexistent_returns_empty() {
        let pool = setup_db().await;
        let repo = DbnexusUserDeviceRepository::new(pool);

        let devices = repo
            .list_user_devices(1, "nonexistent-login")
            .await
            .expect("list 应成功");
        assert!(devices.is_empty(), "不存在的 login_id 应返回空列表");
    }

    /// register_device 不同 tenant_id 下相同 login_id 互不干扰。
    #[tokio::test(flavor = "multi_thread")]
    async fn register_device_isolates_by_tenant() {
        let pool = setup_db().await;
        let repo = DbnexusUserDeviceRepository::new(pool);

        repo.register_device(1, "shared-login", "fp-1", "Chrome/120")
            .await
            .expect("tenant 1 register 应成功");
        repo.register_device(2, "shared-login", "fp-2", "Chrome/120")
            .await
            .expect("tenant 2 register 应成功");

        let count_1 = repo
            .count_user_devices(1, "shared-login")
            .await
            .expect("count tenant 1 应成功");
        let count_2 = repo
            .count_user_devices(2, "shared-login")
            .await
            .expect("count tenant 2 应成功");
        assert_eq!(count_1, 1, "tenant 1 应有 1 个设备");
        assert_eq!(count_2, 1, "tenant 2 应有 1 个设备");
    }
}
