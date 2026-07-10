//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 设备管理模块。
//!
//! 提供设备会话管理与设备指纹生成。

use crate::error::BulwarkResult;
use crate::session::BulwarkSession;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// 设备会话信息。
///
/// 由 [`DeviceManager::list_devices`] 返回，描述一个活跃会话的设备信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSession {
    /// 设备标识（如 "web"/"ios"/"android" 或自动生成的指纹）。
    pub device: String,
    /// 关联的登录主体标识。
    pub login_id: String,
    /// 会话 token。
    pub token: String,
    /// 客户端 IP 地址。
    pub ip: Option<String>,
    /// 客户端 User-Agent。
    pub user_agent: Option<String>,
    /// 最后活跃时间戳（Unix 秒）。
    pub last_active_at: i64,
}

/// 设备管理器，提供设备级会话查询与踢出。
///
/// 持有 [`BulwarkSession`] 引用，通过 `login_token_map` 和 `TokenSession` 实现设备管理。
pub struct DeviceManager {
    /// 会话管理器引用。
    session: Arc<BulwarkSession>,
}

impl DeviceManager {
    /// 创建设备管理器实例。
    pub fn new(session: Arc<BulwarkSession>) -> Self {
        Self { session }
    }

    /// 列出指定 login_id 的所有设备会话。
    ///
    /// 遍历 `login_token_map` 中的 token，查询每个 `TokenSession`，
    /// 映射为 [`DeviceSession`] 返回。已过期或不存在的 token 被跳过（不返回错误）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// `Vec<DeviceSession>`，无会话时返回空 Vec。
    pub async fn list_devices(&self, login_id: &str) -> BulwarkResult<Vec<DeviceSession>> {
        let tokens = self.session.get_tokens_by_login_id(login_id);
        let mut devices = Vec::with_capacity(tokens.len());
        for token in tokens {
            if let Some(ts) = self.session.get_token_session(&token).await? {
                devices.push(DeviceSession {
                    device: ts.device.unwrap_or_default(),
                    login_id: ts.login_id,
                    token: ts.token,
                    ip: ts.ip,
                    user_agent: ts.user_agent,
                    last_active_at: ts.last_active_at,
                });
            }
        }
        Ok(devices)
    }

    /// 踢出指定设备的会话。
    ///
    /// 委托 [`BulwarkSession::kickout_by_device`]，踢出指定 login_id 中
    /// `device` 字段匹配的所有 TokenSession。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `device`: 设备标识。
    ///
    /// # 错误
    /// 透传 `BulwarkSession::kickout_by_device` 的错误。
    pub async fn kickout_device(&self, login_id: &str, device: &str) -> BulwarkResult<()> {
        self.session.kickout_by_device(login_id, device).await
    }
}

/// 生成设备指纹：SHA-256(UA + IP)，截断 16 字节 hex = 32 字符。
///
/// # 参数
/// - `user_agent`: 客户端 User-Agent 字符串。
/// - `ip`: 客户端 IP 地址。
///
/// # 返回
/// 32 字符的十六进制字符串（SHA-256 前 16 字节）。
pub fn device_fingerprint(user_agent: &str, ip: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(user_agent.as_bytes());
    hasher.update(ip.as_bytes());
    let result = hasher.finalize();
    // 取前 16 字节，hex 编码 = 32 字符
    result
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_fingerprint_deterministic() {
        let fp1 = device_fingerprint("Mozilla/5.0 Chrome", "192.168.1.1");
        let fp2 = device_fingerprint("Mozilla/5.0 Chrome", "192.168.1.1");
        assert_eq!(fp1, fp2, "相同输入应生成相同指纹");
    }

    #[test]
    fn device_fingerprint_different_inputs_different_output() {
        let fp1 = device_fingerprint("Mozilla/5.0 Chrome", "192.168.1.1");
        let fp2 = device_fingerprint("Mozilla/5.0 Firefox", "192.168.1.1");
        assert_ne!(fp1, fp2, "不同 UA 应生成不同指纹");

        let fp3 = device_fingerprint("Mozilla/5.0 Chrome", "10.0.0.1");
        assert_ne!(fp1, fp3, "不同 IP 应生成不同指纹");
    }

    #[test]
    fn device_fingerprint_length_is_32() {
        let fp = device_fingerprint("TestAgent", "127.0.0.1");
        assert_eq!(fp.len(), 32, "指纹应为 32 字符（16 字节 hex）");
    }

    // ------------------------------------------------------------------------
    // list_devices
    // ------------------------------------------------------------------------

    /// 辅助函数：创建带 MockDao 的 Arc<BulwarkSession>（供 DeviceManager 使用）。
    fn make_device_session(timeout: u64, active_timeout: u64) -> Arc<BulwarkSession> {
        use crate::dao::tests::MockDao;
        let dao: Arc<dyn crate::dao::BulwarkDao> = Arc::new(MockDao::new());
        Arc::new(BulwarkSession::new(dao, timeout, active_timeout))
    }

    /// 验证 list_devices 返回指定 login_id 的所有活跃设备会话。
    #[tokio::test]
    async fn list_devices_returns_all_active_sessions() {
        let session = make_device_session(3600, 86400);

        session.create("user-001", "token-1").await.unwrap();
        session.create("user-001", "token-2").await.unwrap();

        let mgr = DeviceManager::new(session);
        let devices = mgr.list_devices("user-001").await.unwrap();
        assert_eq!(devices.len(), 2, "应有 2 个设备会话");

        for d in &devices {
            assert_eq!(d.login_id, "user-001");
            assert!(!d.token.is_empty());
        }
    }

    /// 验证 list_devices 在无会话时返回空列表。
    #[tokio::test]
    async fn list_devices_empty_when_no_sessions() {
        let session = make_device_session(3600, 86400);

        let mgr = DeviceManager::new(session);
        let devices = mgr.list_devices("nonexistent-user").await.unwrap();
        assert!(devices.is_empty(), "无会话时应返回空列表");
    }

    // ------------------------------------------------------------------------
    // kickout_device
    // ------------------------------------------------------------------------

    /// 验证 kickout_device 踢出 device 匹配的会话，保留不匹配的会话。
    #[tokio::test]
    async fn kickout_device_removes_matching_session() {
        let session = make_device_session(3600, 86400);

        // 创建带 device="web" 的会话
        let params = crate::stp::LoginParams {
            device: Some("web".to_string()),
            ..Default::default()
        };
        session
            .create_token_session("user-kickout-001", "token-with-device", &params)
            .await
            .unwrap();

        // 创建不带 device 的会话
        session
            .create("user-kickout-001", "token-no-device")
            .await
            .unwrap();

        let mgr = DeviceManager::new(session.clone());
        let result = mgr.kickout_device("user-kickout-001", "web").await;
        assert!(result.is_ok(), "kickout_device 应成功");

        // 带 device="web" 的会话应被踢出
        let removed = session
            .get_token_session("token-with-device")
            .await
            .unwrap();
        assert!(removed.is_none(), "device 匹配的会话应被踢出");

        // 不带 device 的会话应保留
        let kept = session.get_token_session("token-no-device").await.unwrap();
        assert!(kept.is_some(), "device 不匹配的会话应保留");
    }
}
