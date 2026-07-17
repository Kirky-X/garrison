//! Copyright (c) 2026 Kirky.X. All rights reserved.
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

/// 设备指纹输入维度（A10 强化：防止攻击者仅伪造部分 header 即可复用指纹）。
///
/// 封装参与设备指纹计算的全部维度。`accept_language` / `sec_ch_ua` /
/// `sec_ch_ua_platform` 为 `Option`，未提供时以哨兵字节 `\0` 参与 hash，
/// 与 `Some("")` 区分（fail-safe：缺失维度不等于空串维度，防止攻击者
/// 通过省略 header 绕过维度校验）。
#[derive(Debug, Clone, Copy)]
pub struct DeviceFingerprintInput<'a> {
    /// 客户端 User-Agent。
    pub user_agent: &'a str,
    /// 客户端 IP 地址。
    pub ip: &'a str,
    /// Accept-Language header（如 "zh-CN,zh;q=0.9,en;q=0.8"）。
    pub accept_language: Option<&'a str>,
    /// sec-ch-ua header（如 `"Chromium";v="120", "Not.A/Brand";v="24"`）。
    pub sec_ch_ua: Option<&'a str>,
    /// sec-ch-ua-platform header（如 `"Windows"`）。
    pub sec_ch_ua_platform: Option<&'a str>,
}

impl<'a> DeviceFingerprintInput<'a> {
    /// 创建包含全部维度的输入。
    pub fn new(
        user_agent: &'a str,
        ip: &'a str,
        accept_language: Option<&'a str>,
        sec_ch_ua: Option<&'a str>,
        sec_ch_ua_platform: Option<&'a str>,
    ) -> Self {
        Self {
            user_agent,
            ip,
            accept_language,
            sec_ch_ua,
            sec_ch_ua_platform,
        }
    }

    /// 仅从 ua + ip 构造（其他维度为 None，向后兼容旧 `device_fingerprint` 调用方）。
    pub fn from_ua_ip(user_agent: &'a str, ip: &'a str) -> Self {
        Self {
            user_agent,
            ip,
            accept_language: None,
            sec_ch_ua: None,
            sec_ch_ua_platform: None,
        }
    }
}

/// 生成强化设备指纹：SHA-256(ua | ip | accept_language | sec_ch_ua | sec_ch_ua_platform)，
/// 截断 16 字节 hex = 32 字符（A10 修复）。
///
/// 加入 Accept-Language / sec-ch-ua / sec-ch-ua-platform 维度，攻击者仅伪造 UA 或 IP
/// 无法复用指纹，必须同时匹配全部维度。各维度以 `\x1f`（Unit Separator）分隔，
/// 防止维度拼接歧义（如 ua="ab"+ip="c" 与 ua="a"+ip="bc" 在无分隔符时 hash 相同）。
///
/// # 参数
/// - `input`: 设备指纹输入维度（[`DeviceFingerprintInput`]）。
///
/// # 返回
/// 32 字符的十六进制字符串（SHA-256 前 16 字节）。
pub fn device_fingerprint_rich(input: &DeviceFingerprintInput<'_>) -> String {
    let mut hasher = Sha256::new();
    const SEP: u8 = 0x1f;
    hasher.update(input.user_agent.as_bytes());
    hasher.update([SEP]);
    hasher.update(input.ip.as_bytes());
    hasher.update([SEP]);
    match input.accept_language {
        Some(v) => hasher.update(v.as_bytes()),
        None => hasher.update([0x00]),
    }
    hasher.update([SEP]);
    match input.sec_ch_ua {
        Some(v) => hasher.update(v.as_bytes()),
        None => hasher.update([0x00]),
    }
    hasher.update([SEP]);
    match input.sec_ch_ua_platform {
        Some(v) => hasher.update(v.as_bytes()),
        None => hasher.update([0x00]),
    }
    let result = hasher.finalize();
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
    // A10: device_fingerprint_rich 强化指纹测试
    // ------------------------------------------------------------------------

    #[test]
    fn a10_rich_fingerprint_deterministic() {
        let input = DeviceFingerprintInput::new(
            "Mozilla/5.0 Chrome",
            "192.168.1.1",
            Some("zh-CN,zh;q=0.9"),
            Some("\"Chromium\";v=\"120\""),
            Some("\"Windows\""),
        );
        let fp1 = device_fingerprint_rich(&input);
        let fp2 = device_fingerprint_rich(&input);
        assert_eq!(fp1, fp2, "相同输入应生成相同指纹");
    }

    #[test]
    fn a10_rich_fingerprint_length_is_32() {
        let input = DeviceFingerprintInput::new("UA", "IP", None, None, None);
        let fp = device_fingerprint_rich(&input);
        assert_eq!(fp.len(), 32, "强化指纹应为 32 字符（16 字节 hex）");
    }

    /// A10 核心：伪造任意单一维度仍触发指纹变化（防止部分 header 伪造绕过）。
    #[test]
    fn a10_rich_fingerprint_spoofing_partial_dimensions_detected() {
        let base = DeviceFingerprintInput::new(
            "Mozilla/5.0 Chrome",
            "192.168.1.1",
            Some("zh-CN,zh;q=0.9"),
            Some("\"Chromium\";v=\"120\""),
            Some("\"Windows\""),
        );
        let base_fp = device_fingerprint_rich(&base);

        // 仅伪造 UA
        let spoof_ua = DeviceFingerprintInput::new(
            "Mozilla/5.0 Firefox",
            "192.168.1.1",
            Some("zh-CN,zh;q=0.9"),
            Some("\"Chromium\";v=\"120\""),
            Some("\"Windows\""),
        );
        assert_ne!(
            device_fingerprint_rich(&spoof_ua),
            base_fp,
            "伪造 UA 应改变指纹"
        );

        // 仅伪造 IP
        let spoof_ip = DeviceFingerprintInput::new(
            "Mozilla/5.0 Chrome",
            "10.0.0.1",
            Some("zh-CN,zh;q=0.9"),
            Some("\"Chromium\";v=\"120\""),
            Some("\"Windows\""),
        );
        assert_ne!(
            device_fingerprint_rich(&spoof_ip),
            base_fp,
            "伪造 IP 应改变指纹"
        );

        // 仅伪造 Accept-Language
        let spoof_al = DeviceFingerprintInput::new(
            "Mozilla/5.0 Chrome",
            "192.168.1.1",
            Some("en-US,en;q=0.9"),
            Some("\"Chromium\";v=\"120\""),
            Some("\"Windows\""),
        );
        assert_ne!(
            device_fingerprint_rich(&spoof_al),
            base_fp,
            "伪造 Accept-Language 应改变指纹"
        );

        // 仅伪造 sec-ch-ua
        let spoof_chua = DeviceFingerprintInput::new(
            "Mozilla/5.0 Chrome",
            "192.168.1.1",
            Some("zh-CN,zh;q=0.9"),
            Some("\"Firefox\";v=\"121\""),
            Some("\"Windows\""),
        );
        assert_ne!(
            device_fingerprint_rich(&spoof_chua),
            base_fp,
            "伪造 sec-ch-ua 应改变指纹"
        );

        // 仅伪造 sec-ch-ua-platform
        let spoof_plat = DeviceFingerprintInput::new(
            "Mozilla/5.0 Chrome",
            "192.168.1.1",
            Some("zh-CN,zh;q=0.9"),
            Some("\"Chromium\";v=\"120\""),
            Some("\"macOS\""),
        );
        assert_ne!(
            device_fingerprint_rich(&spoof_plat),
            base_fp,
            "伪造 sec-ch-ua-platform 应改变指纹"
        );
    }

    /// A10: None 与 Some("") 应产生不同指纹（防止攻击者用空串绕过 None 维度）。
    #[test]
    fn a10_rich_fingerprint_none_vs_some_empty_differ() {
        let with_none = DeviceFingerprintInput::new("UA", "IP", None, None, None);
        let with_empty = DeviceFingerprintInput::new("UA", "IP", Some(""), Some(""), Some(""));
        assert_ne!(
            device_fingerprint_rich(&with_none),
            device_fingerprint_rich(&with_empty),
            "None 与 Some(\"\") 应产生不同指纹（哨兵字节区分）"
        );
    }

    /// A10: from_ua_ip 构造等价于显式 None 构造。
    #[test]
    fn a10_rich_fingerprint_from_ua_ip_equivalent_to_none() {
        let input1 = DeviceFingerprintInput::from_ua_ip("UA", "IP");
        let input2 = DeviceFingerprintInput::new("UA", "IP", None, None, None);
        assert_eq!(
            device_fingerprint_rich(&input1),
            device_fingerprint_rich(&input2),
            "from_ua_ip 应等价于显式 None 构造"
        );
    }

    /// A10: 维度拼接歧义防护（ua="ab"+ip="c" 与 ua="a"+ip="bc" 应产生不同指纹）。
    #[test]
    fn a10_rich_fingerprint_delimiter_prevents_concat_ambiguity() {
        let ambiguous1 = DeviceFingerprintInput::from_ua_ip("ab", "c");
        let ambiguous2 = DeviceFingerprintInput::from_ua_ip("a", "bc");
        assert_ne!(
            device_fingerprint_rich(&ambiguous1),
            device_fingerprint_rich(&ambiguous2),
            "分隔符应防止维度拼接歧义"
        );
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
