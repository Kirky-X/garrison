//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Session 安全监听器（IP 变更检测）。
//!
//! 在 login 时记录初始 IP，在后续访问时检测 IP 是否跨网段变更，
//! 用于识别潜在的 Session 劫持行为。
//!
//! ## 存储格式
//!
//! - `session:ip:{token}` → 登录 IP 字符串（TTL: 86400 秒 / 24 小时）
//!
//! ## 网段比较
//!
//! 仅支持 IPv4 /24 网段比较（取前 3 段 `A.B.C` 作为网段标识）。
//! IPv6 与无效 IP 格式不参与比较（返回 `None`，不阻断主流程）。

use crate::constants::DaoKeyPrefix;
use crate::dao::BulwarkDao;
use crate::error::BulwarkResult;
use std::sync::Arc;

/// IP 记录的默认 TTL（24 小时，单位：秒）。
const IP_RECORD_TTL: u64 = 86400;

/// Session 安全监听器，用于检测 IP 变更以识别潜在的 Session 劫持。
///
/// 通过 `BulwarkDao` 存储 token 登录时的初始 IP，后续访问时比较当前 IP
/// 与初始 IP 的网段（IPv4 /24），跨网段时返回告警信息并记录 `tracing::warn!`。
///
/// # 使用
///
/// ```ignore
/// use bulwark::session::security_listener::SessionSecurityListener;
/// use std::sync::Arc;
///
/// let listener = SessionSecurityListener::new(dao);
/// listener.record_login_ip("T1", "1001", "192.168.1.100").await?;
/// if let Some(warning) = listener.check_ip_change("T1", "192.168.2.50").await? {
///     // IP 跨网段变更，潜在劫持风险
/// }
/// ```
pub struct SessionSecurityListener {
    /// DAO 引用（oxcache / dbnexus）。
    dao: Arc<dyn BulwarkDao>,
}

impl SessionSecurityListener {
    /// 创建安全监听器实例。
    ///
    /// # 参数
    /// - `dao`: DAO 引用（oxcache / dbnexus）。
    ///
    /// # 返回
    /// 新建的 `SessionSecurityListener` 实例。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }

    /// 记录 token 登录时的初始 IP。
    ///
    /// 在 login 流程中调用，将 token 与登录 IP 关联存储。
    /// 后续 `check_ip_change` 通过此记录检测 IP 变更。
    ///
    /// # 参数
    /// - `token`: token 字符串。
    /// - `login_id`: 登录主体标识（用于日志追踪）。
    /// - `ip`: 登录时的客户端 IP。
    ///
    /// # 存储
    /// - key: `session:ip:{token}`
    /// - value: IP 字符串
    /// - TTL: 86400 秒（24 小时）
    ///
    /// # 错误
    /// - DAO 写入失败：透传 `BulwarkError`。
    pub async fn record_login_ip(
        &self,
        token: &str,
        login_id: &str,
        ip: &str,
    ) -> BulwarkResult<()> {
        let key = format!("{}ip:{}", DaoKeyPrefix::Session, token);
        self.dao.set(&key, ip, IP_RECORD_TTL).await?;
        tracing::info!(
            "记录登录 IP (token={}, login_id={}, ip={})",
            token,
            login_id,
            ip
        );
        Ok(())
    }

    /// 检测当前 IP 是否与登录时记录的初始 IP 跨网段。
    ///
    /// 在请求鉴权时调用，比较当前 IP 与 `record_login_ip` 记录的初始 IP 的网段：
    /// - IPv4 取前 3 段（/24）作为网段标识
    /// - 同网段返回 `Ok(None)`（不告警）
    /// - 跨网段返回 `Ok(Some(warning))`，同时记录 `tracing::warn!`
    /// - 无记录或 IP 格式无效返回 `Ok(None)`（不阻断主流程）
    ///
    /// # 参数
    /// - `token`: token 字符串。
    /// - `current_ip`: 当前请求的客户端 IP。
    ///
    /// # 返回
    /// - `Ok(None)`: 无记录、同网段、或 IP 格式无效（IPv6 / 非法字符串）。
    /// - `Ok(Some(warning))`: 跨网段，warning 为告警消息。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn check_ip_change(
        &self,
        token: &str,
        current_ip: &str,
    ) -> BulwarkResult<Option<String>> {
        let key = format!("{}ip:{}", DaoKeyPrefix::Session, token);
        let recorded_ip = match self.dao.get(&key).await? {
            Some(ip) => ip,
            None => return Ok(None), // 首次访问无记录，不告警
        };

        match (
            extract_ipv4_subnet(&recorded_ip),
            extract_ipv4_subnet(current_ip),
        ) {
            (Some(recorded_subnet), Some(current_subnet)) => {
                if recorded_subnet == current_subnet {
                    Ok(None)
                } else {
                    let warning = format!(
                        "IP 网段变更检测：token={} 初始 IP={} 当前 IP={}（网段 {} -> {}）",
                        token, recorded_ip, current_ip, recorded_subnet, current_subnet
                    );
                    tracing::warn!("{}", warning);
                    Ok(Some(warning))
                }
            },
            // IPv6 或无效 IP 格式，不阻断主流程
            (None, _) | (_, None) => Ok(None),
        }
    }
}

/// 提取 IPv4 地址的 /24 网段标识（前 3 段）。
///
/// # 参数
/// - `ip`: IPv4 字符串（格式 `A.B.C.D`）。
///
/// # 返回
/// - `Some("A.B.C")`: 有效 IPv4，返回前 3 段。
/// - `None`: 非 IPv4 格式（IPv6、无效字符串、段数不为 4、某段非 0-255 数字等）。
fn extract_ipv4_subnet(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for part in &parts {
        if part.is_empty() {
            return None;
        }
        // 验证每段是 0-255 的有效数字（u8 parse 自动拒绝 >255 与非数字）
        part.parse::<u8>().ok()?;
    }
    Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    /// 辅助函数：创建带 MockDao 的 SessionSecurityListener。
    fn make_listener() -> (Arc<MockDao>, SessionSecurityListener) {
        let dao = Arc::new(MockDao::new());
        let listener = SessionSecurityListener::new(dao.clone());
        (dao, listener)
    }

    // ------------------------------------------------------------------------
    // record_login_ip + check_ip_change 行为验证
    // ------------------------------------------------------------------------

    /// 验证 record_login_ip 后 check_ip_change 同 IP 返回 None。
    #[tokio::test]
    async fn same_ip_returns_none() {
        let (_dao, listener) = make_listener();
        listener
            .record_login_ip("T1", "1001", "192.168.1.100")
            .await
            .unwrap();
        let result = listener
            .check_ip_change("T1", "192.168.1.100")
            .await
            .unwrap();
        assert!(result.is_none(), "同 IP 应返回 None");
    }

    /// 验证同网段不同 IP 返回 None（IPv4 /24 比较）。
    #[tokio::test]
    async fn same_subnet_returns_none() {
        let (_dao, listener) = make_listener();
        listener
            .record_login_ip("T1", "1001", "192.168.1.100")
            .await
            .unwrap();
        let result = listener
            .check_ip_change("T1", "192.168.1.200")
            .await
            .unwrap();
        assert!(result.is_none(), "同网段不同 IP 应返回 None");
    }

    /// 验证跨网段返回 Some(warning)。
    #[tokio::test]
    async fn cross_subnet_returns_warning() {
        let (_dao, listener) = make_listener();
        listener
            .record_login_ip("T1", "1001", "192.168.1.100")
            .await
            .unwrap();
        let result = listener
            .check_ip_change("T1", "192.168.2.100")
            .await
            .unwrap();
        assert!(result.is_some(), "跨网段应返回 Some(warning)");
        let warning = result.unwrap();
        assert!(warning.contains("192.168.1.100"), "告警应包含初始 IP");
        assert!(warning.contains("192.168.2.100"), "告警应包含当前 IP");
        assert!(
            warning.contains("192.168.1") && warning.contains("192.168.2"),
            "告警应包含网段标识"
        );
    }

    // ------------------------------------------------------------------------
    // 边界场景
    // ------------------------------------------------------------------------

    /// 验证无记录时 check_ip_change 返回 None（首次访问不告警）。
    #[tokio::test]
    async fn no_record_returns_none() {
        let (_dao, listener) = make_listener();
        let result = listener
            .check_ip_change("nonexistent", "192.168.1.100")
            .await
            .unwrap();
        assert!(result.is_none(), "无记录应返回 None");
    }

    /// 验证无效 IP 格式返回 None（不阻断主流程）。
    #[tokio::test]
    async fn invalid_ip_returns_none() {
        let (_dao, listener) = make_listener();
        listener
            .record_login_ip("T1", "1001", "192.168.1.100")
            .await
            .unwrap();

        // 当前 IP 无效字符串
        let result = listener.check_ip_change("T1", "invalid-ip").await.unwrap();
        assert!(result.is_none(), "无效当前 IP 应返回 None");

        // 当前 IP 是 IPv6（暂不支持）
        let result = listener.check_ip_change("T1", "2001:db8::1").await.unwrap();
        assert!(result.is_none(), "IPv6 应返回 None");

        // 当前 IP 段数不足
        let result = listener.check_ip_change("T1", "192.168.1").await.unwrap();
        assert!(result.is_none(), "段数不足的 IP 应返回 None");

        // 当前 IP 某段 > 255
        let result = listener
            .check_ip_change("T1", "192.168.1.300")
            .await
            .unwrap();
        assert!(result.is_none(), "某段 > 255 的 IP 应返回 None");
    }

    /// 验证 record_login_ip 实际写入 DAO 的 key 格式与 value。
    #[tokio::test]
    async fn record_login_ip_writes_correct_key_and_value() {
        let (dao, listener) = make_listener();
        listener
            .record_login_ip("T1", "1001", "192.168.1.100")
            .await
            .unwrap();

        // spec: DAO key 为 session:ip:{token}，value 为 ip 字符串
        let stored = dao.get("session:ip:T1").await.unwrap();
        assert_eq!(
            stored,
            Some("192.168.1.100".to_string()),
            "DAO 应存储 session:ip:T1 -> 192.168.1.100"
        );
    }

    // ------------------------------------------------------------------------
    // extract_ipv4_subnet 单元测试
    // ------------------------------------------------------------------------

    /// 验证 extract_ipv4_subnet 对有效 IPv4 返回前 3 段。
    #[test]
    fn extract_ipv4_subnet_valid_ipv4() {
        assert_eq!(
            extract_ipv4_subnet("192.168.1.100"),
            Some("192.168.1".to_string())
        );
        assert_eq!(extract_ipv4_subnet("10.0.0.1"), Some("10.0.0".to_string()));
        assert_eq!(
            extract_ipv4_subnet("255.255.255.255"),
            Some("255.255.255".to_string())
        );
        assert_eq!(extract_ipv4_subnet("0.0.0.0"), Some("0.0.0".to_string()));
    }

    /// 验证 extract_ipv4_subnet 对 IPv6 / 无效格式返回 None。
    #[test]
    fn extract_ipv4_subnet_invalid_returns_none() {
        assert_eq!(extract_ipv4_subnet("2001:db8::1"), None, "IPv6 应返回 None");
        assert_eq!(
            extract_ipv4_subnet("invalid"),
            None,
            "非 IP 字符串应返回 None"
        );
        assert_eq!(extract_ipv4_subnet(""), None, "空字符串应返回 None");
        assert_eq!(
            extract_ipv4_subnet("192.168.1"),
            None,
            "段数不足应返回 None"
        );
        assert_eq!(
            extract_ipv4_subnet("192.168.1.1.1"),
            None,
            "段数过多应返回 None"
        );
        assert_eq!(
            extract_ipv4_subnet("192.168.1.300"),
            None,
            "某段 > 255 应返回 None"
        );
        assert_eq!(
            extract_ipv4_subnet("192.168.1.abc"),
            None,
            "非数字段应返回 None"
        );
        assert_eq!(extract_ipv4_subnet("192.168..1"), None, "空段应返回 None");
    }
}
