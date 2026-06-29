//! 策略模块，提供鉴权策略与防火墙策略。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的策略模式设计，
//! 允许通过策略对象定制鉴权行为。

use crate::error::BulwarkResult;

/// 鉴权策略，定义可定制的鉴权行为集合。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 `SaStrategy`，
/// 提供 Token 生成、会话查询等可替换逻辑。
pub struct BulwarkStrategy {
    /// 占位字段。
    _inner: (),
}

impl BulwarkStrategy {
    /// 创建新的策略实例。
    pub fn new() -> Self {
        Self { _inner: () }
    }

    /// 生成 Token 字符串。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    pub fn create_token(&self, login_id: i64) -> BulwarkResult<String> {
        todo!()
    }

    /// 根据 Token 解析登录主体标识。
    ///
    /// # 参数
    /// - `token`: Token 字符串。
    pub fn parse_login_id(&self, token: &str) -> BulwarkResult<Option<i64>> {
        todo!()
    }
}

impl Default for BulwarkStrategy {
    fn default() -> Self {
        Self::new()
    }
}

/// 防火墙策略，定义请求过滤与黑名单逻辑。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的防火墙能力，
/// 提供黑名单 / 白名单 / 速率限制等安全策略。
pub struct BulwarkFirewallStrategy {
    /// 占位字段。
    _inner: (),
}

impl BulwarkFirewallStrategy {
    /// 创建新的防火墙策略实例。
    pub fn new() -> Self {
        Self { _inner: () }
    }

    /// 检查请求是否被允许通过。
    ///
    /// # 参数
    /// - `path`: 请求路径。
    pub fn allow_request(&self, path: &str) -> BulwarkResult<bool> {
        todo!()
    }
}

impl Default for BulwarkFirewallStrategy {
    fn default() -> Self {
        Self::new()
    }
}
