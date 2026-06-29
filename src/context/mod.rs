//! 上下文模块，提供请求 / 响应 / 存储上下文抽象。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的上下文抽象层，
//! 通过 trait 隔离 Web 框架差异，实现框架无关的鉴权逻辑。

use crate::error::BulwarkResult;

/// 上下文 trait，提供请求 / 响应 / 存储的统一访问入口。
///
/// [借鉴 Sa-Token] 对应 `SaTokenContext`，
/// 各 Web 框架适配需实现此 trait。
pub trait BulwarkContext {
    /// 获取当前请求对象。
    fn request(&self) -> BulwarkResult<Box<dyn BulwarkRequest>>;

    /// 获取当前响应对象。
    fn response(&self) -> BulwarkResult<Box<dyn BulwarkResponse>>;

    /// 获取存储对象。
    fn storage(&self) -> BulwarkResult<Box<dyn BulwarkStorage>>;
}

/// 请求抽象 trait，提供 HTTP 请求数据访问。
///
/// [借鉴 Sa-Token] 对应 `SaTokenRequest`。
pub trait BulwarkRequest {
    /// 获取请求路径。
    fn path(&self) -> BulwarkResult<String> {
        todo!()
    }

    /// 获取请求方法（GET / POST 等）。
    fn method(&self) -> BulwarkResult<String> {
        todo!()
    }

    /// 获取请求头。
    ///
    /// # 参数
    /// - `name`: 头部字段名。
    fn header(&self, name: &str) -> BulwarkResult<Option<String>> {
        todo!()
    }

    /// 获取 Cookie 值。
    ///
    /// # 参数
    /// - `name`: Cookie 名称。
    fn cookie(&self, name: &str) -> BulwarkResult<Option<String>> {
        todo!()
    }
}

/// 响应抽象 trait，提供 HTTP 响应数据写入。
///
/// [借鉴 Sa-Token] 对应 `SaTokenResponse`。
pub trait BulwarkResponse {
    /// 设置响应头。
    ///
    /// # 参数
    /// - `name`: 头部字段名。
    /// - `value`: 头部字段值。
    fn set_header(&mut self, name: &str, value: &str) -> BulwarkResult<()> {
        todo!()
    }

    /// 设置响应 Cookie。
    ///
    /// # 参数
    /// - `name`: Cookie 名称。
    /// - `value`: Cookie 值。
    fn set_cookie(&mut self, name: &str, value: &str) -> BulwarkResult<()> {
        todo!()
    }
}

/// 存储抽象 trait，提供请求级临时数据存储。
///
/// [借鉴 Sa-Token] 对应 `SaTokenStorage`，
/// 用于在单次请求范围内传递数据。
pub trait BulwarkStorage {
    /// 存储键值对。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    fn set(&mut self, key: &str, value: &str) -> BulwarkResult<()> {
        todo!()
    }

    /// 获取存储值。
    ///
    /// # 参数
    /// - `key`: 存储键。
    fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        todo!()
    }

    /// 删除存储值。
    ///
    /// # 参数
    /// - `key`: 存储键。
    fn delete(&mut self, key: &str) -> BulwarkResult<()> {
        todo!()
    }
}
