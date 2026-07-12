//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 上下文层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockResponse`（模拟 `BulwarkResponse` trait），
//! 供 `context::tests` 默认方法行为测试复用。

use crate::context::BulwarkResponse;
use crate::error::BulwarkResult;
use std::collections::HashMap;

/// Mock 响应实现，用于测试 BulwarkResponse trait 的默认方法。
pub struct MockResponse {
    /// cookie 存储（供测试断言直接访问）。
    pub cookies: HashMap<String, String>,
    /// header 存储（供测试断言直接访问）。
    pub headers: HashMap<String, String>,
    /// status code（供测试断言直接访问）。
    pub status: Option<u16>,
}

impl MockResponse {
    /// 创建空的 mock 响应（无 cookie/header/status）。
    pub fn new() -> Self {
        Self {
            cookies: HashMap::new(),
            headers: HashMap::new(),
            status: None,
        }
    }
}

impl BulwarkResponse for MockResponse {
    fn set_status(&mut self, code: u16) -> BulwarkResult<()> {
        self.status = Some(code);
        Ok(())
    }

    fn set_header(&mut self, name: &str, value: &str) -> BulwarkResult<()> {
        self.headers.insert(name.to_string(), value.to_string());
        Ok(())
    }

    fn set_cookie_with_config(
        &mut self,
        name: &str,
        value: &str,
        _config: &crate::config::BulwarkConfig,
    ) -> BulwarkResult<()> {
        self.cookies.insert(name.to_string(), value.to_string());
        Ok(())
    }
}
