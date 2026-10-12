// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 会话层测试 mock 实现。
//!
//! 仅 `cfg(test)` 下编译，提供记录回调调用、可选返回错误的 `MockExpiryListener` 供测试复用。

use super::SessionExpiryListener;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

/// Mock 过期监听器：记录所有回调调用，可选返回错误。
pub struct MockExpiryListener {
    calls: Arc<Mutex<Vec<(String, String)>>>,
    fail: bool,
}

impl MockExpiryListener {
    #[allow(clippy::type_complexity)]
    pub fn new() -> (Self, Arc<Mutex<Vec<(String, String)>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                calls: calls.clone(),
                fail: false,
            },
            calls,
        )
    }

    pub fn new_failing() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            fail: true,
        }
    }
}

#[async_trait]
impl SessionExpiryListener for MockExpiryListener {
    async fn on_session_expired(&self, login_id: &str, token: &str) -> GarrisonResult<()> {
        self.calls
            .lock()
            .unwrap()
            .push((login_id.to_string(), token.to_string()));
        if self.fail {
            return Err(GarrisonError::Session(
                "session-mock-callback::".to_string(),
            ));
        }
        Ok(())
    }
}
