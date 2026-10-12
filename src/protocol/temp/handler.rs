//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! `TempCredentialHandler` 实现。
//!
//! 包含临时凭据签发/读取/撤销/消费逻辑。
//!
//! 仅在启用 `protocol-temp` 特性时编译。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
#[cfg(feature = "listener")]
use crate::listener::{GarrisonEvent, GarrisonListenerManager};
use std::sync::Arc;
use uuid::Uuid;

use super::TempCredentialHandler;

impl TempCredentialHandler {
    /// 创建新的临时凭证处理器。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self {
            dao,
            #[cfg(feature = "listener")]
            listener_manager: None,
        }
    }

    /// 注入 `GarrisonListenerManager`：`consume` 成功消费（value 为 Some）时广播
    /// `GarrisonEvent::TempCredentialConsumed`（未注入不广播；需 `listener` feature）。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<GarrisonListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 签发临时凭据：key 为 `garrison:temp:<prefix>:<random>`（`<random>` 为 64 字符
    /// 随机 hex），value 原样存储，TTL = `ttl_seconds` 秒。`prefix` 含 `:` 或
    /// `ttl_seconds <= 0` 返回 `InvalidParam`。
    pub async fn issue(
        &self,
        prefix: &str,
        value: &str,
        ttl_seconds: i64,
    ) -> GarrisonResult<String> {
        if prefix.contains(':') {
            return Err(GarrisonError::InvalidParam(
                "temp-prefix-colon::".to_string(),
            ));
        }
        if ttl_seconds <= 0 {
            return Err(GarrisonError::InvalidParam(
                "temp-ttl-invalid::".to_string(),
            ));
        }
        // 拼接两个 UUID v4 simple（各 32 hex = 64 字符）
        let random = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let key = format!("garrison:temp:{}:{}", prefix, random);
        self.dao.set(&key, value, ttl_seconds as u64).await?;
        Ok(key)
    }

    /// 读取临时凭据（读取后不删除，与 [`consume`](Self::consume) 区分）：
    /// 凭据不存在或已过期返回 `None`。
    pub async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        self.dao.get(key).await
    }

    /// 撤销临时凭据：从 dao 删除指定凭据；凭据不存在也返回 `Ok(())`（幂等）。
    pub async fn revoke(&self, key: &str) -> GarrisonResult<()> {
        self.dao.delete(key).await
    }

    /// 消费临时凭据：`get_and_delete` 原子读删，消除 TOCTOU 竞态、保证一次性
    /// 使用（`get + delete` 两步存在 double-spend 风险）。成功消费（value 为 Some）
    /// 且注入 listener 时广播 `TempCredentialConsumed`（需 `listener` feature）。
    ///
    /// `Ok(Some)` 表示凭据存在且已被消费（删除）；`Ok(None)` 表示不存在或已过期。
    pub async fn consume(&self, key: &str) -> GarrisonResult<Option<String>> {
        let value = self.dao.get_and_delete(key).await?;
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            if let Some(ref v) = value {
                lm.broadcast(&GarrisonEvent::TempCredentialConsumed {
                    key: key.to_string(),
                    value: v.clone(),
                    request_context: None,
                })
                .await;
            }
        }
        Ok(value)
    }
}
