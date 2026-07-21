//! Copyright (c) 2026 Kirky.X. All rights reserved.
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

    /// 注入 `GarrisonListenerManager`，启用 TempCredentialConsumed 事件广播
    ///
    ///
    /// 注入后 `consume` 成功消费（value 为 Some）时广播 `GarrisonEvent::TempCredentialConsumed`。
    /// 未注入时为 no-op（向后兼容 0.4.1）。需启用 `listener` feature。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<GarrisonListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 签发临时凭据。
    ///
    /// 生成 key 格式为 `garrison:temp:<prefix>:<random>`，其中 `<random>` 为
    /// 64 字符随机 hex 字符串。value 原样存储传入的 `value`，TTL 为 `ttl_seconds` 秒。
    ///
    /// # 参数
    /// - `prefix`: 业务场景前缀（不可包含 `:`）。
    /// - `value`: 凭证载荷（允许空字符串）。
    /// - `ttl_seconds`: 过期秒数（必须 > 0）。
    ///
    /// # 错误
    /// - `GarrisonError::InvalidParam`: `prefix` 包含 `:` 或 `ttl_seconds <= 0`。
    pub async fn issue(
        &self,
        prefix: &str,
        value: &str,
        ttl_seconds: i64,
    ) -> GarrisonResult<String> {
        if prefix.contains(':') {
            return Err(GarrisonError::InvalidParam(
                "prefix 不可包含 ':'".to_string(),
            ));
        }
        if ttl_seconds <= 0 {
            return Err(GarrisonError::InvalidParam(
                "ttl_seconds 必须大于 0".to_string(),
            ));
        }
        // 拼接两个 UUID v4 simple（各 32 hex = 64 字符）
        let random = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let key = format!("garrison:temp:{}:{}", prefix, random);
        self.dao.set(&key, value, ttl_seconds as u64).await?;
        Ok(key)
    }

    /// 读取临时凭据。
    ///
    /// 读取后不删除凭据（与 [`consume`](Self::consume) 区分）。
    ///
    /// # 返回
    /// - `Ok(Some(value))`: 凭据存在。
    /// - `Ok(None)`: 凭据不存在或已过期。
    pub async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        self.dao.get(key).await
    }

    /// 撤销临时凭据。
    ///
    /// 从 dao 中删除指定凭据。即使凭据不存在也返回 `Ok(())`（幂等语义）。
    pub async fn revoke(&self, key: &str) -> GarrisonResult<()> {
        // delete 是幂等的：不存在的 key 删除返回 Ok(())
        self.dao.delete(key).await
    }

    /// 消费临时凭据。
    ///
    /// 原子地读取并删除凭据（调用 `GarrisonDao::get_and_delete`），消除 TOCTOU 竞态，
    /// 保证一次性使用语义（vuln-0005 修复：原 `get + delete` 两步操作存在 double-spend 风险）。
    ///
    /// v0.4.2 扩展：成功消费（value 为 Some）时若注入了 `listener_manager`，
    /// 广播 `GarrisonEvent::TempCredentialConsumed`。
    ///
    /// # 返回
    /// - `Ok(Some(value))`: 凭据存在且已被消费（删除）。
    /// - `Ok(None)`: 凭据不存在或已过期。
    pub async fn consume(&self, key: &str) -> GarrisonResult<Option<String>> {
        // 原子 get_and_delete：消除 get 与 delete 之间的 TOCTOU 竞态窗口，
        // 保证并发调用同一 key 时仅一个返回 Some（防 double-spend）。
        let value = self.dao.get_and_delete(key).await?;
        // 广播 TempCredentialConsumed 事件（仅 value 为 Some 时）
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
