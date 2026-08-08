//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 熔断器适配器。
//!
//! 包装 limiteron `CircuitBreaker`，为 Garrison `BackendRemote` 提供
//! 远程调用熔断保护。当远程 Auth Server 连续失败达到阈值时，
//! 熔断器打开并快速拒绝后续请求（不再发起 HTTP 调用），
//! 超时后自动进入半开状态探测恢复。
//!
//! # 设计
//!
//! `CircuitBreakerWrapper` 提供 `execute` 方法，将 Garrison 的异步操作
//! 包裹在熔断器逻辑中：
//! - 操作成功 → `on_success`（重置/递增成功计数）
//! - 操作失败 → `on_failure`（通过 `GarrisonErrorClassifier` 判断是否计入失败）
//! - 熔断器打开 → 立即返回 `GarrisonError::CircuitOpen`
//!
//! # 错误分类
//!
//! `GarrisonErrorClassifier` 将以下错误视为失败（计入熔断计数）：
//! - `Network` 错误（连接超时、DNS 失败等）
//! - 其他非客户端错误（非 `InvalidParam`、`NotFound`）

use crate::error::{GarrisonError, GarrisonResult};
use limiteron::circuit::{CircuitBreaker, CircuitBreakerConfig, ErrorClassifier};
use limiteron::error::LimiteronError;
use std::sync::Arc;

/// Garrison 错误分类器，决定哪些错误应计入熔断器的失败计数。
///
/// # 分类规则
///
/// - `Network` 错误 → 失败（远程服务不可达，熔断器的核心场景）
/// - `Dao` 错误 → 失败（底层存储异常）
/// - `InvalidParam` / `NotFound` → 不计入（客户端错误，不应触发熔断）
/// - 其他 → 计入（保守策略）
#[derive(Debug)]
struct GarrisonErrorClassifier;

impl ErrorClassifier for GarrisonErrorClassifier {
    fn is_counted_as_failure(&self, error: &LimiteronError) -> bool {
        match error {
            // 存储/网络临时错误 → 算失败
            LimiteronError::StorageError(storage_err) => storage_err.is_transient(),
            // 限流/熔断 → 不算（保护机制本身，不应级联触发）
            LimiteronError::LimitError(_) | LimiteronError::CircuitBreakerError(_) => false,
            // 验证错误 → 不算（客户端问题）
            LimiteronError::ValidationError(_) => false,
            // 其他 → 算失败（保守策略）
            _ => true,
        }
    }
}

/// 将 `GarrisonError` 映射为 `LimiteronError`（供熔断器 `execute` 使用）。
///
/// 客户端错误（`InvalidParam`、`NotFound`、`NotLogin` 等）映射为 `ValidationError`
/// 以便 `GarrisonErrorClassifier` 不计入失败计数（避免客户端错误触发熔断）。
fn to_limiteron_error(e: GarrisonError) -> LimiteronError {
    match &e {
        GarrisonError::Network(msg) => {
            LimiteronError::StorageError(limiteron::error::StorageError::ConnectionError {
                msg: msg.clone(),
                source: None,
            })
        },
        GarrisonError::Dao(msg) => {
            LimiteronError::StorageError(limiteron::error::StorageError::QueryError {
                msg: msg.clone(),
                source: None,
            })
        },
        // 客户端错误 → ValidationError（不计入熔断失败计数）
        GarrisonError::InvalidParam(msg)
        | GarrisonError::NotLogin(msg)
        | GarrisonError::NotPermission(msg)
        | GarrisonError::NotRole(msg)
        | GarrisonError::InvalidToken(msg) => LimiteronError::ValidationError(msg.clone()),
        _ => LimiteronError::Other(format!("{}", e)),
    }
}

/// 将 `LimiteronError` 映射回 `GarrisonError`。
fn to_garrison_error(e: LimiteronError) -> GarrisonError {
    match &e {
        // 熔断器打开 → 远程服务不可达语义
        LimiteronError::CircuitBreakerError(msg) => {
            GarrisonError::Network(format!("circuit-open::{}", msg))
        },
        LimiteronError::StorageError(limiteron::error::StorageError::ConnectionError {
            msg,
            ..
        }) => GarrisonError::Network(msg.clone()),
        LimiteronError::LimitError(msg) => {
            GarrisonError::FirewallBlocked(format!("circuit-limited::{}", msg))
        },
        _ => GarrisonError::Internal(format!("circuit-breaker::{}", e)),
    }
}

/// 熔断器包装器，为 Garrison 远程调用提供熔断保护。
///
/// # 线程安全
///
/// 内部 `CircuitBreaker` 使用 `Arc<RwLock>` + `AtomicU64`，可安全跨线程共享。
/// `CircuitBreakerWrapper` 可直接放入 `Arc` 在多个 `BackendRemote` 实例间共享。
pub struct CircuitBreakerWrapper {
    inner: CircuitBreaker,
}

impl CircuitBreakerWrapper {
    /// 创建熔断器包装器。
    ///
    /// # 参数
    /// - `config`: 熔断器配置（failure_threshold、success_threshold、timeout 等）。
    pub fn new(config: CircuitBreakerConfig) -> Self {
        let config = config.error_classifier(Arc::new(GarrisonErrorClassifier));
        Self {
            inner: CircuitBreaker::new(config),
        }
    }

    /// 在熔断器保护下执行异步操作。
    ///
    /// - 熔断器关闭/半开 → 执行 `operation`，根据结果更新状态
    /// - 熔断器打开 → 立即返回 `GarrisonError::CircuitOpen`
    ///
    /// # 参数
    /// - `operation`: 要保护的异步操作
    pub async fn execute<F, Fut, T>(&self, operation: F) -> GarrisonResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = GarrisonResult<T>>,
    {
        self.inner
            .execute(|| async { operation().await.map_err(to_limiteron_error) })
            .await
            .map_err(to_garrison_error)
    }

    /// 查询熔断器是否打开。
    pub async fn is_open(&self) -> bool {
        self.inner.is_open().await
    }

    /// 查询熔断器当前状态。
    pub async fn state(&self) -> limiteron::error::CircuitState {
        self.inner.get_state().await
    }

    /// 重置熔断器到关闭状态。
    pub async fn reset(&self) {
        self.inner.reset().await;
    }

    /// 获取内部熔断器引用（用于高级用法，如获取统计信息）。
    pub fn inner(&self) -> &CircuitBreaker {
        &self.inner
    }
}

impl std::fmt::Debug for CircuitBreakerWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitBreakerWrapper")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use limiteron::circuit::CircuitBreakerConfig;
    use std::time::Duration;

    fn make_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig::new(3, 2, Duration::from_secs(60))
    }

    /// 初始状态为 Closed。
    #[tokio::test]
    async fn initial_state_closed() {
        let wrapper = CircuitBreakerWrapper::new(make_config());
        assert!(!wrapper.is_open().await);
    }

    /// 成功操作不触发熔断。
    #[tokio::test]
    async fn success_does_not_trip() {
        let wrapper = CircuitBreakerWrapper::new(make_config());
        let result = wrapper
            .execute(|| async { Ok::<_, GarrisonError>(42) })
            .await;
        assert_eq!(result.unwrap(), 42);
        assert!(!wrapper.is_open().await);
    }

    /// Network 错误计入失败计数，达到阈值触发熔断。
    #[tokio::test]
    async fn network_errors_trip_breaker() {
        let wrapper = CircuitBreakerWrapper::new(make_config());

        for _ in 0..3 {
            let _ = wrapper
                .execute(|| async {
                    Err::<(), _>(GarrisonError::Network("connection refused".into()))
                })
                .await;
        }

        assert!(wrapper.is_open().await, "3 次 Network 错误后应熔断");
    }

    /// 熔断器打开后，后续调用立即被拒绝。
    #[tokio::test]
    async fn open_breaker_rejects_immediately() {
        let wrapper = CircuitBreakerWrapper::new(make_config());

        // 触发熔断
        for _ in 0..3 {
            let _ = wrapper
                .execute(|| async { Err::<(), _>(GarrisonError::Network("timeout".into())) })
                .await;
        }
        assert!(wrapper.is_open().await);

        // 即使 operation 会成功，熔断器打开时也应被拒绝
        let result = wrapper
            .execute(|| async { Ok::<_, GarrisonError>(42) })
            .await;
        assert!(result.is_err(), "熔断器打开时应拒绝请求");
    }

    /// InvalidParam 错误不计入失败（客户端错误不应触发熔断）。
    #[tokio::test]
    async fn client_errors_not_counted() {
        let config = CircuitBreakerConfig::new(2, 1, Duration::from_secs(60));
        let wrapper = CircuitBreakerWrapper::new(config);

        for _ in 0..5 {
            let _ = wrapper
                .execute(|| async { Err::<(), _>(GarrisonError::InvalidParam("bad input".into())) })
                .await;
        }

        assert!(!wrapper.is_open().await, "客户端错误不应触发熔断");
    }

    /// reset 恢复熔断器。
    #[tokio::test]
    async fn reset_restores() {
        let wrapper = CircuitBreakerWrapper::new(make_config());

        for _ in 0..3 {
            let _ = wrapper
                .execute(|| async { Err::<(), _>(GarrisonError::Network("err".into())) })
                .await;
        }
        assert!(wrapper.is_open().await);

        wrapper.reset().await;
        assert!(!wrapper.is_open().await);
    }

    /// Debug trait 正常输出。
    #[test]
    fn debug_impl() {
        let wrapper = CircuitBreakerWrapper::new(make_config());
        let debug = format!("{:?}", wrapper);
        assert!(debug.contains("CircuitBreakerWrapper"));
    }
}
