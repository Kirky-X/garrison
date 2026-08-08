//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 降级策略适配器。
//!
//! 包装 limiteron `FallbackStrategy`，为 Garrison `BackendRemote` 提供
//! 后端故障时的降级行为控制。
//!
//! # 降级策略
//!
//! - **FailOpen**：后端故障时允许所有请求（适用于可用性优先场景）
//! - **FailClosed**：后端故障时拒绝所有请求（适用于安全性优先场景）
//! - **Degraded**：后端故障时使用缓存的降级响应（需配置 L2 缓存）
//!
//! # 与熔断器的协作
//!
//! 熔断器（`CircuitBreakerWrapper`）检测后端故障并打开/关闭电路。
//! 降级策略（`FallbackPolicy`）决定电路打开时如何处理被拒绝的请求：
//! - 熔断器打开 + FailOpen → 放行（返回默认允许）
//! - 熔断器打开 + FailClosed → 拒绝（返回错误）
//!
//! # 设计
//!
//! `FallbackPolicy` 是轻量级适配器，不包含 limiteron `FallbackManager` 的完整功能
//! （L2 缓存、重试预算等），仅提供策略判断。完整的降级管理可通过直接使用
//! limiteron `FallbackManager` 实现。

use limiteron::fallback::FallbackStrategy;

/// 降级策略包装器。
///
/// 将 limiteron `FallbackStrategy` 映射为 Garrison 可用的降级决策。
#[derive(Clone)]
pub struct FallbackPolicy {
    strategy: FallbackStrategy,
}

/// 降级决策结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackDecision {
    /// 允许请求通过（FailOpen 模式）。
    Allow,
    /// 拒绝请求（FailClosed 模式）。
    Deny,
    /// 使用降级响应（Degraded 模式，调用方提供缓存值）。
    UseDegradedResponse,
}

impl FallbackPolicy {
    /// 创建降级策略。
    pub fn new(strategy: FallbackStrategy) -> Self {
        Self { strategy }
    }

    /// 创建 FailOpen 策略（后端故障时放行）。
    pub fn fail_open() -> Self {
        Self::new(FallbackStrategy::FailOpen)
    }

    /// 创建 FailClosed 策略（后端故障时拒绝）。
    pub fn fail_closed() -> Self {
        Self::new(FallbackStrategy::FailClosed)
    }

    /// 创建 Degraded 策略（后端故障时使用降级响应）。
    pub fn degraded() -> Self {
        Self::new(FallbackStrategy::Degraded)
    }

    /// 当后端故障时，获取降级决策。
    pub fn on_failure(&self) -> FallbackDecision {
        match &self.strategy {
            FallbackStrategy::FailOpen => FallbackDecision::Allow,
            FallbackStrategy::FailClosed => FallbackDecision::Deny,
            FallbackStrategy::Degraded => FallbackDecision::UseDegradedResponse,
        }
    }

    /// 获取底层策略引用。
    pub fn strategy(&self) -> &FallbackStrategy {
        &self.strategy
    }
}

impl std::fmt::Debug for FallbackPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackPolicy")
            .field("strategy", &self.strategy)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FailOpen 策略在后端故障时放行。
    #[test]
    fn fail_open_allows_on_failure() {
        let policy = FallbackPolicy::fail_open();
        assert_eq!(policy.on_failure(), FallbackDecision::Allow);
    }

    /// FailClosed 策略在后端故障时拒绝。
    #[test]
    fn fail_closed_denies_on_failure() {
        let policy = FallbackPolicy::fail_closed();
        assert_eq!(policy.on_failure(), FallbackDecision::Deny);
    }

    /// Degraded 策略在后端故障时使用降级响应。
    #[test]
    fn degraded_uses_fallback_response() {
        let policy = FallbackPolicy::degraded();
        assert_eq!(policy.on_failure(), FallbackDecision::UseDegradedResponse);
    }

    /// Debug 输出包含策略信息。
    #[test]
    fn debug_contains_strategy() {
        let policy = FallbackPolicy::fail_open();
        let debug = format!("{:?}", policy);
        assert!(debug.contains("FallbackPolicy"));
        assert!(debug.contains("FailOpen"));
    }

    /// Clone 正常工作。
    #[test]
    fn clone_preserves_strategy() {
        let policy = FallbackPolicy::fail_closed();
        let cloned = policy.clone();
        assert_eq!(cloned.on_failure(), FallbackDecision::Deny);
    }
}
