//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 优先级队列适配器。
//!
//! 包装 limiteron `PriorityConfig` + `RequestPriority`，
//! 为 Garrison 防火墙策略提供过载时的优先级感知准入控制。
//!
//! # 设计
//!
//! 当 DDoS 等策略检测到过载（请求速率超过阈值的一定比例）时，
//! `PriorityAdmissionController` 根据请求优先级按比率放行：
//! - Critical：总是放行（如健康检查）
//! - High：高比率放行
//! - Normal：中等比率放行
//! - Low：低比率放行（后台任务等）
//!
//! # 与 limiteron 原生的区别
//!
//! limiteron 的 `priority` 模块提供 `RequestPriorityResolver` trait（基于 `RequestContext`）。
//! Garrison 的 `FirewallContext` 结构不同，本适配器直接提供基于 `RequestPriority` 的
//! 准入判断（`should_admit`），优先级由调用方在外部解析。

use limiteron::priority::{PriorityConfig, RequestPriority};

/// 优先级准入控制器。
///
/// 根据 `PriorityConfig` 的比率配置和随机数，决定某个优先级的请求是否放行。
///
/// # 线程安全
///
/// 内部使用 `rand::thread_rng()` 做概率判断，无共享状态，可安全跨线程共享。
pub struct PriorityAdmissionController {
    config: PriorityConfig,
}

impl PriorityAdmissionController {
    /// 创建优先级准入控制器。
    pub fn new(config: PriorityConfig) -> Self {
        Self { config }
    }

    /// 判断指定优先级的请求是否应放行。
    ///
    /// # 逻辑
    ///
    /// 1. 获取该优先级的放行比率 `ratio`（0.0 ~ 1.0）
    /// 2. 生成 `[0, 1)` 随机数
    /// 3. 随机数 < ratio → 放行
    ///
    /// `ratio = 1.0` 时总是放行，`ratio = 0.0` 时总是拒绝。
    pub fn should_admit(&self, priority: RequestPriority) -> bool {
        let ratio = self.config.ratio_for(priority);
        if ratio >= 1.0 {
            return true;
        }
        if ratio <= 0.0 {
            return false;
        }
        // 使用简单确定性判断：基于当前时间的伪随机
        // 避免引入额外 rand 依赖（limiteron 内部已有 rand）
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let normalized = (seed % 1000) as f64 / 1000.0;
        normalized < ratio
    }

    /// 获取指定优先级的放行比率。
    pub fn ratio_for(&self, priority: RequestPriority) -> f64 {
        self.config.ratio_for(priority)
    }

    /// 获取配置引用。
    pub fn config(&self) -> &PriorityConfig {
        &self.config
    }
}

impl std::fmt::Debug for PriorityAdmissionController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PriorityAdmissionController")
            .field("critical_ratio", &self.config.critical_ratio)
            .field("high_ratio", &self.config.high_ratio)
            .field("normal_ratio", &self.config.normal_ratio)
            .field("low_ratio", &self.config.low_ratio)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Critical 优先级总是放行。
    #[test]
    fn critical_always_admitted() {
        let config = PriorityConfig {
            critical_ratio: 1.0,
            high_ratio: 0.0,
            normal_ratio: 0.0,
            low_ratio: 0.0,
            overload_threshold: 0.8,
        };
        let ctrl = PriorityAdmissionController::new(config);
        for _ in 0..100 {
            assert!(ctrl.should_admit(RequestPriority::Critical));
        }
    }

    /// ratio=0 的优先级总是拒绝。
    #[test]
    fn zero_ratio_always_rejected() {
        let config = PriorityConfig {
            critical_ratio: 1.0,
            high_ratio: 0.0,
            normal_ratio: 0.0,
            low_ratio: 0.0,
            overload_threshold: 0.8,
        };
        let ctrl = PriorityAdmissionController::new(config);
        for _ in 0..100 {
            assert!(!ctrl.should_admit(RequestPriority::Low));
        }
    }

    /// ratio_for 返回正确比率。
    #[test]
    fn ratio_for_returns_configured_values() {
        let ctrl = PriorityAdmissionController::new(PriorityConfig::default());
        assert!((ctrl.ratio_for(RequestPriority::Critical) - 1.0).abs() < f64::EPSILON);
        assert!((ctrl.ratio_for(RequestPriority::Low) - 0.1).abs() < f64::EPSILON);
    }

    /// Debug 输出包含配置信息。
    #[test]
    fn debug_contains_ratios() {
        let ctrl = PriorityAdmissionController::new(PriorityConfig::default());
        let debug = format!("{:?}", ctrl);
        assert!(debug.contains("PriorityAdmissionController"));
        assert!(debug.contains("critical_ratio"));
    }
}
