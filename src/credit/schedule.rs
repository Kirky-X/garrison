//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Credit 消费权重表。
//!
//! `CreditSchedule` 定义 resource → credit_weight 映射，
//! 未配置的 resource 使用 `default_weight`。
//!
//! # 权重校验
//!
//! weight = 0 会使资源「免费」（消费 0 credit 绕过限额），构造入口
//! （[`CreditSchedule::insert`] / [`CreditSchedule::with_default`]）拒绝 0 并
//! 返回 [`CreditError::ConfigInvalid`]。

use crate::credit::error::{CreditError, CreditResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Credit 消费权重表：resource → credit_weight。
///
/// 未配置的 resource 使用 `default_weight`（默认 1）。
///
/// # 示例
///
/// ```ignore
/// let mut schedule = CreditSchedule::new();
/// schedule.insert("sms", 5);    // 1 SMS = 5 credits
/// schedule.insert("login", 1);  // 1 login = 1 credit
/// assert_eq!(schedule.weight_for("sms"), 5);
/// assert_eq!(schedule.weight_for("unknown"), 1); // 默认权重
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditSchedule {
    /// resource → credit 权重映射。
    weights: HashMap<String, u64>,
    /// 未配置 resource 的默认权重。
    default_weight: u64,
}

impl CreditSchedule {
    /// 创建空的权重表（默认权重 = 1）。
    pub fn new() -> Self {
        Self {
            weights: HashMap::new(),
            default_weight: 1,
        }
    }

    /// 创建带指定默认权重的权重表。
    ///
    /// # 错误
    /// `default_weight = 0` 返回 [`CreditError::ConfigInvalid`]（零权重会使所有
    /// 未配置资源免费，绕过限额）。
    pub fn with_default(default_weight: u64) -> CreditResult<Self> {
        if default_weight == 0 {
            return Err(CreditError::ConfigInvalid(
                "credit-schedule-zero-weight::default_weight=0".to_string(),
            ));
        }
        Ok(Self {
            weights: HashMap::new(),
            default_weight,
        })
    }

    /// 获取 resource 的 credit 权重。
    ///
    /// 未配置的 resource 返回 `default_weight`。
    pub fn weight_for(&self, resource: &str) -> u64 {
        self.weights
            .get(resource)
            .copied()
            .unwrap_or(self.default_weight)
    }

    /// 设置 resource 的 credit 权重。
    ///
    /// # 错误
    /// `weight = 0` 返回 [`CreditError::ConfigInvalid`]（零权重会使该资源免费，
    /// 消费 0 credit 绕过限额），且不写入映射。
    pub fn insert(&mut self, resource: impl Into<String>, weight: u64) -> CreditResult<()> {
        if weight == 0 {
            return Err(CreditError::ConfigInvalid(format!(
                "credit-schedule-zero-weight::resource={}",
                resource.into()
            )));
        }
        self.weights.insert(resource.into(), weight);
        Ok(())
    }

    /// 返回已配置的权重映射引用。
    pub fn weights(&self) -> &HashMap<String, u64> {
        &self.weights
    }

    /// 返回默认权重。
    pub fn default_weight(&self) -> u64 {
        self.default_weight
    }
}

impl Default for CreditSchedule {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 已知 resource 返回配置的权重。
    #[test]
    fn test_weight_for_known_resource() {
        let mut schedule = CreditSchedule::new();
        schedule.insert("sms", 5);
        schedule.insert("login", 1);
        assert_eq!(schedule.weight_for("sms"), 5);
        assert_eq!(schedule.weight_for("login"), 1);
    }

    /// 未知 resource 返回默认权重（1）。
    #[test]
    fn test_weight_for_unknown_resource_returns_default() {
        let schedule = CreditSchedule::new();
        assert_eq!(schedule.weight_for("unknown"), 1);
    }

    /// 自定义默认权重。
    #[test]
    fn test_with_default_weight() {
        let schedule = CreditSchedule::with_default(10).unwrap();
        assert_eq!(schedule.weight_for("anything"), 10);
    }

    /// insert 拒绝 weight = 0（零权重会使资源免费绕过限额），且不写入映射。
    #[test]
    fn test_insert_zero_weight_rejected() {
        let mut schedule = CreditSchedule::new();
        let err = schedule.insert("sms", 0).unwrap_err();
        assert!(
            format!("{}", err).contains("credit-schedule-zero-weight"),
            "实际: {}",
            err
        );
        // 拒绝后映射未写入，resource 回退到默认权重
        assert_eq!(schedule.weight_for("sms"), 1);
    }

    /// with_default 拒绝 default_weight = 0。
    #[test]
    fn test_with_default_zero_rejected() {
        let err = CreditSchedule::with_default(0).unwrap_err();
        assert!(
            format!("{}", err).contains("credit-schedule-zero-weight"),
            "实际: {}",
            err
        );
    }

    /// insert 覆盖已有权重。
    #[test]
    fn test_insert_overwrites_weight() {
        let mut schedule = CreditSchedule::new();
        schedule.insert("sms", 5).unwrap();
        assert_eq!(schedule.weight_for("sms"), 5);
        schedule.insert("sms", 10).unwrap();
        assert_eq!(schedule.weight_for("sms"), 10);
    }

    /// weights() 返回映射引用。
    #[test]
    fn test_weights_ref() {
        let mut schedule = CreditSchedule::new();
        schedule.insert("sms", 5).unwrap();
        assert_eq!(schedule.weights().len(), 1);
        assert_eq!(schedule.weights().get("sms"), Some(&5));
    }
}
