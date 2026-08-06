//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Credit 计量监听器（可选自动扣减）。
//!
//! `CreditMeteringListener` 监听 `GarrisonEvent::Login` 事件，
//! 自动扣减 1 credit（weight 由 `CreditSchedule` 中 "login" 资源决定）。

use crate::context::tenant::current_tenant_id_or_error;
use crate::credit::meter::CreditMeter;
use crate::error::GarrisonResult;
use crate::listener::{GarrisonEvent, GarrisonListener};
use async_trait::async_trait;
use std::sync::Arc;

/// Credit 计量监听器。
///
/// 监听 `GarrisonEvent::Login` 事件，自动扣减 1 credit。
/// 失败仅记录 `tracing::warn`，不阻断登录流程。
pub struct CreditMeteringListener {
    meter: Arc<CreditMeter>,
}

impl CreditMeteringListener {
    /// 创建监听器实例。
    pub fn new(meter: Arc<CreditMeter>) -> Self {
        Self { meter }
    }
}

#[async_trait]
impl GarrisonListener for CreditMeteringListener {
    async fn on_event(&self, event: &GarrisonEvent) -> GarrisonResult<()> {
        if let GarrisonEvent::Login { .. } = event {
            // 从 TENANT task_local 获取 tenant_id
            match current_tenant_id_or_error() {
                Ok(tenant_id) => {
                    if let Err(e) = self.meter.consume_credit(tenant_id, "login", 1).await {
                        tracing::warn!(
                            tenant_id,
                            error = %e,
                            "credit: auto-deduct on login failed"
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "credit: cannot get tenant_id for auto-deduct on login"
                    );
                },
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credit::config::CreditConfig;
    use crate::credit::cycle::CreditCycle;
    use crate::credit::schedule::CreditSchedule;
    use crate::dao::tests::MockDao;
    use crate::dao::GarrisonDao;

    fn make_meter() -> Arc<CreditMeter> {
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let config = CreditConfig {
            credit_limit: 100,
            cycle: CreditCycle::Rolling { days: 30 },
            schedule: CreditSchedule::default(),
            alert_thresholds: vec![80],
            persist_history: false,
        };
        Arc::new(CreditMeter::new(dao, config))
    }

    /// 非 Login 事件不触发 credit 扣减。
    #[tokio::test]
    async fn test_non_login_event_ignored() {
        let meter = make_meter();
        let listener = CreditMeteringListener::new(meter.clone());
        let event = GarrisonEvent::Logout {
            login_id: "1001".to_string(),
            token: "tok".to_string(),
            request_context: None,
        };
        // 不应 panic 或返回 Err
        let result = listener.on_event(&event).await;
        assert!(result.is_ok());
    }

    /// Login 事件在无 TENANT 上下文时不阻断（仅 warn）。
    #[tokio::test]
    async fn test_meter_error_does_not_block_login() {
        let meter = make_meter();
        let listener = CreditMeteringListener::new(meter.clone());
        let event = GarrisonEvent::Login {
            login_id: "1001".to_string(),
            token: "tok".to_string(),
            device: None,
            request_context: None,
        };
        // 无 TENANT scope → current_tenant_id_or_error() 返回 Err → 仅 warn
        let result = listener.on_event(&event).await;
        assert!(result.is_ok(), "listener 不应阻断登录流程");
    }
}
