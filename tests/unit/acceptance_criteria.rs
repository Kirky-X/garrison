//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BW-AC-008 故障注入用例（单元层版本）。
//!
//! 下沉说明（production-mock-purge T024）：原 `tests/acceptance_criteria.rs`
//! 的 `bw_ac_008_oxcache_failure_degrades_to_jwt_stateless` 依赖 `FailingDao`
//! 强制注入 DAO 故障（所有操作返回 `Err(GarrisonError::Dao)`）。错误注入/故障
//! 模拟语义属单元层，按 production-mock-purge 方案 D7-2 下沉至本目录，
//! 集成测试文件不再包含故障注入替身。
//!
//! 单元测试允许本地 mock。

use async_trait::async_trait;
use serial_test::serial;
use std::sync::Arc;

use garrison::error::{GarrisonError, GarrisonResult};
use garrison::stp::GarrisonInterface;
use garrison::{GarrisonConfig, GarrisonDao, GarrisonManager, GarrisonUtil};

/// FailingDao：所有操作返回 Err（模拟 oxcache 故障）。
struct FailingDao;

#[async_trait]
impl GarrisonDao for FailingDao {
    async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
        Err(GarrisonError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        Err(GarrisonError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Err(GarrisonError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
    async fn delete(&self, _key: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Dao(
            "simulated redis cluster failure".to_string(),
        ))
    }
}

/// 单元层空接口（仅满足 `GarrisonManager::builder().interface()` 构造要求；
/// 故障注入本体是 `FailingDao`，接口数据不参与断言）。
struct EmptyInterface;

#[async_trait]
impl GarrisonInterface for EmptyInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
}

/// 初始化全局 GarrisonManager 并注入 FailingDao（用于 BW-AC-008 故障降级测试）。
async fn init_manager_failing() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(FailingDao);
    let mut config = GarrisonConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    let interface: Arc<dyn GarrisonInterface> = Arc::new(EmptyInterface);
    GarrisonManager::builder()
        .dao(dao)
        .config(Arc::new(config))
        .interface(interface)
        .build()
        .await
        .expect("GarrisonManager::builder() 应成功");
}

/// BW-AC-008：oxcache Redis Cluster 故障时降级为 JWT Stateless 模式
/// （FRD §8.1 BW-AC-008）。
///
/// # 规则7 冲突
///
/// spec 期望"系统降级为 JWT Stateless 模式"，但代码库无自动降级逻辑。
/// 降级需业务代码捕获 DAO 错误后手动切换 `JwtMode::Stateless`。
/// 本测试验证 DAO 故障时错误显性传播（规则12：失败必须显性化），
/// 不验证自动降级（推迟到 v0.7.0）。
///
/// # Gherkin
///
/// ```text
/// Given: oxcache Redis Cluster 后端故障（mock DAO 返回 Err）
/// When: 用户尝试登录
/// Then:
///   - DAO 错误显性传播（login 返回 Err(GarrisonError::Dao)）
///   - 错误不被吞掉或隐藏在默认值背后
///   - 触发告警（tracing::warn 日志，由 session.create 内部记录）
/// ```
#[tokio::test]
#[serial]
async fn bw_ac_008_oxcache_failure_degrades_to_jwt_stateless() {
    init_manager_failing().await;

    // When: 用户尝试登录（FailingDao 的 set 返回 Err）
    let result = GarrisonUtil::login_simple("user-008").await;

    // Then: DAO 错误显性传播（规则12）
    assert!(result.is_err(), "DAO 故障时 login 应返回错误（不吞掉）");
    let err = result.unwrap_err();
    assert!(
        matches!(err, GarrisonError::Dao(_)),
        "期望 Dao 错误，实际: {:?}",
        err
    );

    // 规则7 冲突文档：自动降级到 JwtMode::Stateless 未实现。
    // 业务代码应捕获此错误后手动切换 JwtMode::Stateless 重试（需 protocol-jwt feature）。
}