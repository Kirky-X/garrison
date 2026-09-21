// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 数据主体擦除编排（GDPR Art. 17 / 个保法第 47 条语境的删除权）。
//!
//! # 框架管辖内的可定位键
//!
//! | 数据类 | 键（构造来源） | 主体维度 |
//! |--------|----------------|----------|
//! | Account-Session 索引 | `account:session:{login_id}`（`session::account_key`） | login_id |
//! | 账户锁定状态 | `lockout:{login_id}`（`DaoKeyPrefix::Lockout`） | login_id |
//! | 暴力破解失败计数 | `bf:{ip}:count`（`DaoKeyPrefix::BruteForce`，同生产路径） | 客户端 IP |
//!
//! 会话/token 明细由委托闭包擦除（推荐 `StpLogic::logout_by_login_id`，
//! 含 per-login 锁、token 键删除与内存索引清理）。
//!
//! # 框架管辖外（报告 `residual_guidance` 提示，由业务方处置）
//!
//! API Key（owner 关联，含业务授权语义）、验证码记录（手机号/邮箱键，业务映射）、
//! 业务用户资料、审计日志（合规保留期优先于删除权，见 docs/DATA_COMPLIANCE.md）。

use std::future::Future;
use std::sync::Arc;

use crate::constants::DaoKeyPrefix;
use crate::dao::GarrisonDao;
use crate::error::GarrisonResult;
use crate::session::account_key;

/// 数据主体擦除服务。
///
/// 组合框架既有删除原语，按主体执行可定位数据的擦除并产出报告。
/// 构造只需 [`GarrisonDao`]；会话擦除经 [`erase_subject`](Self::erase_subject)
/// 的闭包参数委托（推荐注入 `StpLogic::logout_by_login_id`）。
pub struct DataErasureService {
    dao: Arc<dyn GarrisonDao>,
}

/// 擦除报告：记录已删除键、委托执行结果与业务方残留处置提示。
///
/// 报告本身不含个人信息明文以外的载荷（仅键名与提示文案），可直接
/// 作为删除权请求的响应留档。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureReport {
    /// 主体标识（login_id）。
    pub login_id: String,
    /// 本服务直接删除的 DAO 键（已验证幂等删除调用成功）。
    pub erased_keys: Vec<String>,
    /// 会话擦除委托是否执行成功（false = 调用方未提供或委托返回 Err）。
    pub session_erasure_delegated: bool,
    /// 框架管辖外、需业务方处置的残留数据提示。
    pub residual_guidance: Vec<&'static str>,
}

impl DataErasureService {
    /// 创建擦除服务。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self { dao }
    }

    /// 擦除指定主体在框架管辖内的可定位数据。
    ///
    /// # 参数
    /// - `login_id`: 主体标识。
    /// - `session_erasure`: 会话擦除委托（推荐 `stp.logout_by_login_id`，
    ///   持有 per-login 锁与会话完整性语义）。闭包返回 `Ok` 即视为委托成功；
    ///   若调用方刻意跳过会话擦除，由其自行承担闭包语义（委托的成败以
    ///   闭包返回值为准，本服务不做二次解读）。
    ///
    /// # 报告语义
    ///
    /// `erased_keys` 仅含本服务直接删除且调用成功的键；`session_erasure_delegated`
    /// 忠实反映委托闭包的执行结果——失败为 `false` 且不中断整体擦除（会话残留由
    /// 报告显性暴露，调用方决定重试或告警），与框架 fail-closed 立场一致：
    /// 删除权路径宁可报告残留也不静默宣称完成。
    pub async fn erase_subject<F, Fut>(
        &self,
        login_id: &str,
        session_erasure: F,
    ) -> GarrisonResult<ErasureReport>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = GarrisonResult<()>>,
    {
        let mut erased_keys = Vec::new();

        // 1. 会话擦除委托（per-login 锁语义在 StpLogic 侧）
        let delegated = session_erasure(login_id.to_string()).await.is_ok();

        // 2. Account-Session 索引键（与 session::account_key 同源构造；委托已删时幂等）
        let account_key = account_key(login_id);
        self.dao.delete(&account_key).await?;
        erased_keys.push(account_key);

        // 3. 账户锁定状态键（锁定状态含失败模式等主体行为画像，属删除权范围）
        let lockout_key = DaoKeyPrefix::Lockout.build_key(login_id);
        self.dao.delete(&lockout_key).await?;
        erased_keys.push(lockout_key);

        Ok(ErasureReport {
            login_id: login_id.to_string(),
            erased_keys,
            session_erasure_delegated: delegated,
            residual_guidance: residual_guidance(),
        })
    }

    /// 擦除指定客户端 IP 在框架管辖内的防护状态（暴力破解失败计数）。
    ///
    /// IP 属个人信息（GDPR Recital 30），主体请求删除时同步清理。
    /// 键构造与 `strategy::firewall::brute_force` 生产路径一致（`bf:{ip}:count`）。
    pub async fn erase_ip_artifacts(&self, ip: &str) -> GarrisonResult<ErasureReport> {
        let count_key = format!("{}{}:count", DaoKeyPrefix::BruteForce, ip);
        self.dao.delete(&count_key).await?;

        Ok(ErasureReport {
            login_id: ip.to_string(),
            erased_keys: vec![count_key],
            session_erasure_delegated: false,
            residual_guidance: vec![
                "IP 关联的其他防护记录（GeoIP 缓存、限速窗口键）随 TTL 自然过期；若需立即清除请扩展本方法",
            ],
        })
    }
}

/// 框架管辖外的残留处置提示（固定清单，报告可留档）。
fn residual_guidance() -> Vec<&'static str> {
    vec![
        "API Key：与 owner 关联且含业务授权语义，经 ApiKeyRepository 按 owner 查询后吊销（见 protocol-apikey 文档）",
        "审计日志：合规保留期优先于删除权（个保法第 47 条 / GDPR Art. 17(3)(b) 法律义务例外），到期按保留策略销毁",
        "业务用户资料与业务副本：存储于业务方自有表，框架不可达",
        "验证码 / 邮箱验证记录：以手机号/邮箱为键（业务映射），随 TTL（≤1 小时）自然过期",
        "已发出的 JWT：无状态签名，到期前技术不可撤回（除非启用 revocation，见 config enable_jwt_revocation）",
    ]
}

#[cfg(all(test, feature = "data-erasure"))]
mod tests {
    use super::*;
    use crate::dao::InMemoryDao;

    fn service() -> (DataErasureService, Arc<InMemoryDao>) {
        let dao = Arc::new(InMemoryDao::new());
        (DataErasureService::new(dao.clone()), dao)
    }

    /// 擦除主体：可定位键被删除、委托被调用、报告含残留提示。
    #[tokio::test]
    async fn erase_subject_removes_locatable_keys_and_delegates() {
        let (service, dao) = service();

        // 预置三类键（与生产同源构造）
        dao.set(&account_key("1001"), "account-session", 3600)
            .await
            .unwrap();
        dao.set(&DaoKeyPrefix::Lockout.build_key("1001"), "lockout-state", 0)
            .await
            .unwrap();
        // 无关键：不得被误删
        dao.set(&account_key("2002"), "other-subject", 3600)
            .await
            .unwrap();

        let dao_for_delegate = dao.clone();
        let delegated = move |id: String| async move {
            // 模拟 StpLogic::logout_by_login_id（真实注入见集成路径）
            dao_for_delegate.delete(&account_key(&id)).await.unwrap();
            Ok(())
        };
        let report = service.erase_subject("1001", delegated).await.unwrap();

        assert!(report.session_erasure_delegated);
        assert!(
            report.erased_keys.contains(&account_key("1001")),
            "应含 account-session 键: {:?}",
            report.erased_keys
        );
        assert!(
            report
                .erased_keys
                .contains(&DaoKeyPrefix::Lockout.build_key("1001")),
            "应含 lockout 键: {:?}",
            report.erased_keys
        );
        assert!(
            dao.get(&account_key("1001")).await.unwrap().is_none(),
            "account-session 键应已删除"
        );
        assert!(
            dao.get(&DaoKeyPrefix::Lockout.build_key("1001"))
                .await
                .unwrap()
                .is_none(),
            "lockout 键应已删除"
        );
        assert!(
            dao.get(&account_key("2002")).await.unwrap().is_some(),
            "无关主体键不得被误删"
        );
        assert!(
            !report.residual_guidance.is_empty(),
            "报告应含业务方残留处置提示"
        );
        assert_eq!(report.login_id, "1001");
    }

    /// 委托失败不中断擦除：可定位键仍删除，报告显性暴露委托失败（不静默）。
    #[tokio::test]
    async fn erase_subject_surfaces_delegation_failure_without_aborting() {
        let (service, dao) = service();
        dao.set(&account_key("1001"), "v", 60).await.unwrap();

        let failing =
            |_id: String| async { Err(crate::error::GarrisonError::Internal("boom".into())) };
        let report = service.erase_subject("1001", failing).await.unwrap();

        assert!(
            !report.session_erasure_delegated,
            "委托失败应在报告中显性暴露"
        );
        assert!(
            dao.get(&account_key("1001")).await.unwrap().is_none(),
            "委托失败不得中断可定位键的删除"
        );
    }

    /// 调用方自选跳过（Ok 空委托）：delegated 如实为 true——委托成败以闭包
    /// 返回值为准，服务不二次解读；与委托失败为 false（上一测试）形成对照。
    #[tokio::test]
    async fn erase_subject_trivial_delegate_reports_by_closure_outcome() {
        let (service, _dao) = service();
        let report = service
            .erase_subject("1001", |_id| async { Ok(()) })
            .await
            .unwrap();
        assert!(report.session_erasure_delegated);
    }

    /// IP 防护痕迹擦除：bf 计数键删除且与生产键格式一致。
    #[tokio::test]
    async fn erase_ip_artifacts_removes_brute_force_count() {
        let (service, dao) = service();
        let key = format!("{}{}:count", DaoKeyPrefix::BruteForce, "203.0.113.7");
        dao.set(&key, "3", 3600).await.unwrap();

        let report = service.erase_ip_artifacts("203.0.113.7").await.unwrap();
        assert_eq!(report.erased_keys, vec![key.clone()]);
        assert!(dao.get(&key).await.unwrap().is_none());
    }

    /// 幂等：对已擦除主体重复执行不报错。
    #[tokio::test]
    async fn erase_subject_is_idempotent() {
        let (service, _dao) = service();
        service
            .erase_subject("1001", |_id| async { Ok(()) })
            .await
            .unwrap();
        let second = service
            .erase_subject("1001", |_id| async { Ok(()) })
            .await
            .unwrap();
        assert!(!second.erased_keys.is_empty(), "幂等删除仍返回键清单");
    }
}
