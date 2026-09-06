//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `src/protocol/invitation` 单元测试。
//!
//! 覆盖：码生成与规范化（T002）、签发（T003）、只读校验（T004）、原子消费（T005）、
//! 防爆破锁定（T006）、吊销与列出（T007）、事件广播（T008）、注册编排钩子（T009）。

use super::*;
use crate::listener::{GarrisonEvent, GarrisonListener, GarrisonListenerManager};
use std::sync::Mutex;

// ============================================================================
// T008: 事件变体与广播（listener/mod.rs + audit.rs）
// ============================================================================

#[cfg(feature = "listener")]
mod event_tests {
    use super::*;

    /// 收集型监听器：把广播到达的事件克隆进共享缓冲。
    #[derive(Default)]
    struct CollectingListener {
        events: Mutex<Vec<GarrisonEvent>>,
    }

    #[async_trait::async_trait]
    impl GarrisonListener for CollectingListener {
        async fn on_event(&self, event: &GarrisonEvent) -> crate::error::GarrisonResult<()> {
            self.events.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    #[test]
    fn invitation_events_constructible_and_matchable() {
        let created = GarrisonEvent::InvitationCreated {
            code: "AB3C9XYZ".to_string(),
            issuer_id: "issuer-1".to_string(),
        };
        let redeemed = GarrisonEvent::InvitationRedeemed {
            code: "AB3C9XYZ".to_string(),
            redeemer_id: "user-1".to_string(),
        };
        let revoked = GarrisonEvent::InvitationRevoked {
            code: "AB3C9XYZ".to_string(),
            issuer_id: "issuer-1".to_string(),
        };
        // Debug 输出含变体名；PartialEq 可比较
        assert!(format!("{created:?}").contains("InvitationCreated"));
        assert!(format!("{redeemed:?}").contains("InvitationRedeemed"));
        assert!(format!("{revoked:?}").contains("InvitationRevoked"));
        assert_eq!(
            created,
            GarrisonEvent::InvitationCreated {
                code: "AB3C9XYZ".to_string(),
                issuer_id: "issuer-1".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn invitation_events_broadcast_reach_listeners() {
        let manager = GarrisonListenerManager::new();
        let listener = std::sync::Arc::new(CollectingListener::default());
        manager.register(listener.clone());
        manager
            .broadcast(&GarrisonEvent::InvitationCreated {
                code: "AB3C9XYZ".to_string(),
                issuer_id: "issuer-1".to_string(),
            })
            .await;
        manager
            .broadcast(&GarrisonEvent::InvitationRedeemed {
                code: "AB3C9XYZ".to_string(),
                redeemer_id: "user-1".to_string(),
            })
            .await;
        manager
            .broadcast(&GarrisonEvent::InvitationRevoked {
                code: "AB3C9XYZ".to_string(),
                issuer_id: "issuer-1".to_string(),
            })
            .await;
        let events = listener.events.lock().unwrap();
        assert_eq!(events.len(), 3, "三个事件均应到达监听器");
        assert!(matches!(events[0], GarrisonEvent::InvitationCreated { .. }));
        assert!(matches!(
            events[1],
            GarrisonEvent::InvitationRedeemed { .. }
        ));
        assert!(matches!(events[2], GarrisonEvent::InvitationRevoked { .. }));
    }
}

// ============================================================================
// T002: 码生成与输入规范化（code.rs）
// ============================================================================

mod code_tests {
    use super::super::code;
    use crate::error::GarrisonError;

    #[test]
    fn generate_produces_normalized_shape_from_charset() {
        // 生成 100 次，全部满足 XXXX-XXXX 形态且字符在去歧义字符集内
        for _ in 0..100 {
            let code = code::generate();
            assert_eq!(code.len(), 9, "码长度应为 9（8 字符 + 1 连字符）: {code}");
            assert_eq!(&code[4..5], "-", "第 5 位应为连字符: {code}");
            for (i, ch) in code.chars().enumerate() {
                if i == 4 {
                    continue;
                }
                assert!(
                    code::CHARSET.contains(ch),
                    "字符 {ch} 不在去歧义字符集内: {code}"
                );
            }
        }
    }

    #[test]
    fn generate_produces_distinct_codes() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            assert!(seen.insert(code::generate()), "50 次生成不应重复");
        }
    }

    #[test]
    fn normalize_uppercases_and_strips_hyphens() {
        assert_eq!(code::normalize("ab3c-9xyz").unwrap(), "AB3C9XYZ");
        assert_eq!(code::normalize(" AB3C-9XYZ ").unwrap(), "AB3C9XYZ");
        assert_eq!(code::normalize("AB3C9XYZ").unwrap(), "AB3C9XYZ");
        assert_eq!(code::normalize("a-b-c-d").unwrap(), "ABCD");
    }

    #[test]
    fn normalize_rejects_ambiguous_and_illegal_chars() {
        for bad in [
            "AB0C-9XYZ",
            "AB1C-9XYZ",
            "ABOC-9XYZ",
            "ABLC-9XYZ",
            "AB@C-9XYZ",
        ] {
            let err = code::normalize(bad).unwrap_err();
            assert!(
                matches!(err, GarrisonError::InvalidParam(ref m) if m.starts_with("invitation-code-invalid::")),
                "非法输入 {bad} 应返回 invitation-code-invalid:: key 前缀错误，实际 {err:?}"
            );
        }
    }

    #[test]
    fn normalize_rejects_empty_and_oversized_input() {
        assert!(code::normalize("").is_err());
        assert!(code::normalize("   ").is_err());
        let oversized = "A".repeat(33);
        assert!(code::normalize(&oversized).is_err());
    }
}

// ============================================================================
// 测试 DAO：记录 TTL 的内存 Mock（key 过滤支持尾部 '*' 通配）
// ============================================================================

mod mock {
    use crate::dao::GarrisonDao;
    use crate::error::{GarrisonError, GarrisonResult};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use tokio::sync::Mutex;

    pub struct MockDao {
        /// key → (value, deadline)。deadline 为 None 表示永不过期。
        pub data: Mutex<HashMap<String, (String, Option<Instant>)>>,
    }

    impl MockDao {
        pub fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl GarrisonDao for MockDao {
        async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
            let data = self.data.lock().await;
            match data.get(key) {
                Some((v, deadline)) if deadline.map(|d| Instant::now() < d).unwrap_or(true) => {
                    Ok(Some(v.clone()))
                },
                _ => Ok(None),
            }
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
            let deadline = if ttl_seconds == 0 {
                None
            } else {
                Some(Instant::now() + Duration::from_secs(ttl_seconds))
            };
            self.data
                .lock()
                .await
                .insert(key.to_string(), (value.to_string(), deadline));
            Ok(())
        }

        async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
            let mut data = self.data.lock().await;
            match data.get_mut(key) {
                Some(entry) => {
                    entry.0 = value.to_string();
                    Ok(())
                },
                None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
            let mut data = self.data.lock().await;
            match data.get_mut(key) {
                Some(entry) => {
                    entry.1 = Some(Instant::now() + Duration::from_secs(seconds));
                    Ok(())
                },
                None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
            }
        }

        async fn delete(&self, key: &str) -> GarrisonResult<()> {
            self.data.lock().await.remove(key);
            Ok(())
        }

        async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
            let mut data = self.data.lock().await;
            match data.remove(key) {
                Some((v, deadline)) if deadline.map(|d| Instant::now() < d).unwrap_or(true) => {
                    Ok(Some(v))
                },
                // 过期条目视为不存在（已随 remove 丢弃）
                _ => Ok(None),
            }
        }

        async fn get_with_ttl(
            &self,
            key: &str,
        ) -> GarrisonResult<Option<(String, Option<Duration>)>> {
            let data = self.data.lock().await;
            match data.get(key) {
                Some((v, deadline)) if deadline.map(|d| Instant::now() < d).unwrap_or(true) => {
                    Ok(Some((v.clone(), deadline.map(|d| d - Instant::now()))))
                },
                _ => Ok(None),
            }
        }

        async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
            let data = self.data.lock().await;
            let prefix = pattern.strip_suffix('*').unwrap_or(pattern);
            Ok(data
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }

        // 其余原子方法（set_if_absent/rename/incr/decr/compare_and_swap）经子集宏展开
        crate::atomic_test_fallback_no_get_and_delete!();
    }
}

use mock::MockDao;

use std::sync::Arc;
use std::time::Duration;

/// 构造 handler（MockDao）。
fn make_handler() -> InvitationHandler {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(MockDao::new());
    InvitationHandler::new(dao)
}

/// 构造带 listener 的 handler，返回 (handler, 收集到的事件缓冲 Arc)。
#[cfg(feature = "listener")]
fn make_handler_with_listener() -> (
    InvitationHandler,
    Arc<std::sync::Mutex<Vec<crate::listener::GarrisonEvent>>>,
) {
    let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(MockDao::new());
    let manager = Arc::new(crate::listener::GarrisonListenerManager::new());
    let sink = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink2 = sink.clone();
    manager.register(Arc::new(EventSink { events: sink2 }));
    (
        InvitationHandler::new(dao).with_listener_manager(manager),
        sink,
    )
}

/// 收集型监听器（供 handler 广播验证）。
#[cfg(feature = "listener")]
struct EventSink {
    events: Arc<std::sync::Mutex<Vec<crate::listener::GarrisonEvent>>>,
}

#[cfg(feature = "listener")]
#[async_trait::async_trait]
impl crate::listener::GarrisonListener for EventSink {
    async fn on_event(
        &self,
        event: &crate::listener::GarrisonEvent,
    ) -> crate::error::GarrisonResult<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}

/// 默认签发规格。
fn base_spec() -> InvitationSpec {
    InvitationSpec {
        issuer_id: "issuer-1".to_string(),
        tenant_id: None,
        bound_roles: vec!["member".to_string()],
        max_uses: 1,
        ttl_seconds: 600,
    }
}

// ============================================================================
// T003: create / create_batch（handler.rs）
// ============================================================================

mod create_tests {
    use super::*;

    #[tokio::test]
    async fn create_returns_record_and_kv_has_positive_ttl() {
        let handler = make_handler();
        let record = handler.create(base_spec()).await.unwrap();
        assert_eq!(record.issuer_id, "issuer-1");
        assert_eq!(record.max_uses, 1);
        assert_eq!(record.used_count, 0);
        assert_eq!(record.status, InvitationStatus::Active);
        assert!(record.created_at > 0 && record.expires_at > record.created_at);
        // KV 中可读回且剩余 TTL > 0
        let key = format!("garrison:invitation:code:{}", record.code);
        let (value, ttl) = handler.dao.get_with_ttl(&key).await.unwrap().unwrap();
        assert_eq!(value, serde_json::to_string(&record).unwrap());
        assert!(ttl.unwrap() > Duration::ZERO, "剩余 TTL 应大于 0");
    }

    #[tokio::test]
    async fn create_rejects_non_positive_ttl() {
        let handler = make_handler();
        let mut spec = base_spec();
        spec.ttl_seconds = 0;
        let err = handler.create(spec).await.unwrap_err();
        assert!(
            matches!(err, crate::error::GarrisonError::InvalidParam(ref m) if m.starts_with("invitation-ttl-invalid::")),
            "实际 {err:?}"
        );
    }

    #[tokio::test]
    async fn create_rejects_zero_max_uses() {
        let handler = make_handler();
        let mut spec = base_spec();
        spec.max_uses = 0;
        let err = handler.create(spec).await.unwrap_err();
        assert!(
            matches!(err, crate::error::GarrisonError::InvalidParam(ref m) if m.starts_with("invitation-max-uses-invalid::")),
            "实际 {err:?}"
        );
    }

    #[tokio::test]
    async fn create_batch_returns_distinct_codes() {
        let handler = make_handler();
        let records = handler.create_batch(base_spec(), 5).await.unwrap();
        assert_eq!(records.len(), 5);
        let codes: std::collections::HashSet<&str> =
            records.iter().map(|r| r.code.as_str()).collect();
        assert_eq!(codes.len(), 5, "批量签发的码应互异");
    }

    #[tokio::test]
    async fn create_batch_rejects_zero_count() {
        let handler = make_handler();
        assert!(handler.create_batch(base_spec(), 0).await.is_err());
    }

    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn create_broadcasts_invitation_created() {
        let (handler, sink) = make_handler_with_listener();
        let record = handler.create(base_spec()).await.unwrap();
        let events = sink.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            crate::listener::GarrisonEvent::InvitationCreated { code, issuer_id } => {
                assert_eq!(code, &record.code);
                assert_eq!(issuer_id, "issuer-1");
            },
            other => panic!("期望 InvitationCreated 事件，实际 {other:?}"),
        }
    }
}

// ============================================================================
// T004: validate 只读校验（handler.rs）
// ============================================================================

mod validate_tests {
    use super::*;

    /// 直接向 KV 写入一条自定义记录（绕过 create，构造边界场景）。
    async fn seed_record(handler: &InvitationHandler, record: &InvitationRecord, ttl: u64) {
        let key = format!("garrison:invitation:code:{}", record.code);
        handler
            .dao
            .set(&key, &serde_json::to_string(record).unwrap(), ttl)
            .await
            .unwrap();
    }

    fn record_with(
        code: &str,
        max_uses: u32,
        used_count: u32,
        status: InvitationStatus,
    ) -> InvitationRecord {
        let now = handler::unix_now();
        InvitationRecord {
            code: code.to_string(),
            issuer_id: "issuer-1".to_string(),
            tenant_id: None,
            bound_roles: vec![],
            max_uses,
            used_count,
            redeemed_by: vec![],
            created_at: now,
            expires_at: now + 600,
            status,
        }
    }

    #[tokio::test]
    async fn validate_valid_code_has_no_side_effect() {
        let handler = make_handler();
        let record = handler.create(base_spec()).await.unwrap();
        let report = handler.validate(&record.code).await.unwrap();
        assert!(report.is_valid());
        assert!(report.reason.is_none());
        assert_eq!(report.record.as_ref().unwrap().code, record.code);
        // 只读：KV 仍在且 used_count 不变
        let key = format!("garrison:invitation:code:{}", record.code);
        let raw = handler.dao.get(&key).await.unwrap().unwrap();
        let after: InvitationRecord = serde_json::from_str(&raw).unwrap();
        assert_eq!(after.used_count, 0);
    }

    #[tokio::test]
    async fn validate_unknown_code_reports_not_found() {
        let handler = make_handler();
        let report = handler.validate("ZZZZZZZZ").await.unwrap();
        assert!(!report.is_valid());
        assert_eq!(report.reason, Some(InvitationInvalidReason::NotFound));
        assert!(report.record.is_none());
    }

    #[tokio::test]
    async fn validate_expired_code_reports_expired() {
        let handler = make_handler();
        let mut record = record_with("AB2C9XYZ", 1, 0, InvitationStatus::Active);
        record.expires_at = handler::unix_now() - 1; // 已过期
        seed_record(&handler, &record, 3600).await; // KV 仍存活（TTL 由 expires_at 判定）
        let report = handler.validate(&record.code).await.unwrap();
        assert_eq!(report.reason, Some(InvitationInvalidReason::Expired));
    }

    #[tokio::test]
    async fn validate_revoked_code_reports_revoked() {
        let handler = make_handler();
        let record = record_with("CD3C9XYZ", 1, 0, InvitationStatus::Revoked);
        seed_record(&handler, &record, 3600).await;
        let report = handler.validate(&record.code).await.unwrap();
        assert_eq!(report.reason, Some(InvitationInvalidReason::Revoked));
    }

    #[tokio::test]
    async fn validate_exhausted_code_reports_exhausted() {
        let handler = make_handler();
        let record = record_with("EF4C9XYZ", 3, 3, InvitationStatus::Active);
        seed_record(&handler, &record, 3600).await;
        let report = handler.validate(&record.code).await.unwrap();
        assert_eq!(report.reason, Some(InvitationInvalidReason::Exhausted));
    }

    #[tokio::test]
    async fn validate_normalizes_input() {
        let handler = make_handler();
        let record = handler.create(base_spec()).await.unwrap();
        // 小写 + 连字符输入应归一后命中
        let display = format!(
            "{}-{}-{}",
            &record.code[..2],
            &record.code[2..6],
            &record.code[6..]
        )
        .to_lowercase();
        let report = handler.validate(&display).await.unwrap();
        assert!(report.is_valid(), "归一化输入应命中记录");
    }
}

// ============================================================================
// T005: redeem 原子消费（handler.rs，check-and-restore）
// ============================================================================

mod redeem_tests {
    use super::*;
    use crate::error::GarrisonError;

    async fn seed_record(handler: &InvitationHandler, record: &InvitationRecord, ttl: u64) {
        let key = format!("garrison:invitation:code:{}", record.code);
        handler
            .dao
            .set(&key, &serde_json::to_string(record).unwrap(), ttl)
            .await
            .unwrap();
    }

    fn record_with(
        code: &str,
        max_uses: u32,
        used_count: u32,
        status: InvitationStatus,
    ) -> InvitationRecord {
        let now = handler::unix_now();
        InvitationRecord {
            code: code.to_string(),
            issuer_id: "issuer-1".to_string(),
            tenant_id: None,
            bound_roles: vec!["member".to_string()],
            max_uses,
            used_count,
            redeemed_by: vec![],
            created_at: now,
            expires_at: now + 600,
            status,
        }
    }

    fn assert_invitation_err(err: GarrisonError, prefix: &str) {
        match err {
            GarrisonError::InvalidParam(m) => {
                assert!(m.starts_with(prefix), "错误应带 {prefix} 前缀，实际 {m}");
            },
            other => panic!("期望 InvalidParam({prefix}::)，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn redeem_single_use_succeeds_then_not_found() {
        let handler = make_handler();
        let record = handler.create(base_spec()).await.unwrap();
        let redeemed = handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap();
        assert_eq!(redeemed.used_count, 1);
        assert_eq!(redeemed.redeemed_by, vec!["user-1".to_string()]);
        // 单次消费后 KV 删除
        let key = format!("garrison:invitation:code:{}", record.code);
        assert!(handler.dao.get(&key).await.unwrap().is_none());
        // 二次消费 NotFound
        let err = handler
            .redeem(&record.code, "user-2", "10.0.0.2")
            .await
            .unwrap_err();
        assert_invitation_err(err, "invitation-code-not-found::");
    }

    #[tokio::test]
    async fn redeem_multi_use_exactly_max_uses_then_exhausted() {
        let handler = make_handler();
        let mut spec = base_spec();
        spec.max_uses = 3;
        let record = handler.create(spec).await.unwrap();
        for i in 1..=3 {
            let r = handler
                .redeem(&record.code, &format!("user-{i}"), "10.0.0.1")
                .await
                .unwrap();
            assert_eq!(r.used_count, i, "第 {i} 次消费后计数应为 {i}");
            let key = format!("garrison:invitation:code:{}", record.code);
            let (_, ttl) = handler.dao.get_with_ttl(&key).await.unwrap().unwrap();
            assert!(
                ttl.unwrap() > Duration::ZERO,
                "第 {i} 次消费后回写剩余 TTL 应 > 0"
            );
        }
        // 第 4 次：Exhausted
        let err = handler
            .redeem(&record.code, "user-4", "10.0.0.1")
            .await
            .unwrap_err();
        assert_invitation_err(err, "invitation-code-exhausted::");
        // Exhausted 记录回写保留，validate 可复核
        let report = handler.validate(&record.code).await.unwrap();
        assert_eq!(
            report.reason,
            Some(InvitationInvalidReason::Exhausted),
            "耗尽记录应回写供复核"
        );
    }

    #[tokio::test]
    async fn redeem_expired_code_rejected_without_rewrite() {
        let handler = make_handler();
        let mut record = record_with("AB2C9XZW", 1, 0, InvitationStatus::Active);
        record.expires_at = handler::unix_now() - 1;
        seed_record(&handler, &record, 3600).await;
        let err = handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap_err();
        assert_invitation_err(err, "invitation-code-expired::");
        // 过期记录不回写
        let key = format!("garrison:invitation:code:{}", record.code);
        assert!(
            handler.dao.get(&key).await.unwrap().is_none(),
            "过期记录不应回写"
        );
    }

    #[tokio::test]
    async fn redeem_revoked_code_rejected_and_record_kept() {
        let handler = make_handler();
        let record = record_with("CD3C9XZW", 1, 0, InvitationStatus::Revoked);
        seed_record(&handler, &record, 3600).await;
        let err = handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap_err();
        assert_invitation_err(err, "invitation-code-revoked::");
        // 吊销记录回写保留，validate 可复核
        let report = handler.validate(&record.code).await.unwrap();
        assert_eq!(report.reason, Some(InvitationInvalidReason::Revoked));
    }

    #[tokio::test]
    async fn redeem_revoked_and_expired_code_rejected_without_rewrite() {
        let handler = make_handler();
        let mut record = record_with("GH5C9XZW", 1, 0, InvitationStatus::Revoked);
        record.expires_at = handler::unix_now() - 1; // 吊销且已过期
        seed_record(&handler, &record, 3600).await;
        let err = handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap_err();
        assert_invitation_err(err, "invitation-code-revoked::");
        // 过期吊销记录不回写（本应随 KV TTL 消失）
        let key = format!("garrison:invitation:code:{}", record.code);
        assert!(handler.dao.get(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn redeem_concurrent_single_use_exactly_one_success() {
        let handler = Arc::new(make_handler());
        let record = handler.create(base_spec()).await.unwrap();
        let mut handles = Vec::new();
        for i in 0..32 {
            let h = handler.clone();
            let code = record.code.clone();
            // 每个任务独立 source：防爆破按来源计数，共享来源会被锁定短路
            let source = format!("10.0.0.{i}");
            handles.push(tokio::spawn(async move {
                h.redeem(&code, &format!("user-{i}"), &source).await
            }));
        }
        let mut successes = 0usize;
        let mut not_founds = 0usize;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(_) => successes += 1,
                Err(GarrisonError::InvalidParam(m))
                    if m.starts_with("invitation-code-not-found::") =>
                {
                    not_founds += 1;
                },
                Err(other) => panic!("并发消费不应出现其他错误: {other:?}"),
            }
        }
        assert_eq!(successes, 1, "单次码并发 32 消费应恰 1 成功");
        assert_eq!(not_founds, 31, "其余应 NotFound");
    }

    #[tokio::test]
    async fn redeem_normalizes_input() {
        let handler = make_handler();
        let record = handler.create(base_spec()).await.unwrap();
        let display = record.code.to_lowercase();
        let redeemed = handler
            .redeem(&display, "user-1", "10.0.0.1")
            .await
            .unwrap();
        assert_eq!(redeemed.code, record.code);
    }

    #[tokio::test]
    async fn redeem_rejects_invalid_code_format() {
        let handler = make_handler();
        let err = handler
            .redeem("AB@C-9XYZ", "user-1", "10.0.0.1")
            .await
            .unwrap_err();
        assert_invitation_err(err, "invitation-code-invalid::");
    }

    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn redeem_broadcasts_invitation_redeemed() {
        let (handler, sink) = make_handler_with_listener();
        let record = handler.create(base_spec()).await.unwrap();
        handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap();
        let events = sink.lock().unwrap();
        // create + redeem 各一条
        assert_eq!(events.len(), 2);
        match &events[1] {
            crate::listener::GarrisonEvent::InvitationRedeemed { code, redeemer_id } => {
                assert_eq!(code, &record.code);
                assert_eq!(redeemer_id, "user-1");
            },
            other => panic!("期望 InvitationRedeemed 事件，实际 {other:?}"),
        }
    }
}

// ============================================================================
// T006: 防爆破尝试锁定（limiter.rs + redeem 集成）
// ============================================================================

mod limiter_tests {
    use super::*;
    use crate::error::GarrisonError;
    use limiter::InvitationAttemptLimiter;

    fn assert_locked(err: GarrisonError) {
        match err {
            GarrisonError::InvalidParam(m) => {
                assert!(
                    m.starts_with("invitation-too-many-attempts::"),
                    "应返回 invitation-too-many-attempts:: 前缀错误，实际 {m}"
                );
            },
            other => panic!("期望 InvalidParam(too-many-attempts)，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_blocks_after_max_attempts() {
        let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(MockDao::new());
        let limiter = InvitationAttemptLimiter::with_config(dao, 3, 600);
        for i in 1..=3 {
            limiter
                .check("10.0.0.9")
                .await
                .unwrap_or_else(|e| panic!("第 {i} 次不应被锁: {e:?}"));
        }
        let err = limiter.check("10.0.0.9").await.unwrap_err();
        assert_locked(err);
        // 不同 source 互不影响
        assert!(limiter.check("10.0.0.10").await.is_ok());
    }

    #[tokio::test]
    async fn reset_clears_attempt_count() {
        let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(MockDao::new());
        let limiter = InvitationAttemptLimiter::with_config(dao, 2, 600);
        limiter.check("src-a").await.unwrap();
        limiter.check("src-a").await.unwrap();
        assert!(limiter.check("src-a").await.is_err());
        limiter.reset("src-a").await.unwrap();
        assert!(limiter.check("src-a").await.is_ok(), "reset 后应恢复通过");
        // 对无计数 source reset 幂等
        limiter.reset("never-seen").await.unwrap();
    }

    #[tokio::test]
    async fn redeem_locked_short_circuits_before_kv_access() {
        let handler = make_handler();
        let record = handler
            .create(InvitationSpec {
                issuer_id: "issuer-1".to_string(),
                tenant_id: None,
                bound_roles: vec![],
                max_uses: 100, // 大次数：锁定不是耗尽导致
                ttl_seconds: 600,
            })
            .await
            .unwrap();
        let source = "brute-src";
        // 默认阈值 10：先打满
        for _ in 0..10 {
            // 码不存在（NotFound）也会计数
            let _ = handler.redeem("ZZZZZZZZ", "user", source).await;
        }
        // 同 source 再 redeem 有效码：短路径锁定，不消费邀请码
        let err = handler
            .redeem(&record.code, "user-1", source)
            .await
            .unwrap_err();
        assert_locked(err);
        let report = handler.validate(&record.code).await.unwrap();
        assert!(report.is_valid(), "被锁定的 redeem 不得消费/修改邀请码");
        assert_eq!(report.record.unwrap().used_count, 0);
    }

    #[tokio::test]
    async fn redeem_success_resets_attempt_count() {
        let handler = make_handler();
        let record = handler
            .create(InvitationSpec {
                issuer_id: "issuer-1".to_string(),
                tenant_id: None,
                bound_roles: vec![],
                max_uses: 100,
                ttl_seconds: 600,
            })
            .await
            .unwrap();
        let source = "good-src";
        // 打满 9 次（默认阈值 10，第 10 次是上限内最后一次失败计数）
        for _ in 0..9 {
            let _ = handler.redeem("ZZZZZZZZ", "user", source).await;
        }
        // 第 10 次（计数=10，达到上限但未超）消费成功 → reset
        handler
            .redeem(&record.code, "user-1", source)
            .await
            .unwrap();
        // reset 后可继续正常 redeem（第 2 个新码）
        let second = handler
            .create(InvitationSpec {
                issuer_id: "issuer-1".to_string(),
                tenant_id: None,
                bound_roles: vec![],
                max_uses: 1,
                ttl_seconds: 600,
            })
            .await
            .unwrap();
        handler
            .redeem(&second.code, "user-2", source)
            .await
            .unwrap_or_else(|e| panic!("成功消费 reset 后不应被锁: {e:?}"));
    }
}

// ============================================================================
// T007: revoke 吊销与 list 列出（handler.rs）
// ============================================================================

mod revoke_list_tests {
    use super::*;

    #[tokio::test]
    async fn revoke_marks_record_and_validate_reports_revoked() {
        let handler = make_handler();
        let record = handler.create(base_spec()).await.unwrap();
        handler.revoke(&record.code, "issuer-1").await.unwrap();
        let report = handler.validate(&record.code).await.unwrap();
        assert_eq!(report.reason, Some(InvitationInvalidReason::Revoked));
        // 吊销后 redeem 被拒
        let err = handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap_err();
        match err {
            crate::error::GarrisonError::InvalidParam(m) => {
                assert!(m.starts_with("invitation-code-revoked::"), "实际 {m}");
            },
            other => panic!("期望 revoked 错误，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn revoke_is_idempotent() {
        let handler = make_handler();
        let record = handler.create(base_spec()).await.unwrap();
        handler.revoke(&record.code, "issuer-1").await.unwrap();
        // 重复吊销不报错
        handler.revoke(&record.code, "issuer-1").await.unwrap();
        let report = handler.validate(&record.code).await.unwrap();
        assert_eq!(report.reason, Some(InvitationInvalidReason::Revoked));
    }

    #[tokio::test]
    async fn revoke_unknown_code_returns_ok() {
        let handler = make_handler();
        handler.revoke("ZZZZZZZZ", "issuer-1").await.unwrap();
    }

    #[tokio::test]
    async fn revoke_rejects_invalid_format() {
        let handler = make_handler();
        let err = handler.revoke("AB@C", "issuer-1").await.unwrap_err();
        match err {
            crate::error::GarrisonError::InvalidParam(m) => {
                assert!(m.starts_with("invitation-code-invalid::"), "实际 {m}");
            },
            other => panic!("期望 invalid 错误，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_filters_by_issuer() {
        let handler = make_handler();
        let mine = handler.create(base_spec()).await.unwrap();
        let mine2 = handler.create(base_spec()).await.unwrap();
        let mut other_spec = base_spec();
        other_spec.issuer_id = "issuer-2".to_string();
        let theirs = handler.create(other_spec).await.unwrap();
        let listed = handler.list("issuer-1").await.unwrap();
        let codes: Vec<&str> = listed.iter().map(|r| r.code.as_str()).collect();
        assert!(codes.contains(&mine.code.as_str()));
        assert!(codes.contains(&mine2.code.as_str()));
        assert!(!codes.contains(&theirs.code.as_str()), "不应含他人邀请码");
    }

    #[tokio::test]
    async fn list_excludes_redeemed_single_use_record() {
        let handler = make_handler();
        let record = handler.create(base_spec()).await.unwrap();
        handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap();
        let listed = handler.list("issuer-1").await.unwrap();
        assert!(
            listed.is_empty(),
            "单次码消费即删除，list 不应返回: {:?}",
            listed.iter().map(|r| r.code.clone()).collect::<Vec<_>>()
        );
    }

    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn revoke_broadcasts_invitation_revoked() {
        let (handler, sink) = make_handler_with_listener();
        let record = handler.create(base_spec()).await.unwrap();
        handler.revoke(&record.code, "issuer-1").await.unwrap();
        let events = sink.lock().unwrap();
        assert_eq!(events.len(), 2);
        match &events[1] {
            crate::listener::GarrisonEvent::InvitationRevoked { code, issuer_id } => {
                assert_eq!(code, &record.code);
                assert_eq!(issuer_id, "issuer-1");
            },
            other => panic!("期望 InvitationRevoked 事件，实际 {other:?}"),
        }
    }

    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn revoke_unknown_code_does_not_broadcast() {
        let (handler, sink) = make_handler_with_listener();
        handler.revoke("ZZZZZZZZ", "issuer-1").await.unwrap();
        let events = sink.lock().unwrap();
        assert!(events.is_empty(), "未知码幂等路径不应广播: {:?}", *events);
    }
}

// ============================================================================
// T009: 注册编排钩子 InvitationRedeemHook（mod.rs + handler.rs）
// ============================================================================

mod hook_tests {
    use super::*;
    use crate::error::GarrisonError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 可编程结果的 mock hook：记录调用次数，前 `fail_times` 次失败后转成功
    /// （模拟"应用侧账号创建故障排除后重试成功"）。
    struct MockHook {
        calls: AtomicUsize,
        fail_times: AtomicUsize,
    }

    impl MockHook {
        fn ok() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail_times: AtomicUsize::new(0),
            }
        }
        fn failing_once() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail_times: AtomicUsize::new(1),
            }
        }
        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl InvitationRedeemHook for MockHook {
        async fn on_redeem(&self, record: &InvitationRecord) -> crate::error::GarrisonResult<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self
                .fail_times
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    if n > 0 {
                        Some(n - 1)
                    } else {
                        None
                    }
                })
                == Ok(1)
            {
                return Err(GarrisonError::Dao(
                    "hook-account-creation-failed::".to_string(),
                ));
            }
            assert!(
                record.used_count >= 1,
                "hook 回调时 used_count 应已含本次消费"
            );
            Ok(())
        }
    }

    #[tokio::test]
    async fn hook_success_redeem_completes_with_updated_count() {
        let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(MockDao::new());
        let hook = Arc::new(MockHook::ok());
        let handler = InvitationHandler::new(dao).with_hook(hook.clone());
        let record = handler.create(base_spec()).await.unwrap();
        let redeemed = handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap();
        assert_eq!(redeemed.used_count, 1);
        assert_eq!(hook.call_count(), 1, "hook 应被调用一次");
    }

    #[tokio::test]
    async fn hook_failure_propagates_and_rolls_back_count() {
        let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(MockDao::new());
        let hook = Arc::new(MockHook::failing_once());
        let handler = InvitationHandler::new(dao).with_hook(hook);
        let record = handler.create(base_spec()).await.unwrap();
        let err = handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap_err();
        match err {
            GarrisonError::Dao(m) => {
                assert!(m.starts_with("hook-account-creation-failed::"), "实际 {m}");
            },
            other => panic!("期望 hook 错误传播，实际 {other:?}"),
        }
        // 计数回滚：码未被吞掉，validate 显示 used_count=0 未耗尽，可重试
        let report = handler.validate(&record.code).await.unwrap();
        assert!(report.is_valid(), "hook 失败后邀请码应回滚为可重试");
        assert_eq!(report.record.unwrap().used_count, 0);
        // 修正后重试成功
        let retry = handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap();
        assert_eq!(retry.used_count, 1);
    }

    #[tokio::test]
    async fn no_hook_behaves_like_hook_success() {
        let handler = make_handler();
        let record = handler.create(base_spec()).await.unwrap();
        let redeemed = handler
            .redeem(&record.code, "user-1", "10.0.0.1")
            .await
            .unwrap();
        assert_eq!(redeemed.used_count, 1);
    }
}

// ============================================================================
// T010: 错误消息 i18n（locales/{zh,en}.ftl）
// ============================================================================

#[cfg(feature = "i18n-icu")]
mod i18n_tests {
    use super::*;
    use crate::error::GarrisonError;
    use crate::i18n::{set_locale, translate_error, GarrisonLocale};

    /// 全部 invitation 错误 key 对应的 InvalidParam 构造（key::arg 形态）。
    fn invitation_errors() -> Vec<GarrisonError> {
        vec![
            GarrisonError::InvalidParam("invitation-code-invalid::@".to_string()),
            GarrisonError::InvalidParam("invitation-code-collision::".to_string()),
            GarrisonError::InvalidParam("invitation-code-not-found::".to_string()),
            GarrisonError::InvalidParam("invitation-code-expired::".to_string()),
            GarrisonError::InvalidParam("invitation-code-revoked::AB3C9XYZ".to_string()),
            GarrisonError::InvalidParam("invitation-code-exhausted::AB3C9XYZ".to_string()),
            GarrisonError::InvalidParam("invitation-too-many-attempts::10.0.0.1".to_string()),
            GarrisonError::InvalidParam("invitation-ttl-invalid::".to_string()),
            GarrisonError::InvalidParam("invitation-max-uses-invalid::".to_string()),
            GarrisonError::InvalidParam("invitation-count-invalid::".to_string()),
            GarrisonError::InvalidParam("invitation-serialize-failed::x".to_string()),
        ]
    }

    fn assert_all_translated(locale: GarrisonLocale, forbid: Option<&str>) {
        let _guard = set_locale(locale);
        for err in invitation_errors() {
            let translated = translate_error(&err);
            assert!(!translated.is_empty(), "{locale:?}: {err:?} 翻译不应为空");
            assert!(
                !translated.contains("invitation-"),
                "{locale:?}: {err:?} 应翻译为文本而非回退 key，实际 {translated:?}"
            );
            if let Some(forbid) = forbid {
                assert!(
                    !translated.contains(forbid),
                    "{locale:?}: {err:?} 翻译不应含 {forbid}，实际 {translated:?}"
                );
            }
        }
    }

    #[test]
    fn all_invitation_keys_translate_in_zh() {
        // zh 翻译应输出中文（含 CJK 字符）
        assert_all_translated(GarrisonLocale::Zh, None);
        let _guard = set_locale(GarrisonLocale::Zh);
        for err in invitation_errors() {
            let translated = translate_error(&err);
            assert!(
                translated.chars().any(|c| !c.is_ascii()),
                "zh 翻译应含非 ASCII（中文）字符，实际 {translated:?}"
            );
        }
    }

    #[test]
    fn all_invitation_keys_translate_in_en() {
        // en 翻译应输出英文（不含中文）
        assert_all_translated(GarrisonLocale::En, Some("邀请"));
    }

    #[test]
    fn redeem_error_translates_with_arg() {
        let _guard = set_locale(GarrisonLocale::Zh);
        let err = GarrisonError::InvalidParam("invitation-code-revoked::AB3C9XYZ".to_string());
        let translated = translate_error(&err);
        assert!(
            translated.contains("AB3C9XYZ"),
            "arg 应被格式化进翻译文本，实际 {translated:?}"
        );
    }
}

// ============================================================================
// T012: 覆盖率补齐（consumable 便捷方法 / 脏数据防御分支 / 碰撞重试 / 批量广播）
// ============================================================================

mod coverage_tests {
    use super::*;
    use crate::error::GarrisonError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ----------------------------------------------------------------
    // mod.rs：InvitationRecord::consumable
    // ----------------------------------------------------------------

    #[test]
    fn consumable_reflects_status_expiry_and_budget() {
        let now = handler::unix_now();
        let mut record = InvitationRecord {
            code: "AB2C9XYZ".to_string(),
            issuer_id: "issuer-1".to_string(),
            tenant_id: None,
            bound_roles: vec![],
            max_uses: 3,
            used_count: 0,
            redeemed_by: vec![],
            created_at: now,
            expires_at: now + 600,
            status: InvitationStatus::Active,
        };
        assert!(record.consumable(now));
        // 吊销后不可消费
        record.status = InvitationStatus::Revoked;
        assert!(!record.consumable(now));
        record.status = InvitationStatus::Active;
        // 过期（now == expires_at 视为过期）不可消费
        assert!(!record.consumable(record.expires_at));
        // 次数耗尽不可消费
        record.used_count = 3;
        assert!(!record.consumable(now));
    }

    // ----------------------------------------------------------------
    // 脏数据防御分支（KV 中非合法 JSON 的记录按 NotFound / 跳过处理）
    // ----------------------------------------------------------------

    /// 向 KV 直接写入脏数据条目。
    async fn seed_dirty(handler: &InvitationHandler, code: &str) {
        let key = format!("garrison:invitation:code:{}", code);
        handler
            .dao
            .set(&key, "not-a-valid-json", 600)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn validate_dirty_json_reports_not_found() {
        let handler = make_handler();
        seed_dirty(&handler, "AB2C9XDQ").await;
        let report = handler.validate("AB2C9XDQ").await.unwrap();
        assert_eq!(report.reason, Some(InvitationInvalidReason::NotFound));
        assert!(report.record.is_none());
    }

    #[tokio::test]
    async fn redeem_dirty_json_reports_not_found() {
        let handler = make_handler();
        seed_dirty(&handler, "CD3C9XD2").await;
        let err = handler
            .redeem("CD3C9XD2", "user-1", "10.0.0.1")
            .await
            .unwrap_err();
        match err {
            GarrisonError::InvalidParam(m) => {
                assert!(m.starts_with("invitation-code-not-found::"), "实际 {m}");
            },
            other => panic!("期望 not-found 错误，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn revoke_dirty_json_returns_ok() {
        let handler = make_handler();
        seed_dirty(&handler, "EF4C9XD3").await;
        handler.revoke("EF4C9XD3", "issuer-1").await.unwrap();
    }

    #[tokio::test]
    async fn list_skips_dirty_and_expired_entries() {
        // 保留具体类型引用以便直接操纵 mock 数据
        let mock = Arc::new(MockDao::new());
        let handler = InvitationHandler::new(mock.clone() as Arc<dyn crate::dao::GarrisonDao>);
        let record = handler.create(base_spec()).await.unwrap();
        seed_dirty(&handler, "XY9C9XD4").await;
        // 直接构造 KV 中 deadline 已过期的条目：keys 枚举到但 get 返回 None
        {
            let mut data = mock.data.lock().await;
            data.insert(
                "garrison:invitation:code:OV8C9XD5".to_string(),
                ("{\"code\":\"OV8C9XD5\"}".to_string(), None),
            );
            // 将该条目的 deadline 置为过去（mock get 判定过期返回 None）
            data.get_mut("garrison:invitation:code:OV8C9XD5").unwrap().1 =
                Some(std::time::Instant::now() - Duration::from_secs(1));
        }
        let listed = handler.list("issuer-1").await.unwrap();
        assert_eq!(listed.len(), 1, "应只返回合法且未过期记录");
        assert_eq!(listed[0].code, record.code);
    }

    // ----------------------------------------------------------------
    // create_batch：listener 广播
    // ----------------------------------------------------------------

    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn create_batch_broadcasts_per_record() {
        let (handler, sink) = make_handler_with_listener();
        let records = handler.create_batch(base_spec(), 3).await.unwrap();
        let events = sink.lock().unwrap();
        assert_eq!(events.len(), 3, "每条批量签发各广播一次");
        for (i, event) in events.iter().enumerate() {
            match event {
                crate::listener::GarrisonEvent::InvitationCreated { code, .. } => {
                    assert_eq!(code, &records[i].code);
                },
                other => panic!("期望 InvitationCreated，实际 {other:?}"),
            }
        }
    }

    // ----------------------------------------------------------------
    // create：set_if_absent 碰撞重试与耗尽
    // ----------------------------------------------------------------

    /// set_if_absent 注入失败的 DAO：前 `failures` 次返回 false（模拟键碰撞）。
    struct CollisionDao {
        inner: MockDao,
        failures: AtomicUsize,
    }

    impl CollisionDao {
        fn failing(times: usize) -> Self {
            Self {
                inner: MockDao::new(),
                failures: AtomicUsize::new(times),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::dao::GarrisonDao for CollisionDao {
        async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
            self.inner.get(key).await
        }
        async fn set(&self, key: &str, value: &str, ttl: u64) -> GarrisonResult<()> {
            self.inner.set(key, value, ttl).await
        }
        async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
            self.inner.update(key, value).await
        }
        async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
            self.inner.expire(key, seconds).await
        }
        async fn delete(&self, key: &str) -> GarrisonResult<()> {
            self.inner.delete(key).await
        }
        async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
            self.inner.get_and_delete(key).await
        }
        async fn get_with_ttl(
            &self,
            key: &str,
        ) -> GarrisonResult<Option<(String, Option<Duration>)>> {
            self.inner.get_with_ttl(key).await
        }
        async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
            self.inner.keys(pattern).await
        }
        async fn set_if_absent(
            &self,
            key: &str,
            value: &str,
            ttl_seconds: u64,
        ) -> GarrisonResult<bool> {
            // 预算内返回 false 模拟键碰撞；预算耗尽后正常写入成功
            if self.failures.fetch_sub(1, Ordering::SeqCst) > 0 {
                return Ok(false);
            }
            self.inner.set(key, value, ttl_seconds).await?;
            Ok(true)
        }
        // 其余原子方法委托内部 mock（宏展开实现）
        async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
            self.inner.rename(old_key, new_key).await
        }
        async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
            self.inner.incr(key, ttl_seconds).await
        }
        async fn decr(&self, key: &str) -> GarrisonResult<u64> {
            self.inner.decr(key).await
        }
        async fn compare_and_swap(
            &self,
            key: &str,
            expected: Option<&str>,
            new_value: &str,
            ttl_seconds: u64,
        ) -> GarrisonResult<bool> {
            self.inner
                .compare_and_swap(key, expected, new_value, ttl_seconds)
                .await
        }
    }

    #[tokio::test]
    async fn create_collision_retry_succeeds_after_conflicts() {
        // 前 2 次碰撞，第 3 次（上限内）成功
        let dao = Arc::new(CollisionDao::failing(2));
        let handler = InvitationHandler::new(dao);
        let record = handler.create(base_spec()).await.unwrap();
        assert!(!record.code.is_empty());
    }

    #[tokio::test]
    async fn create_collision_exhausted_retries_returns_error() {
        // 恒碰撞：3 次重试耗尽 → invitation-code-collision::
        let dao = Arc::new(CollisionDao::failing(usize::MAX));
        let handler = InvitationHandler::new(dao);
        let err = handler.create(base_spec()).await.unwrap_err();
        match err {
            GarrisonError::InvalidParam(m) => {
                assert!(m.starts_with("invitation-code-collision::"), "实际 {m}");
            },
            other => panic!("期望 collision 错误，实际 {other:?}"),
        }
    }
}
