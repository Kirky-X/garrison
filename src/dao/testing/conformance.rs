// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 契约组断言函数库（同一把尺子）：每个函数断言一个能力层下所有 `GarrisonDao` 实现都应满足的行为属性；
//! 键名由调用方传入的 `prefix` 隔离（套件用 `<backend>:`），断言消息均携带 `prefix` 便于失败定位。
//!
//! 断言按安全属性组织：并发层的「恰一赢家（SETNX 防并发绑定重复）/ 一次性消费（GETDEL 防票券双花）/
//! 计数无丢失与无跨越式递减（防限速绕过）/ CAS 单调（防备份码双花、Digest nc 回退）」即 TOCTOU/双花缓解的持续回归门禁。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use std::sync::Arc;
use std::time::Duration;

/// 提取 `Ok`；`Err` 时 panic 并携带 prefix 上下文（fail-loud，禁止吞错）。
///
/// `what` 为标签 key：命中 FTL 时按当前 locale 输出（如 `dao-conformance-what-set-overwrite`），
/// 未命中（纯英文标签，如 `set`/`get`）由 `translate_detail` 原样返回，等价于直传文本。
fn expect_ok<T>(prefix: &str, what: &str, r: GarrisonResult<T>) -> T {
    r.unwrap_or_else(|e| {
        let what = crate::i18n::translate_detail(what, &[]);
        let error = e.to_string();
        panic!(
            "{}",
            crate::i18n::translate_detail(
                "dao-conformance-expect-ok-failed",
                &[
                    ("prefix", prefix),
                    ("what", what.as_str()),
                    ("error", error.as_str()),
                ]
            )
        )
    })
}

/// 断言结果为 `Err` 且匹配给定变体模式，否则 panic（`$msg` 为 FTL 标签 key）。
macro_rules! expect_err {
    ($prefix:expr, $r:expr, $pat:pat, $msg:expr) => {
        assert!(
            matches!($r, Err($pat)),
            "{}",
            crate::i18n::translate_detail(
                "dao-conformance-expect-err-failed",
                &[
                    ("prefix", $prefix),
                    ("what", crate::i18n::translate_detail($msg, &[]).as_str()),
                    ("actual", format!("{:?}", $r).as_str()),
                ]
            )
        );
    };
}

// basic 层：单线程 KV / 计数 / rename 契约

/// basic 层契约：核心 KV 语义 + 计数器 + rename（含各错误路径显性化；rename 缺键报 `InvalidParam`）。
pub async fn run_basic(dao: &Arc<dyn GarrisonDao>, prefix: &str) {
    let k = format!("{prefix}basic:roundtrip");
    expect_ok(prefix, "set", dao.set(&k, "v1", 3600).await);
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some("v1"),
        "[{prefix}] set→get 应往返精确值"
    );
    expect_ok(
        prefix,
        "dao-conformance-what-set-overwrite",
        dao.set(&k, "v2", 3600).await,
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some("v2"),
        "[{prefix}] 二次 set 应覆盖值"
    );

    let missing = format!("{prefix}basic:missing");
    assert_eq!(
        expect_ok(
            prefix,
            "dao-conformance-what-get-missing-key",
            dao.get(&missing).await
        ),
        None,
        "[{prefix}] get 缺键应返回 Ok(None)"
    );

    let k = format!("{prefix}basic:delete");
    expect_ok(prefix, "set", dao.set(&k, "v", 60).await);
    expect_ok(prefix, "delete", dao.delete(&k).await);
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await),
        None,
        "[{prefix}] delete 后键应不存在"
    );
    expect_ok(
        prefix,
        "dao-conformance-what-delete-missing-key",
        dao.delete(&missing).await,
    );

    let k = format!("{prefix}basic:update");
    expect_ok(prefix, "set", dao.set(&k, "old", 3600).await);
    expect_ok(prefix, "update", dao.update(&k, "new").await);
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some("new"),
        "[{prefix}] update 应改值"
    );
    let r = dao.update(&missing, "v").await;
    expect_err!(
        prefix,
        r,
        GarrisonError::Dao(_),
        "dao-conformance-expect-err-update-missing-key"
    );

    let k = format!("{prefix}basic:expire");
    expect_ok(prefix, "set", dao.set(&k, "v", 1).await);
    expect_ok(prefix, "expire", dao.expire(&k, 3600).await);
    let ttl = expect_ok(prefix, "get_timeout", dao.get_timeout(&k).await);
    assert!(
        matches!(ttl, Some(d) if d <= Duration::from_secs(3600)),
        "[{prefix}] expire 延长后 get_timeout 应返回 Some(≤新 TTL)，实际: {:?}",
        ttl
    );
    let r = dao.expire(&missing, 60).await;
    expect_err!(
        prefix,
        r,
        GarrisonError::Dao(_),
        "dao-conformance-expect-err-expire-missing-key"
    );

    let k1 = format!("{prefix}basic:perm_set_zero");
    expect_ok(prefix, "set(ttl=0)", dao.set(&k1, "v", 0).await);
    assert_eq!(
        expect_ok(prefix, "get_timeout", dao.get_timeout(&k1).await),
        None,
        "[{prefix}] set(ttl=0) 应为永久键"
    );
    let k2 = format!("{prefix}basic:perm_api");
    expect_ok(prefix, "set_permanent", dao.set_permanent(&k2, "v").await);
    assert_eq!(
        expect_ok(prefix, "get_timeout", dao.get_timeout(&k2).await),
        None,
        "[{prefix}] set_permanent 应为永久键"
    );

    let kt = format!("{prefix}basic:get_with_ttl_key");
    expect_ok(prefix, "set", dao.set(&kt, "v", 60).await);
    let got = expect_ok(prefix, "get_with_ttl", dao.get_with_ttl(&kt).await);
    assert!(
        matches!(&got, Some((v, Some(d))) if v == "v" && *d <= Duration::from_secs(60)),
        "[{prefix}] TTL 键 get_with_ttl 应返回 Some((v, Some(≤ttl)))，实际: {:?}",
        got
    );
    let kp = format!("{prefix}basic:get_with_ttl_perm");
    expect_ok(prefix, "set_permanent", dao.set_permanent(&kp, "pv").await);
    let got = expect_ok(prefix, "get_with_ttl", dao.get_with_ttl(&kp).await);
    assert!(
        matches!(&got, Some((v, None)) if v == "pv"),
        "[{prefix}] 永久键 get_with_ttl 应返回 Some((v, None))，实际: {:?}",
        got
    );
    assert_eq!(
        expect_ok(
            prefix,
            "get_with_ttl 缺键",
            dao.get_with_ttl(&missing).await
        ),
        None,
        "[{prefix}] get_with_ttl 缺键应返回 None"
    );

    let k = format!("{prefix}basic:incr");
    assert_eq!(
        expect_ok(
            prefix,
            "dao-conformance-what-incr-new-key",
            dao.incr(&k, 60).await
        ),
        1,
        "[{prefix}] incr 新键应初始化为 1"
    );
    assert!(
        expect_ok(prefix, "get_timeout", dao.get_timeout(&k).await).is_some(),
        "[{prefix}] incr 新键应设置 TTL"
    );
    assert_eq!(
        expect_ok(
            prefix,
            "dao-conformance-what-incr-increment",
            dao.incr(&k, 60).await
        ),
        2,
        "[{prefix}] 续增应返回 2"
    );
    let kbad = format!("{prefix}basic:incr_non_numeric");
    expect_ok(prefix, "set", dao.set(&kbad, "abc", 60).await);
    let r = dao.incr(&kbad, 60).await;
    expect_err!(
        prefix,
        r,
        GarrisonError::Dao(_),
        "dao-conformance-expect-err-incr-non-numeric"
    );
    let kmax = format!("{prefix}basic:incr_overflow");
    expect_ok(
        prefix,
        "set",
        dao.set(&kmax, &u64::MAX.to_string(), 60).await,
    );
    let r = dao.incr(&kmax, 60).await;
    expect_err!(
        prefix,
        r,
        GarrisonError::Dao(_),
        "dao-conformance-expect-err-incr-overflow"
    );

    let kmissing = format!("{prefix}basic:decr_missing");
    assert_eq!(
        expect_ok(
            prefix,
            "dao-conformance-what-decr-missing-key",
            dao.decr(&kmissing).await
        ),
        0,
        "[{prefix}] decr 缺键应返回 0"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&kmissing).await),
        None,
        "[{prefix}] decr 缺键不应创建键"
    );
    let kzero = format!("{prefix}basic:decr_zero");
    expect_ok(prefix, "set", dao.set(&kzero, "0", 60).await);
    assert_eq!(
        expect_ok(
            prefix,
            "dao-conformance-what-decr-zero",
            dao.decr(&kzero).await
        ),
        0,
        "[{prefix}] 存量值 0 的 decr 应返回 0（不递减为负）"
    );
    let kone = format!("{prefix}basic:decr_to_zero");
    expect_ok(prefix, "set", dao.set(&kone, "1", 60).await);
    assert_eq!(
        expect_ok(prefix, "decr", dao.decr(&kone).await),
        0,
        "[{prefix}] 1→0 的 decr 应返回 0"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&kone).await),
        None,
        "[{prefix}] 递减后值为 0 应删除键"
    );
    let kttl = format!("{prefix}basic:decr_keeps_ttl");
    expect_ok(prefix, "set", dao.set(&kttl, "5", 100).await);
    assert_eq!(
        expect_ok(prefix, "decr", dao.decr(&kttl).await),
        4,
        "[{prefix}] 5→4 的 decr 应返回 4"
    );
    assert!(
        expect_ok(prefix, "get_timeout", dao.get_timeout(&kttl).await).is_some(),
        "[{prefix}] 递减后值 >0 应保留 TTL 元数据"
    );

    let k = format!("{prefix}basic:caui");
    assert!(
        expect_ok(
            prefix,
            "caui 缺键",
            dao.compare_and_update_if_greater(&k, 7, 60).await
        ),
        "[{prefix}] 缺键时写入更大值应返回 true"
    );
    let ttl = expect_ok(prefix, "get_timeout", dao.get_timeout(&k).await);
    assert!(
        matches!(ttl, Some(d) if d <= Duration::from_secs(60)),
        "[{prefix}] compare_and_update_if_greater 创建键应设置 TTL，实际: {:?}",
        ttl
    );
    assert!(
        !expect_ok(
            prefix,
            "caui 更小值",
            dao.compare_and_update_if_greater(&k, 3, 60).await
        ),
        "[{prefix}] 更小值应返回 false"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some("7"),
        "[{prefix}] 更小值不应覆盖"
    );
    let kbad = format!("{prefix}basic:caui_non_numeric");
    expect_ok(prefix, "set", dao.set(&kbad, "abc", 60).await);
    let r = dao.compare_and_update_if_greater(&kbad, 7, 60).await;
    expect_err!(
        prefix,
        r,
        GarrisonError::Dao(_),
        "dao-conformance-expect-err-caui-non-numeric"
    );

    let old = format!("{prefix}basic:rename_old");
    let new = format!("{prefix}basic:rename_new");
    expect_ok(prefix, "set", dao.set(&old, "v", 60).await);
    expect_ok(prefix, "rename", dao.rename(&old, &new).await);
    assert_eq!(
        expect_ok(
            prefix,
            "dao-conformance-what-get-old-key",
            dao.get(&old).await
        ),
        None,
        "[{prefix}] rename 后旧键应消失"
    );
    assert_eq!(
        expect_ok(
            prefix,
            "dao-conformance-what-get-new-key",
            dao.get(&new).await
        )
        .as_deref(),
        Some("v"),
        "[{prefix}] rename 后新键应保留值"
    );
    let r = dao
        .rename(&missing, &format!("{prefix}basic:rename_any"))
        .await;
    expect_err!(
        prefix,
        r,
        GarrisonError::InvalidParam(_),
        "dao-conformance-expect-err-rename-missing-key"
    );
}

// atomic 层：原子原语单线程语义

/// atomic 层契约：set_if_absent / get_and_delete / compare_and_swap 的单线程原子语义（含过期键接管；并发竞态见 `run_concurrent`）。
pub async fn run_atomic(dao: &Arc<dyn GarrisonDao>, prefix: &str) {
    let k = format!("{prefix}atomic:sia");
    assert!(
        expect_ok(
            prefix,
            "set_if_absent 新键",
            dao.set_if_absent(&k, "v", 60).await
        ),
        "[{prefix}] 新键 set_if_absent 应返回 true"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some("v"),
        "[{prefix}] set_if_absent 成功后应写入值"
    );
    assert!(
        expect_ok(prefix, "get_timeout", dao.get_timeout(&k).await).is_some(),
        "[{prefix}] set_if_absent(ttl>0) 应设置 TTL"
    );

    // set_if_absent 已存在键：false 且不覆盖
    assert!(
        !expect_ok(
            prefix,
            "set_if_absent 已存在",
            dao.set_if_absent(&k, "other", 60).await
        ),
        "[{prefix}] 已存在键 set_if_absent 应返回 false"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some("v"),
        "[{prefix}] set_if_absent 失败不应覆盖原值"
    );

    // set_if_absent(ttl=0)：永久键
    let k0 = format!("{prefix}atomic:sia_perm");
    assert!(
        expect_ok(
            prefix,
            "set_if_absent(ttl=0)",
            dao.set_if_absent(&k0, "v", 0).await
        ),
        "[{prefix}] 新键 set_if_absent(ttl=0) 应返回 true"
    );
    assert_eq!(
        expect_ok(prefix, "get_timeout", dao.get_timeout(&k0).await),
        None,
        "[{prefix}] set_if_absent(ttl=0) 应为永久键"
    );

    // get_and_delete：存在键返回 Some 并删除；缺键 None
    let k = format!("{prefix}atomic:gd");
    expect_ok(prefix, "set", dao.set(&k, "v", 60).await);
    assert_eq!(
        expect_ok(prefix, "get_and_delete", dao.get_and_delete(&k).await).as_deref(),
        Some("v"),
        "[{prefix}] get_and_delete 应返回键值"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await),
        None,
        "[{prefix}] get_and_delete 后键应删除"
    );
    assert_eq!(
        expect_ok(
            prefix,
            "dao-conformance-what-gd-missing-key",
            dao.get_and_delete(&k).await
        ),
        None,
        "[{prefix}] get_and_delete 缺键应返回 None"
    );

    // compare_and_swap：期望匹配 true 并写入；不匹配 false 且值不变；
    // expected=None 缺键创建；缺键 expected=Some false
    let k = format!("{prefix}atomic:cas");
    expect_ok(prefix, "set", dao.set(&k, "old", 60).await);
    assert!(
        !expect_ok(
            prefix,
            "cas 不匹配",
            dao.compare_and_swap(&k, Some("mismatch"), "new", 60).await
        ),
        "[{prefix}] 期望值不匹配应返回 false"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some("old"),
        "[{prefix}] CAS 失败不应改值"
    );
    assert!(
        expect_ok(
            prefix,
            "cas 匹配",
            dao.compare_and_swap(&k, Some("old"), "new", 60).await
        ),
        "[{prefix}] 期望值匹配应返回 true"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some("new"),
        "[{prefix}] CAS 成功应写入新值"
    );
    let kabsent = format!("{prefix}atomic:cas_absent");
    assert!(
        expect_ok(
            prefix,
            "cas expected=None",
            dao.compare_and_swap(&kabsent, None, "created", 60).await
        ),
        "[{prefix}] 缺键 expected=None 的 CAS 应创建键并返回 true"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&kabsent).await).as_deref(),
        Some("created"),
        "[{prefix}] CAS 创建的键应有值"
    );
    let kmissing = format!("{prefix}atomic:cas_missing");
    assert!(
        !expect_ok(
            prefix,
            "cas 缺键",
            dao.compare_and_swap(&kmissing, Some("v"), "n", 60).await
        ),
        "[{prefix}] 缺键 expected=Some 的 CAS 应返回 false"
    );

    // 过期键接管（过期视为不存在）：set(ttl=1) + 一次 sleep(3s) 窗口，对齐 run_ttl「每测试仅 1 次 sleep」惯例
    let k = format!("{prefix}atomic:sia_expired");
    expect_ok(prefix, "set", dao.set(&k, "stale", 1).await);
    let k_cas = format!("{prefix}atomic:cas_expired_none");
    expect_ok(prefix, "set", dao.set(&k_cas, "stale", 1).await);
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        expect_ok(
            prefix,
            "set_if_absent 过期键接管",
            dao.set_if_absent(&k, "fresh", 60).await
        ),
        "[{prefix}] 过期键 set_if_absent 应返回 true（过期视为不存在）"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some("fresh"),
        "[{prefix}] 过期键 set_if_absent 接管后应写入新值"
    );

    assert!(
        expect_ok(
            prefix,
            "cas(None) 过期键接管",
            dao.compare_and_swap(&k_cas, None, "created", 60).await
        ),
        "[{prefix}] compare_and_swap(None) 对过期键应接管返回 true"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k_cas).await).as_deref(),
        Some("created"),
        "[{prefix}] CAS 过期键接管后应写入新值"
    );
}

// concurrent 层：真并发竞态（安全属性回归门禁）

/// concurrent 层契约：multi_thread 真并发下的原子性不变式，断言精确计数（不放宽为 ≥1）：
/// set_if_absent 16 任务恰 1 个 `Ok(true)`（SETNX 恰一赢家）／get_and_delete 16 任务恰 1 个 `Some`（GETDEL 防票券双花）／
/// incr 32 任务返回值恰为 `1..=32` 排列（无丢失更新）／decr 16 任务（预置 16）返回值恰为 `0..=15` 排列（无跨越式递减，SMS 限速 flaky 回归签名）且终态键删除／
/// compare_and_update_if_greater 16 任务互异值终值恰为 max（Digest nc 单调）／compare_and_swap 16 任务同 expected 恰 1 个 true，终值等于唯一赢家。
pub async fn run_concurrent(dao: &Arc<dyn GarrisonDao>, prefix: &str) {
    let k = format!("{prefix}concurrent:sia");
    let mut handles = Vec::with_capacity(16);
    for i in 0..16u32 {
        let d = Arc::clone(dao);
        let k = k.clone();
        handles.push(tokio::spawn(async move {
            d.set_if_absent(&k, &format!("winner_{i}"), 3600).await
        }));
    }
    let mut ok_true = 0;
    let mut ok_false = 0;
    for h in handles {
        match h.await.unwrap_or_else(|e| {
            panic!(
                "{}: {e}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-sia-join-failed",
                    &[("prefix", prefix)],
                )
            )
        }) {
            Ok(true) => ok_true += 1,
            Ok(false) => ok_false += 1,
            Err(e) => panic!(
                "{}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-sia-error",
                    &[("prefix", prefix), ("error", e.to_string().as_str())]
                )
            ),
        }
    }
    assert_eq!(
        ok_true, 1,
        "[{prefix}] set_if_absent 并发应恰 1 个赢家（SETNX），实际 {ok_true}"
    );
    assert_eq!(
        ok_false, 15,
        "[{prefix}] set_if_absent 并发其余应返回 false，实际 {ok_false}"
    );
    let v = expect_ok(prefix, "get", dao.get(&k).await);
    assert!(
        matches!(v.as_deref(), Some(w) if w.starts_with("winner_")),
        "[{prefix}] 回读值应等于恰好一个任务写入的 winner_*，实际: {v:?}"
    );

    let k = format!("{prefix}concurrent:gd");
    expect_ok(prefix, "set", dao.set(&k, "ticket", 3600).await);
    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let d = Arc::clone(dao);
        let k = k.clone();
        handles.push(tokio::spawn(async move { d.get_and_delete(&k).await }));
    }
    let mut got_some = 0;
    let mut got_none = 0;
    for h in handles {
        match h.await.unwrap_or_else(|e| {
            panic!(
                "{}: {e}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-gd-join-failed",
                    &[("prefix", prefix)],
                )
            )
        }) {
            Ok(Some(_)) => got_some += 1,
            Ok(None) => got_none += 1,
            Err(e) => panic!(
                "{}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-gd-error",
                    &[("prefix", prefix), ("error", e.to_string().as_str())]
                )
            ),
        }
    }
    assert_eq!(
        got_some, 1,
        "[{prefix}] get_and_delete 并发应恰 1 个消费到值（GETDEL 防双花），实际 {got_some}"
    );
    assert_eq!(
        got_none, 15,
        "[{prefix}] get_and_delete 并发其余应返回 None，实际 {got_none}"
    );

    let k = format!("{prefix}concurrent:incr");
    let mut handles = Vec::with_capacity(32);
    for _ in 0..32 {
        let d = Arc::clone(dao);
        let k = k.clone();
        handles.push(tokio::spawn(async move { d.incr(&k, 3600).await }));
    }
    let mut results = Vec::with_capacity(32);
    for h in handles {
        match h.await.unwrap_or_else(|e| {
            panic!(
                "{}: {e}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-incr-join-failed",
                    &[("prefix", prefix)],
                )
            )
        }) {
            Ok(v) => results.push(v),
            Err(e) => panic!(
                "{}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-incr-error",
                    &[("prefix", prefix), ("error", e.to_string().as_str())]
                )
            ),
        }
    }
    results.sort_unstable();
    let expected: Vec<u64> = (1..=32).collect();
    assert_eq!(
        results, expected,
        "[{prefix}] incr 并发返回值应恰为 1..=32 的排列（无丢失更新）"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some("32"),
        "[{prefix}] incr 并发终值应为 32"
    );

    let k = format!("{prefix}concurrent:decr");
    expect_ok(prefix, "set", dao.set(&k, "16", 3600).await);
    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let d = Arc::clone(dao);
        let k = k.clone();
        handles.push(tokio::spawn(async move { d.decr(&k).await }));
    }
    let mut results = Vec::with_capacity(16);
    for h in handles {
        match h.await.unwrap_or_else(|e| {
            panic!(
                "{}: {e}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-decr-join-failed",
                    &[("prefix", prefix)],
                )
            )
        }) {
            Ok(v) => results.push(v),
            Err(e) => panic!(
                "{}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-decr-error",
                    &[("prefix", prefix), ("error", e.to_string().as_str())]
                )
            ),
        }
    }
    results.sort_unstable();
    let expected: Vec<u64> = (0..=15).collect();
    assert_eq!(
        results, expected,
        "[{prefix}] decr 并发返回值应恰为 0..=15 的排列（无跨越式递减）"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await),
        None,
        "[{prefix}] decr 并发归零后键应被删除"
    );

    let k = format!("{prefix}concurrent:caui");
    let mut handles = Vec::with_capacity(16);
    for i in 0..16u64 {
        let d = Arc::clone(dao);
        let k = k.clone();
        handles.push(tokio::spawn(async move {
            d.compare_and_update_if_greater(&k, i * 3 + 5, 3600).await
        }));
    }
    for h in handles {
        match h.await.unwrap_or_else(|e| {
            panic!(
                "{}: {e}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-caui-join-failed",
                    &[("prefix", prefix)],
                )
            )
        }) {
            Ok(_) => {},
            Err(e) => panic!(
                "{}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-caui-error",
                    &[("prefix", prefix), ("error", e.to_string().as_str())]
                )
            ),
        }
    }
    let expected_max = 15 * 3 + 5;
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some(expected_max.to_string().as_str()),
        "[{prefix}] 并发 CAS-if-greater 终值应恰为 max(全部输入)（nc 单调性）"
    );

    let k = format!("{prefix}concurrent:cas");
    expect_ok(prefix, "set", dao.set(&k, "start", 3600).await);
    let mut handles = Vec::with_capacity(16);
    for i in 0..16u32 {
        let d = Arc::clone(dao);
        let k = k.clone();
        handles.push(tokio::spawn(async move {
            d.compare_and_swap(&k, Some("start"), &format!("cas_winner_{i}"), 3600)
                .await
                .map(|ok| (ok, i))
        }));
    }
    let mut winners = Vec::new();
    for h in handles {
        match h.await.unwrap_or_else(|e| {
            panic!(
                "{}: {e}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-cas-join-failed",
                    &[("prefix", prefix)],
                )
            )
        }) {
            Ok((true, i)) => winners.push(i),
            Ok((false, _)) => {},
            Err(e) => panic!(
                "{}",
                crate::i18n::translate_detail(
                    "dao-conformance-concurrent-cas-error",
                    &[("prefix", prefix), ("error", e.to_string().as_str())]
                )
            ),
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "[{prefix}] compare_and_swap 并发应恰 1 个赢家，实际: {winners:?}"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&k).await).as_deref(),
        Some(format!("cas_winner_{}", winners[0]).as_str()),
        "[{prefix}] 终值应等于唯一 CAS 赢家写入的值"
    );
}

// 独立契约组：过期键接管并发争抢（不进 caps 矩阵——SQL KV 的 concurrent 层含模块契约内的读-改-写方法，见 instances.rs caps 说明）

/// 过期键接管并发争抢契约（独立契约函数，与 `run_refresh_token_rotation` 同构，不经 `caps` 矩阵）：
/// 同一过期键 8 写者并发 `set_if_absent` 不同值，断言「恰一个 true，且终值为唯一赢家写入的值」；30 轮循环放大调度窗口。
/// 预置 30 个 ttl=1 键共用一次 sleep(3s)（对齐套件「每测试仅 1 次 sleep」惯例；逐轮真实等待会放大 30× 墙钟）。
/// 调用方须提供无并行干扰的库（专属命名内存库 / acceptance 单线程目标），否则「恰 1 个赢家」可被外力污染。
pub async fn run_expired_key_takeover_contention(dao: &Arc<dyn GarrisonDao>, prefix: &str) {
    let mut expired_keys = Vec::with_capacity(30);
    for round in 0..30u32 {
        let k = format!("{prefix}takeover:expired_{round}");
        expect_ok(prefix, "set", dao.set(&k, "stale", 1).await);
        expired_keys.push(k);
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    for (round, k) in expired_keys.iter().enumerate() {
        let mut handles = Vec::with_capacity(8);
        for i in 0..8u32 {
            let d = Arc::clone(dao);
            let k = k.clone();
            handles.push(tokio::spawn(async move {
                d.set_if_absent(&k, &format!("taker_{round}_{i}"), 3600)
                    .await
                    .map(|ok| (ok, i))
            }));
        }
        let mut winners = Vec::new();
        for h in handles {
            match h.await.unwrap_or_else(|e| {
                panic!(
                    "{}: {e}",
                    crate::i18n::translate_detail(
                        "dao-conformance-concurrent-sia-join-failed",
                        &[("prefix", prefix)],
                    )
                )
            }) {
                Ok((true, i)) => winners.push(i),
                Ok((false, _)) => {},
                Err(e) => panic!(
                    "{}",
                    crate::i18n::translate_detail(
                        "dao-conformance-concurrent-sia-error",
                        &[("prefix", prefix), ("error", e.to_string().as_str())]
                    )
                ),
            }
        }
        assert_eq!(
            winners.len(),
            1,
            "[{prefix}] 第 {round} 轮：过期键并发 set_if_absent 应恰 1 个赢家，实际: {winners:?}"
        );
        assert_eq!(
            expect_ok(prefix, "get", dao.get(k).await).as_deref(),
            Some(format!("taker_{round}_{}", winners[0]).as_str()),
            "[{prefix}] 第 {round} 轮：终值应等于唯一赢家写入的值"
        );
    }
}

// 独立契约组：vacuum_expired 过期行清理（强断言仅对 SQL KV 成立；trait 默认 no-op 后端返回 0，不入通用 ttl 层）

/// vacuum 契约（独立契约函数，与 `run_expired_key_takeover_contention` 同构，不经 `caps` 矩阵）：
/// 先调一次 vacuum 排除宿主既有过期行干扰（drain），再混合预置 2 个过期（ttl=1）/ 存活 / 永久行；
/// 断言单次 vacuum 精确删除 2 行、过期键不可见、存活与永久行原样、二次调用幂等归零。
/// 强断言（精确计数 / 只删过期）对 trait 默认 no-op 后端不成立，故不入通用 `run_ttl` 层；
/// 调用方须提供无并行写入干扰的库（专属命名内存库 / acceptance 单线程目标）。
pub async fn run_vacuum_expired(dao: &Arc<dyn GarrisonDao>, prefix: &str) {
    // drain：宿主库（共享存储被复用时）可能已有过期行——先清一次，使后续精确计数不受历史行干扰。
    expect_ok(prefix, "vacuum-drain", dao.vacuum_expired().await);

    let k_expired_a = format!("{prefix}vacuum:expired_a");
    let k_expired_b = format!("{prefix}vacuum:expired_b");
    let k_live = format!("{prefix}vacuum:live");
    let k_permanent = format!("{prefix}vacuum:permanent");
    expect_ok(
        prefix,
        "set expired_a",
        dao.set(&k_expired_a, "e1", 1).await,
    );
    expect_ok(
        prefix,
        "set expired_b",
        dao.set(&k_expired_b, "e2", 1).await,
    );
    expect_ok(prefix, "set live", dao.set(&k_live, "alive", 3600).await);
    expect_ok(
        prefix,
        "set permanent",
        dao.set(&k_permanent, "forever", 0).await,
    );

    tokio::time::sleep(Duration::from_secs(3)).await;

    let removed = expect_ok(prefix, "vacuum", dao.vacuum_expired().await);
    assert_eq!(
        removed, 2,
        "[{prefix}] vacuum 应精确删除 2 个过期行，实际: {removed}"
    );
    assert_eq!(
        expect_ok(prefix, "get expired_a", dao.get(&k_expired_a).await),
        None,
        "[{prefix}] vacuum 后过期键应不存在"
    );
    assert_eq!(
        expect_ok(prefix, "get expired_b", dao.get(&k_expired_b).await),
        None,
        "[{prefix}] vacuum 后过期键应不存在"
    );
    assert_eq!(
        expect_ok(prefix, "get live", dao.get(&k_live).await).as_deref(),
        Some("alive"),
        "[{prefix}] 存活行不应被 vacuum 删除"
    );
    assert_eq!(
        expect_ok(prefix, "get permanent", dao.get(&k_permanent).await).as_deref(),
        Some("forever"),
        "[{prefix}] 永久行（NULL expire_at）不应被 vacuum 删除"
    );
    assert_eq!(
        expect_ok(prefix, "vacuum 2nd", dao.vacuum_expired().await),
        0,
        "[{prefix}] 二次 vacuum 应幂等归零（无剩余过期行）"
    );
}

// ttl 层：墙钟过期契约（每测试仅 1 次 sleep，沿用既有惯例 set(ttl=2)+sleep(3s)）

/// ttl 层契约：过期即不存在、update/rename/incr 保留原窗口不重置、`expire(k, 0)` 转永久；
/// 子断言共用一次 `sleep(3s)` 窗口（ttl=1 必消失、ttl=2 原窗口后消失，1s 余量）。
pub async fn run_ttl(dao: &Arc<dyn GarrisonDao>, prefix: &str) {
    let ka = format!("{prefix}ttl:expire");
    expect_ok(prefix, "set", dao.set(&ka, "v", 1).await);

    let kb = format!("{prefix}ttl:update_keeps_ttl");
    expect_ok(prefix, "set", dao.set(&kb, "v1", 2).await);
    expect_ok(prefix, "update", dao.update(&kb, "v2").await);

    let kc = format!("{prefix}ttl:rename_src");
    let kc2 = format!("{prefix}ttl:rename_dst");
    expect_ok(prefix, "set", dao.set(&kc, "v", 2).await);
    expect_ok(prefix, "rename", dao.rename(&kc, &kc2).await);

    let kd = format!("{prefix}ttl:expire_zero_permanent");
    expect_ok(prefix, "set", dao.set(&kd, "v", 1).await);
    expect_ok(prefix, "expire(0)", dao.expire(&kd, 0).await);

    let ke = format!("{prefix}ttl:incr_keeps_ttl");
    expect_ok(prefix, "set", dao.set(&ke, "0", 2).await);
    assert_eq!(
        expect_ok(prefix, "incr", dao.incr(&ke, 9999).await),
        1,
        "[{prefix}] 存量键 incr 应递增为 1"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert_eq!(
        expect_ok(prefix, "get", dao.get(&ka).await),
        None,
        "[{prefix}] set(ttl=1) 过期后 get 应为 None"
    );
    assert_eq!(
        expect_ok(prefix, "get_timeout", dao.get_timeout(&ka).await),
        None,
        "[{prefix}] 过期键 get_timeout 应为 None"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&kb).await),
        None,
        "[{prefix}] update 不重置 TTL，原窗口后键应消失"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&kc2).await),
        None,
        "[{prefix}] rename 保留原 TTL，原窗口后新键应消失"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&kd).await).as_deref(),
        Some("v"),
        "[{prefix}] expire(k, 0) 应转永久，原窗口过后键仍存活"
    );
    assert_eq!(
        expect_ok(prefix, "get", dao.get(&ke).await),
        None,
        "[{prefix}] incr 保留原窗口不重置，原窗口后键应消失"
    );
}

// keys 层：glob 扫描契约

/// keys 层契约：`*` 与 `?` glob 匹配精确计数、无匹配返回空 Vec、delete/rename 后扫描结果同步。
pub async fn run_keys(dao: &Arc<dyn GarrisonDao>, prefix: &str) {
    let k1 = format!("{prefix}keys:a1");
    let k2 = format!("{prefix}keys:a2");
    let k3 = format!("{prefix}keys:b");
    expect_ok(prefix, "set k1", dao.set(&k1, "v", 3600).await);
    expect_ok(prefix, "set k2", dao.set(&k2, "v", 3600).await);
    expect_ok(prefix, "set k3", dao.set(&k3, "v", 3600).await);

    // `*` 匹配：精确计数 + 集合比较（keys() 返回无序）
    let got = expect_ok(
        prefix,
        "keys *",
        dao.keys(&format!("{prefix}keys:a*")).await,
    );
    let mut got = got;
    got.sort();
    let mut expected = vec![k1.clone(), k2.clone()];
    expected.sort();
    assert_eq!(got, expected, "[{prefix}] `*` glob 应精确匹配两个 a 键");

    // `?` 单字符匹配：a1/a2 命中；单字符后缀的 b 命中 `?`；双字符 a1 不被 `?` 短配
    let got = expect_ok(
        prefix,
        "keys ?",
        dao.keys(&format!("{prefix}keys:a?")).await,
    );
    let mut got = got;
    got.sort();
    assert_eq!(got, expected, "[{prefix}] `?` glob 应精确匹配两个 a 键");
    let got = expect_ok(
        prefix,
        "keys ? 单字符",
        dao.keys(&format!("{prefix}keys:?")).await,
    );
    assert_eq!(
        got,
        vec![k3.clone()],
        "[{prefix}] `?` 应恰匹配单字符后缀的 b 键"
    );

    // 无匹配：空 Vec
    let got = expect_ok(
        prefix,
        "keys 无匹配",
        dao.keys(&format!("{prefix}keys:zzz*")).await,
    );
    assert!(
        got.is_empty(),
        "[{prefix}] 无匹配应返回空 Vec，实际: {got:?}"
    );

    // delete 后扫描同步
    expect_ok(prefix, "delete", dao.delete(&k1).await);
    let got = expect_ok(
        prefix,
        "keys delete 后",
        dao.keys(&format!("{prefix}keys:a*")).await,
    );
    assert_eq!(got, vec![k2.clone()], "[{prefix}] delete 后扫描应同步移除");

    // rename 后扫描同步：旧键消失、新键出现
    let k4 = format!("{prefix}keys:a4");
    expect_ok(prefix, "rename", dao.rename(&k2, &k4).await);
    let got = expect_ok(
        prefix,
        "keys rename 后",
        dao.keys(&format!("{prefix}keys:a*")).await,
    );
    assert_eq!(got, vec![k4.clone()], "[{prefix}] rename 后扫描应指向新键");
}

// refresh token 轮换层契约（db-sqlite + protocol-jwt）

/// RefreshTokenRotation SQL 层契约（同一把尺子，跑 sqlite 实例）：
/// `rotated_at` 写入（子代恒 NULL、被消费旧记录写正值时刻）／重用三级分类（RecentPrev / OrphanedBranch / StaleLineage / 存活与未知 hash 为 `None`）／
/// 宽限窗口（窗口内重放兑现同一新 token，预算耗尽转盗用处置）／旋转失败补偿（INSERT 注入失败后无残留子代、原链仍可用）。
///
/// 调用方负责先对 `pool` 执行迁移（`GarrisonMigration::migrate_core`）。
#[cfg(all(feature = "db-sqlite", feature = "protocol-jwt"))]
pub async fn run_refresh_token_rotation(prefix: &str, pool: &dbnexus::DbPool) {
    use crate::protocol::jwt::refresh::{RefreshTokenReuseSubtype, RefreshTokenRotation};
    use crate::protocol::jwt::JwtHandler;
    use dbnexus::sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, RwLock};

    let rotation = Arc::new(
        RefreshTokenRotation::new(
            pool.clone(),
            Arc::new(JwtHandler::new("contract-refresh-secret-0123456789abcdef")),
            Arc::new(RwLock::new(1)),
        )
        .with_grace_window(60, 1),
    );

    let sha256_hex = |s: &str| {
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    // 原生错误显性化：统一映射 GarrisonError::Dao 后 fail-loud（透传消息）
    fn dao_err(e: impl std::fmt::Display) -> crate::error::GarrisonError {
        crate::error::GarrisonError::Dao(e.to_string())
    }

    // 单值探测查询（SQL 恒带 1 个 `?` 占位）
    let query_i64 = |sql: &'static str, param: String| {
        let pool = pool.clone();
        async move {
            let session = pool
                .get_session("admin")
                .await
                .map_err(dao_err)
                .unwrap_or_else(|e| {
                    panic!(
                        "{}",
                        crate::i18n::translate_detail(
                            "dao-conformance-get-session-failed",
                            &[("prefix", prefix), ("error", e.to_string().as_str())]
                        )
                    )
                });
            let conn = session.connection().map_err(dao_err).unwrap_or_else(|e| {
                panic!(
                    "{}",
                    crate::i18n::translate_detail(
                        "dao-conformance-connection-failed",
                        &[("prefix", prefix), ("error", e.to_string().as_str())]
                    )
                )
            });
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                sql,
                vec![Value::String(Some(param))],
            );
            let row = conn
                .query_one_raw(stmt)
                .await
                .map_err(dao_err)
                .unwrap_or_else(|e| {
                    panic!(
                        "{}",
                        crate::i18n::translate_detail(
                            "dao-conformance-query-failed",
                            &[("prefix", prefix), ("error", e.to_string().as_str())]
                        )
                    )
                })
                .unwrap_or_else(|| {
                    panic!(
                        "{}",
                        crate::i18n::translate_detail(
                            "dao-conformance-query-returned-no-row",
                            &[("prefix", prefix), ("sql", sql)]
                        )
                    )
                });
            row.try_get::<i64>("", "val").unwrap_or_else(|e| {
                panic!(
                    "{}",
                    crate::i18n::translate_detail(
                        "dao-conformance-val-column-read-failed",
                        &[("prefix", prefix), ("error", e.to_string().as_str())]
                    )
                )
            })
        }
    };

    let executed = |sql: &'static str| {
        let pool = pool.clone();
        async move {
            let session = pool
                .get_session("admin")
                .await
                .map_err(dao_err)
                .unwrap_or_else(|e| {
                    panic!(
                        "{}",
                        crate::i18n::translate_detail(
                            "dao-conformance-get-session-failed",
                            &[("prefix", prefix), ("error", e.to_string().as_str())]
                        )
                    )
                });
            let conn = session.connection().map_err(dao_err).unwrap_or_else(|e| {
                panic!(
                    "{}",
                    crate::i18n::translate_detail(
                        "dao-conformance-connection-failed",
                        &[("prefix", prefix), ("error", e.to_string().as_str())]
                    )
                )
            });
            let stmt = Statement::from_sql_and_values(DbBackend::Sqlite, sql, vec![]);
            conn.execute_raw(stmt)
                .await
                .map_err(dao_err)
                .unwrap_or_else(|e| {
                    panic!(
                        "{}",
                        crate::i18n::translate_detail(
                            "dao-conformance-execute-failed",
                            &[("prefix", prefix), ("error", e.to_string().as_str())]
                        )
                    )
                });
        }
    };

    // 1. rotated_at 写入契约
    let t1 = expect_ok(
        prefix,
        "issue",
        rotation.issue("c1", Some(1), &[], None, 1, 0, 9999).await,
    );
    let t1_hash = sha256_hex(&t1);
    let (_, t2) = expect_ok(prefix, "rotate#1", rotation.rotate(&t1).await);
    let t2_hash = sha256_hex(&t2);
    let (_, t3) = expect_ok(prefix, "rotate#2", rotation.rotate(&t2).await);
    let t3_hash = sha256_hex(&t3);
    // 被消费的旧记录 rotated_at 为正时刻
    let rotated = query_i64(
        "SELECT COALESCE(rotated_at, 0) AS val FROM refresh_tokens WHERE token_hash = ?",
        t1_hash.clone(),
    )
    .await;
    assert!(
        rotated > 0,
        "[{prefix}] 被消费旧记录应写入 rotated_at，实际 {rotated}"
    );
    // 存活子代记录 rotated_at 为 NULL（以 COALESCE 0 探测）
    let child_rotated = query_i64(
        "SELECT COALESCE(rotated_at, 0) AS val FROM refresh_tokens WHERE token_hash = ?",
        t3_hash.clone(),
    )
    .await;
    assert_eq!(child_rotated, 0, "[{prefix}] 存活子代 rotated_at 应为 NULL");

    // 2. 三级分类契约
    let subtype = expect_ok(prefix, "detect#t2", rotation.detect_reuse(&t2_hash).await);
    assert_eq!(
        subtype,
        Some(RefreshTokenReuseSubtype::RecentPrev),
        "[{prefix}] 1 跳祖先应为 RecentPrev"
    );
    let subtype = expect_ok(prefix, "detect#t1", rotation.detect_reuse(&t1_hash).await);
    assert_eq!(
        subtype,
        Some(RefreshTokenReuseSubtype::OrphanedBranch),
        "[{prefix}] 2 跳祖先应为 OrphanedBranch"
    );
    let subtype = expect_ok(prefix, "detect#live", rotation.detect_reuse(&t3_hash).await);
    assert_eq!(subtype, None, "[{prefix}] 存活链头不应检出重用");
    let subtype = expect_ok(
        prefix,
        "detect#unknown",
        rotation.detect_reuse(&sha256_hex("never-issued")).await,
    );
    assert_eq!(subtype, None, "[{prefix}] 未知 hash 不应检出重用");

    // 3. 宽限窗口契约（窗口内兑现同一 token；预算耗尽转盗用）
    let (_, graced) = expect_ok(prefix, "grace-redeem", rotation.rotate(&t2).await);
    assert_eq!(graced, t3, "[{prefix}] 窗口内重放应兑现胜者的同一新 token");
    let again = rotation.rotate(&t2).await;
    assert!(
        matches!(again, Err(crate::error::GarrisonError::TokenRevoked(_))),
        "[{prefix}] 预算耗尽后应转盗用处置，实际 {again:?}"
    );

    // 4. 旋转失败补偿契约
    // 注入目标须是未消费的存活 token（上方预算耗尽处置已吊销 t3）
    let t4 = expect_ok(
        prefix,
        "issue#t4",
        rotation.issue("c1", Some(1), &[], None, 1, 0, 9999).await,
    );
    let t4_hash = sha256_hex(&t4);
    // BEFORE INSERT 触发器注入写失败：消费（UPDATE）成功、INSERT 中止
    let trigger_sql = "CREATE TRIGGER contract_fail_insert BEFORE INSERT ON refresh_tokens \
                       BEGIN SELECT RAISE(ABORT, 'contract injected insert failure'); END;";
    executed(trigger_sql).await;
    let failed = rotation.rotate(&t4).await;
    executed("DROP TRIGGER contract_fail_insert").await;
    match failed {
        Err(crate::error::GarrisonError::Dao(msg)) => {
            assert!(
                msg.contains("rolled-back"),
                "[{prefix}] 补偿成功时错误应标注 rolled-back，实际 {msg}"
            );
        },
        other => panic!(
            "{}",
            crate::i18n::translate_detail(
                "dao-conformance-injection-expected-dao-error",
                &[
                    ("prefix", prefix),
                    ("actual", format!("{other:?}").as_str())
                ]
            )
        ),
    }
    // 无残留子代 + 原链仍可用（回退后可再次正常轮换）
    let children = query_i64(
        "SELECT COUNT(*) AS val FROM refresh_tokens WHERE parent_token_hash = ?",
        t4_hash.clone(),
    )
    .await;
    assert_eq!(children, 0, "[{prefix}] 补偿后不得残留半成品子代");
    let (_, retried) = expect_ok(prefix, "retry-rotate", rotation.rotate(&t4).await);
    let retried_hash = sha256_hex(&retried);
    assert!(
        !retried_hash.is_empty(),
        "[{prefix}] 重试轮换应产出新 token"
    );
    let consumed = query_i64(
        "SELECT revoked AS val FROM refresh_tokens WHERE token_hash = ?",
        t4_hash,
    )
    .await;
    assert_eq!(consumed, 1, "[{prefix}] 重试轮换应正常消费原 token");
}

/// WebAuthn 凭据 repository 契约组（dbnexus sqlite；postgres 方言经 make_statement 复用同实现）：
/// create 唯一约束兜底并发绑定（重复绑定 `AlreadyBound` 且不泄露他人行）、find/list 全字段 roundtrip、update 持久化（缺失显性 `InvalidParam`）、delete 幂等。
#[cfg(all(feature = "db-sqlite", feature = "protocol-webauthn"))]
pub async fn run_webauthn_credential_repository(prefix: &str, pool: &dbnexus::DbPool) {
    use crate::dao::repository::sqlite::DbnexusWebauthnCredentialRepository;
    use crate::dao::repository::WebauthnCredentialRepository;
    use crate::dao::repository::{WebauthnBindOutcome, WebauthnCredentialRow};

    let repo = DbnexusWebauthnCredentialRepository::new(pool.clone());
    let tenant = 7_i64;

    let row = |user: &str, cred: &str| WebauthnCredentialRow {
        tenant_id: tenant,
        user_id: user.to_string(),
        credential_id: cred.to_string(),
        public_key: r#"{"kty":2,"alg":-7,"crv":1,"x":"aa","y":"bb"}"#.to_string(),
        sign_count: 0,
        backup_eligible: false,
        backup_state: false,
        attestation: Some("none".to_string()),
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
    };

    // create：首次 Bound；同凭据再次 create → AlreadyBound（携原占用者）
    let first = repo.create(&row("user-wn-a", "cred-wn-1")).await;
    assert!(
        matches!(first, Ok(WebauthnBindOutcome::Bound)),
        "[{prefix}] 首次绑定应为 Bound，实际: {first:?}"
    );
    let dup = repo.create(&row("user-wn-b", "cred-wn-1")).await;
    match dup {
        Ok(WebauthnBindOutcome::AlreadyBound { by_user_id }) => {
            assert_eq!(
                by_user_id, "user-wn-a",
                "[{prefix}] AlreadyBound 应携带当前占用者，不泄露其他行内容"
            );
        },
        other => panic!(
            "{}",
            crate::i18n::translate_detail(
                "dao-conformance-duplicate-binding-expected-already-bound",
                &[
                    ("prefix", prefix),
                    ("actual", format!("{other:?}").as_str())
                ]
            )
        ),
    }

    // find：全字段 roundtrip；缺失 → None
    let found = repo.find_by_credential_id(tenant, "cred-wn-1").await;
    match found {
        Ok(Some(r)) => {
            assert_eq!(r.user_id, "user-wn-a", "[{prefix}] roundtrip user_id");
            assert_eq!(r.sign_count, 0, "[{prefix}] roundtrip sign_count");
            assert_eq!(
                r.attestation.as_deref(),
                Some("none"),
                "[{prefix}] roundtrip attestation"
            );
        },
        other => panic!(
            "{}",
            crate::i18n::translate_detail(
                "dao-conformance-bound-credential-not-found",
                &[
                    ("prefix", prefix),
                    ("actual", format!("{other:?}").as_str())
                ]
            )
        ),
    }
    assert!(
        repo.find_by_credential_id(tenant, "cred-wn-missing")
            .await
            .unwrap_or_else(|e| panic!(
                "{}: {e}",
                crate::i18n::translate_detail(
                    "dao-conformance-query-must-succeed",
                    &[("prefix", prefix)]
                )
            ))
            .is_none(),
        "[{prefix}] 未绑定凭据应返回 None"
    );

    // list_by_user：按租户 + 用户过滤
    let listed = repo.list_by_user(tenant, "user-wn-a").await;
    assert_eq!(
        listed.as_ref().map(Vec::len).unwrap_or_default(),
        1,
        "[{prefix}] user-wn-a 应恰好列出 1 条"
    );
    let empty = repo.list_by_user(tenant, "user-wn-b").await;
    assert!(
        empty.as_ref().map(Vec::len).unwrap_or_default() == 0,
        "[{prefix}] 被拒绑定者不应列出任何凭据"
    );

    // update：持久化 sign_count/backup flags；缺失显性 InvalidParam
    repo.update_authenticator_state(tenant, "cred-wn-1", 5, true, true)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{}: {e}",
                crate::i18n::translate_detail(
                    "dao-conformance-credential-update-must-succeed",
                    &[("prefix", prefix)],
                )
            )
        });
    let updated = repo
        .find_by_credential_id(tenant, "cred-wn-1")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            panic!(
                "{}",
                crate::i18n::translate_detail(
                    "dao-conformance-credential-must-exist-after-update",
                    &[("prefix", prefix)],
                )
            )
        });
    assert_eq!(updated.sign_count, 5, "[{prefix}] sign_count 应持久化");
    assert!(
        updated.backup_eligible,
        "[{prefix}] backup_eligible 应持久化"
    );
    assert!(updated.backup_state, "[{prefix}] backup_state 应持久化");
    assert!(
        updated.updated_at >= updated.created_at,
        "[{prefix}] updated_at 应随更新刷新"
    );
    let missing_update = repo
        .update_authenticator_state(tenant, "cred-wn-missing", 1, false, false)
        .await;
    assert!(
        matches!(
            missing_update,
            Err(crate::error::GarrisonError::InvalidParam(_))
        ),
        "[{prefix}] 更新缺失凭据应 InvalidParam 显性拒绝，实际: {missing_update:?}"
    );

    // 单调 CAS：sign_count 回退显性拒绝（克隆检测的落库基准不被倒退破坏）
    let regressed = repo
        .update_authenticator_state(tenant, "cred-wn-1", 3, false, false)
        .await;
    assert!(
        matches!(
            regressed,
            Err(crate::error::GarrisonError::Dao(ref m))
                if m.contains("sign-count-regression")
        ),
        "[{prefix}] 计数回退应显性拒绝，实际: {regressed:?}"
    );
    // 回退被拒后落库值保持不变
    let after_regression = repo
        .find_by_credential_id(tenant, "cred-wn-1")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            panic!(
                "{}",
                crate::i18n::translate_detail(
                    "dao-conformance-credential-must-exist-after-rollback",
                    &[("prefix", prefix)],
                )
            )
        });
    assert_eq!(
        after_regression.sign_count, 5,
        "[{prefix}] 回退拒绝后落库计数不应变化"
    );
    // 同值重写（并发 finish 双方读到相同落库值）同样拒绝——计数器只进不退
    let same_value = repo
        .update_authenticator_state(tenant, "cred-wn-1", 5, true, true)
        .await;
    assert!(
        matches!(
            same_value,
            Err(crate::error::GarrisonError::Dao(ref m))
                if m.contains("sign-count-regression")
        ),
        "[{prefix}] 同值重写应显性拒绝（并发写保护），实际: {same_value:?}"
    );

    // delete：幂等（删除后 find None，重复 delete Ok）
    repo.delete(tenant, "cred-wn-1").await.unwrap_or_else(|e| {
        panic!(
            "{}: {e}",
            crate::i18n::translate_detail(
                "dao-conformance-unbind-must-succeed",
                &[("prefix", prefix)],
            )
        )
    });
    assert!(
        repo.find_by_credential_id(tenant, "cred-wn-1")
            .await
            .ok()
            .flatten()
            .is_none(),
        "[{prefix}] 解绑后不可再查得"
    );
    repo.delete(tenant, "cred-wn-1").await.unwrap_or_else(|e| {
        panic!(
            "{}: {e}",
            crate::i18n::translate_detail(
                "dao-conformance-unbind-must-be-idempotent",
                &[("prefix", prefix)],
            )
        )
    });
}
