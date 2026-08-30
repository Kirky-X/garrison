//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 存储域验收（spec `dao-atomicity` R-dao-atomicity-002 / `acceptance-matrix`
//! R-acceptance-matrix-002 DAO 原子性并发补盲）。
//!
//! 验证 `GarrisonDao` 六个原子必需方法（T012 编译期契约）在真实多线程并发下
//! 的正确性：`set_if_absent` 仅一次成功、`get_and_delete` 恰一次消费、
//! `incr` 无丢失更新。覆盖 InMemoryDao（parking_lot 锁）与 GarrisonDaoOxcache
//! （进程内 oxcache 后端）两种内置实现。
//!
//! 本域不经 `GarrisonManager` 全局单例，无需 `#[serial]`；统一使用
//! `multi_thread` runtime 以获得真实并行竞争。

use garrison::dao::{GarrisonDao, GarrisonDaoOxcache, InMemoryDao};
use std::sync::Arc;

/// 并发任务数（任务文本规定 100）。
const CONCURRENCY: usize = 100;

/// 构造被测后端：InMemoryDao / GarrisonDaoOxcache（异步构造）。
async fn make_backend(name: &str) -> Arc<dyn GarrisonDao> {
    match name {
        "in-memory" => Arc::new(InMemoryDao::new()),
        "oxcache" => Arc::new(GarrisonDaoOxcache::new().await.unwrap()),
        other => panic!("未知后端: {other}"),
    }
}

/// ACC-STORAGE-001（异常/竞争）：100 task 并发 `set_if_absent` 同一 key，
/// 恰好 1 个调用成功写入，其余全部返回 `Ok(false)`；最终值为首个写入值。
async fn concurrency_set_if_absent_exactly_one_winner(backend: &str) {
    let dao = make_backend(backend).await;
    let mut handles = Vec::with_capacity(CONCURRENCY);
    for i in 0..CONCURRENCY {
        let dao = dao.clone();
        handles.push(tokio::spawn(async move {
            let value = format!("writer-{i}");
            dao.set_if_absent("lock:key", &value, 60).await
        }));
    }
    let mut winners = Vec::with_capacity(CONCURRENCY);
    for h in handles {
        let ok = h.await.expect("task 不应 panic");
        winners.push(ok.expect("set_if_absent 不应返回 Err"));
    }
    let success_count = winners.iter().filter(|&&ok| ok).count();
    assert_eq!(
        success_count, 1,
        "并发 set_if_absent 同一 key 应恰好 1 个成功（TOCTOU 将出现多个），实际 {success_count}"
    );

    let final_value = dao.get("lock:key").await.unwrap().expect("key 应存在");
    assert!(
        final_value.starts_with("writer-"),
        "最终值应为某个写入者的值，实际: {final_value}"
    );
}

/// ACC-STORAGE-002（异常/竞争）：100 task 并发 `get_and_delete` 同一 key，
/// 恰好 1 个调用取到值，其余返回 `None`（SSO ticket 一次性消费语义）。
async fn concurrency_get_and_delete_exactly_one_consumer(backend: &str) {
    let dao = make_backend(backend).await;
    dao.set("ticket:one-shot", "secret-ticket", 60)
        .await
        .unwrap();

    let mut handles = Vec::with_capacity(CONCURRENCY);
    for _ in 0..CONCURRENCY {
        let dao = dao.clone();
        handles.push(tokio::spawn(async move {
            dao.get_and_delete("ticket:one-shot").await
        }));
    }
    let mut consumers = Vec::with_capacity(CONCURRENCY);
    for h in handles {
        let got = h.await.expect("task 不应 panic");
        consumers.push(got.expect("get_and_delete 不应返回 Err"));
    }
    let hit_count = consumers.iter().filter(|v| v.is_some()).count();
    assert_eq!(
        hit_count, 1,
        "并发 get_and_delete 同一 key 应恰好 1 个取到（TOCTOU 将出现多次），实际 {hit_count}"
    );
    assert_eq!(
        consumers.iter().find(|v| v.is_some()).unwrap().as_deref(),
        Some("secret-ticket"),
        "唯一消费者应取到原始值"
    );
    // 消费后 key 不应残留
    assert!(dao.get("ticket:one-shot").await.unwrap().is_none());
}

/// ACC-STORAGE-003（正常+竞争）：100 task 并发 `incr` 同一计数器（初值 0），
/// 最终值必须等于串行期望 100（无丢失更新）；TTL 窗口不被并发重置。
async fn concurrency_incr_matches_serial_expectation(backend: &str) {
    let dao = make_backend(backend).await;
    let mut handles = Vec::with_capacity(CONCURRENCY);
    for _ in 0..CONCURRENCY {
        let dao = dao.clone();
        handles.push(tokio::spawn(
            async move { dao.incr("rate:window", 60).await },
        ));
    }
    for h in handles {
        h.await
            .expect("task 不应 panic")
            .expect("incr 不应返回 Err");
    }
    let final_count = dao.get("rate:window").await.unwrap().expect("key 应存在");
    assert_eq!(
        final_count,
        CONCURRENCY.to_string(),
        "并发 incr 后计数应等于串行期望 {CONCURRENCY}（丢失更新将小于该值）"
    );
}

// ------------------------------------------------------------------------
// InMemoryDao 后端
// ------------------------------------------------------------------------

/// ACC-STORAGE-001a：InMemoryDao 并发 set_if_absent 仅一个赢家。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acc_storage_001a_in_memory_set_if_absent_one_winner() {
    concurrency_set_if_absent_exactly_one_winner("in-memory").await;
}

/// ACC-STORAGE-002a：InMemoryDao 并发 get_and_delete 恰一个消费者。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acc_storage_002a_in_memory_get_and_delete_one_consumer() {
    concurrency_get_and_delete_exactly_one_consumer("in-memory").await;
}

/// ACC-STORAGE-003a：InMemoryDao 并发 incr 等于串行期望。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acc_storage_003a_in_memory_incr_serial_expectation() {
    concurrency_incr_matches_serial_expectation("in-memory").await;
}

// ------------------------------------------------------------------------
// GarrisonDaoOxcache 后端
// ------------------------------------------------------------------------

/// ACC-STORAGE-001b：oxcache 并发 set_if_absent 仅一个赢家。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acc_storage_001b_oxcache_set_if_absent_one_winner() {
    concurrency_set_if_absent_exactly_one_winner("oxcache").await;
}

/// ACC-STORAGE-002b：oxcache 并发 get_and_delete 恰一个消费者。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acc_storage_002b_oxcache_get_and_delete_one_consumer() {
    concurrency_get_and_delete_exactly_one_consumer("oxcache").await;
}

/// ACC-STORAGE-003b：oxcache 并发 incr 等于串行期望。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acc_storage_003b_oxcache_incr_serial_expectation() {
    concurrency_incr_matches_serial_expectation("oxcache").await;
}
