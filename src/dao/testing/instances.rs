// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 契约测试套件的后端实例化矩阵：每条 [`crate::dao_conformance_tests!`] invocation 声明一个后端的能力层清单，
//! 由同一把尺子（`conformance::run_*`）逐一检验；仅 `cfg(test)` 下编译运行。
//!
//! - `in_memory`：[basic, atomic, concurrent, ttl, keys]（无 feature 依赖）
//! - `oxcache_memory`：[basic, atomic, concurrent, ttl]（`cache-memory`）；`oxcache_memory_keys` 独立块挂 keys（`dao-key-index`）
//! - `dbnexus_sqlite`：[basic, atomic, concurrent, ttl]（KV 委托进程内 `InMemoryDao`，不触 SQL 表故不跑迁移）
//! - `dbnexus_kv_sqlite`：[atomic, ttl]（`DbnexusKvDao` 直连真实 SQL 表；并发争抢由独立测试 `expired_key_takeover_contention_dbnexus_kv_sqlite` 承载）
//! - `dbnexus_postgres`：同 caps（`#[ignore]` + `DATABASE_URL`，`#[serial]`）
//! - `alone_cache`：[basic, atomic]（装饰器纯委托，concurrent/ttl 由内层 InMemoryDao 证明）

crate::dao_conformance_tests! {
    backend: in_memory,
    make: || async {
        Ok(::std::sync::Arc::new(crate::dao::InMemoryDao::new())
            as ::std::sync::Arc<dyn crate::dao::GarrisonDao>)
    },
    caps: [basic, atomic, concurrent, ttl, keys],
}

#[cfg(feature = "cache-memory")]
crate::dao_conformance_tests! {
    backend: oxcache_memory,
    make: || async {
        crate::dao::GarrisonDaoOxcache::new()
            .await
            .map(|d| ::std::sync::Arc::new(d) as ::std::sync::Arc<dyn crate::dao::GarrisonDao>)
    },
    caps: [basic, atomic, concurrent, ttl],
}

#[cfg(all(
    feature = "dao-key-index",
    any(feature = "cache-memory", feature = "cache-redis")
))]
crate::dao_conformance_tests! {
    backend: oxcache_memory_keys,
    make: || async {
        crate::dao::GarrisonDaoOxcache::new()
            .await
            .map(|d| ::std::sync::Arc::new(d) as ::std::sync::Arc<dyn crate::dao::GarrisonDao>)
    },
    caps: [keys],
}

#[cfg(feature = "db-sqlite")]
crate::dao_conformance_tests! {
    backend: dbnexus_sqlite,
    make: || async {
        let pool = // cache=shared 命名内存库：池内多连接共享同一库（`sqlite::memory:` Windows 下开新连接得到空库，迁移建表后查询报 no such table，2026-10-08 Windows CI 实证）
    crate::dao::init_dbnexus("sqlite:file:garrison_dao_conformance_mem?mode=memory&cache=shared").await?;
        Ok(::std::sync::Arc::new(crate::dao::GarrisonDaoDbnexus::new(
            pool,
            ::std::sync::Arc::new(crate::dao::InMemoryDao::new()),
        )) as ::std::sync::Arc<dyn crate::dao::GarrisonDao>)
    },
    caps: [basic, atomic, concurrent, ttl],
}

// SQL 持久化 KV 契约（dbnexus sqlite）：`GarrisonDaoDbnexus` 的 KV 委托为进程内实例（见上），
// 本实例以 `DbnexusKvDao` 直连 `garrison_kv` 表补齐 SQL KV 行为（含 `set_if_absent` 过期接管语义）的契约覆盖。
// caps 仅 [atomic, ttl]：basic 要求 `compare_and_update_if_greater`（trait 默认 fail-closed NotImplemented，未实现）；
// concurrent 要求 get_and_delete/incr/decr 恰一赢家/无丢失更新，而它们是模块契约内的「读-改-写」两步（Non-Goal 不修）
// ——SQL KV 并发争抢由独立契约函数 `run_expired_key_takeover_contention` 另行承载，见下方独立测试。
#[cfg(feature = "db-sqlite")]
crate::dao_conformance_tests! {
    backend: dbnexus_kv_sqlite,
    make: || async {
        let pool = // cache=shared 命名内存库：池内多连接共享同一库（`sqlite::memory:` Windows 下开新连接得到空库，迁移建表后查询报 no such table，2026-10-08 Windows CI 实证）
            crate::dao::init_dbnexus("sqlite:file:garrison_dao_kv_conformance_mem?mode=memory&cache=shared").await?;
        let kv = crate::dao::DbnexusKvDao::new(pool);
        kv.ensure_table().await?;
        Ok(::std::sync::Arc::new(kv) as ::std::sync::Arc<dyn crate::dao::GarrisonDao>)
    },
    caps: [atomic, ttl],
}

/// 过期键接管并发争抢契约（dbnexus sqlite）：caps 矩阵不含 concurrent（get_and_delete/incr/decr 属模块契约内的读-改-写），
/// 本独立测试以 `DbnexusKvDao` 直连 SQL 表承载 `set_if_absent` 单语句原子性的并发回归（30 轮 × 8 写者）。
/// 专属命名内存库与 caps 实例隔离——「恰 1 个赢家」的计数断言不容并行用例的过期行干扰。
#[cfg(all(test, feature = "db-sqlite"))]
#[tokio::test(flavor = "multi_thread")]
async fn expired_key_takeover_contention_dbnexus_kv_sqlite() {
    let pool = // cache=shared 命名内存库：池内多连接共享同一库（`sqlite::memory:` Windows 下开新连接得到空库，迁移建表后查询报 no such table，2026-10-08 Windows CI 实证）
        crate::dao::init_dbnexus("sqlite:file:garrison_dao_kv_takeover_mem?mode=memory&cache=shared")
            .await
            .expect("init_dbnexus 应成功");
    let kv = crate::dao::DbnexusKvDao::new(pool);
    kv.ensure_table().await.expect("ensure_table 应成功");
    let dao: ::std::sync::Arc<dyn crate::dao::GarrisonDao> = ::std::sync::Arc::new(kv);
    crate::dao::testing::conformance::run_expired_key_takeover_contention(
        &dao,
        "dbnexus_kv_sqlite_takeover:",
    )
    .await;
}

#[cfg(all(test, feature = "db-postgres"))]
crate::dao_conformance_tests! {
    backend: dbnexus_postgres,
    make: || async {
        let db_url = std::env::var("DATABASE_URL")
            .or_else(|_| std::env::var("SINNAN_TEST_DATABASE_URL"))
            .expect("DATABASE_URL 或 SINNAN_TEST_DATABASE_URL 必须设置才能运行此测试");
        let pool = crate::dao::init_dbnexus(&db_url).await?;
        Ok(::std::sync::Arc::new(crate::dao::GarrisonDaoDbnexus::new(
            pool,
            ::std::sync::Arc::new(crate::dao::InMemoryDao::new()),
        )) as ::std::sync::Arc<dyn crate::dao::GarrisonDao>)
    },
    caps: [basic, atomic, concurrent, ttl],
    serial: true,
    ignore: "requires DATABASE_URL",
}

/// refresh token 轮换层契约（dbnexus sqlite）：`RefreshTokenRotation` 为 SQL 直连层，不走 `dao_conformance_tests!`，
/// 以独立测试挂 [`crate::dao::testing::conformance::run_refresh_token_rotation`]（调用方先行迁移，契约组内含失败注入与恢复断言）。
#[cfg(all(test, feature = "db-sqlite", feature = "protocol-jwt"))]
#[tokio::test(flavor = "multi_thread")]
async fn refresh_token_rotation_contract_dbnexus_sqlite() {
    let pool = // cache=shared 命名内存库：池内多连接共享同一库（`sqlite::memory:` Windows 下开新连接得到空库，迁移建表后查询报 no such table，2026-10-08 Windows CI 实证）
    crate::dao::init_dbnexus("sqlite:file:garrison_refresh_rotation_mem?mode=memory&cache=shared")
        .await
        .expect("init_dbnexus 应成功");
    let migration = crate::dao::GarrisonMigration::with_base_dir(
        pool.clone(),
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("migrations")
            .join("sqlite"),
    );
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
    crate::dao::testing::conformance::run_refresh_token_rotation("refresh_token_sqlite", &pool)
        .await;
}

#[cfg(feature = "alone-cache")]
crate::dao_conformance_tests! {
    backend: alone_cache,
    make: || async {
        Ok(::std::sync::Arc::new(crate::dao::alone_cache::AloneCache::new(
            ::std::sync::Arc::new(crate::dao::InMemoryDao::new()),
            "cf:",
        )) as ::std::sync::Arc<dyn crate::dao::GarrisonDao>)
    },
    caps: [basic, atomic],
}

/// WebAuthn 凭据 repository 契约（dbnexus sqlite）：repository 为 SQL 直连层，不走 `dao_conformance_tests!`，
/// 以独立测试挂 [`crate::dao::testing::conformance::run_webauthn_credential_repository`]。
#[cfg(all(test, feature = "db-sqlite", feature = "protocol-webauthn"))]
#[tokio::test(flavor = "multi_thread")]
async fn webauthn_credential_repository_contract_dbnexus_sqlite() {
    let pool = // cache=shared 命名内存库：池内多连接共享同一库（`sqlite::memory:` Windows 下开新连接得到空库，迁移建表后查询报 no such table，2026-10-08 Windows CI 实证）
    crate::dao::init_dbnexus("sqlite:file:garrison_webauthn_mem?mode=memory&cache=shared")
        .await
        .expect("init_dbnexus 应成功");
    let migration = crate::dao::GarrisonMigration::with_base_dir(
        pool.clone(),
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("migrations")
            .join("sqlite"),
    );
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
    crate::dao::testing::conformance::run_webauthn_credential_repository("webauthn_sqlite", &pool)
        .await;
}
