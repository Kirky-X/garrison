// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 契约测试套件的后端实例化矩阵。
//!
//! 每条 [`crate::dao_conformance_tests!`] invocation 声明一个后端的能力层清单，
//! 由同一把尺子（`conformance::run_*`）逐一检验；仅 `cfg(test)` 下编译运行。
//!
//! 矩阵：
//! - `in_memory`：`[basic, atomic, concurrent, ttl, keys]`（无 feature 依赖）
//! - `oxcache_memory`：`[basic, atomic, concurrent, ttl]`（`cache-memory`）
//!   + `oxcache_memory_keys` 独立块挂 `keys`（`dao-key-index`，由
//!     `protocol-apikey` / `anomalous-detector-dual` 传递；`full` 自动含，
//!     `production` 无此 feature 时不编译，`keys()` 的 `NotImplemented` 行为
//!     由既有 `dao::tests` 的分层断言覆盖）
//! - `dbnexus_sqlite`：`[basic, atomic, concurrent, ttl]`（`db-sqlite`）——
//!   KV 委托进程内 `InMemoryDao`，不触 SQL 表故不跑迁移
//! - `dbnexus_postgres`：同 caps（`#[ignore]` + `DATABASE_URL`，`#[serial]`）
//! - `alone_cache`：`[basic, atomic]`（`alone-cache`）——装饰器纯委托，
//!   concurrent/ttl 由内层 InMemoryDao 证明，控制墙钟门禁时长

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
        let pool = crate::dao::init_dbnexus("sqlite::memory:").await?;
        Ok(::std::sync::Arc::new(crate::dao::GarrisonDaoDbnexus::new(
            pool,
            ::std::sync::Arc::new(crate::dao::InMemoryDao::new()),
        )) as ::std::sync::Arc<dyn crate::dao::GarrisonDao>)
    },
    caps: [basic, atomic, concurrent, ttl],
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

/// refresh token 轮换层契约（dbnexus sqlite 实例）。
///
/// RefreshTokenRotation 为 SQL 直连层（非 `GarrisonDao` KV 门面），故不走
/// `dao_conformance_tests!` 宏，而以独立测试挂同一把尺子
/// （[`crate::dao::testing::conformance::run_refresh_token_rotation`]）；
/// 调用方先行迁移，契约组内含失败注入（触发器）与恢复断言。
#[cfg(all(test, feature = "db-sqlite", feature = "protocol-jwt"))]
#[tokio::test(flavor = "multi_thread")]
async fn refresh_token_rotation_contract_dbnexus_sqlite() {
    let pool = crate::dao::init_dbnexus("sqlite::memory:")
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

/// WebAuthn 凭据 repository 契约（dbnexus sqlite 实例）。
///
/// 与 refresh_token_rotation 契约同模式：repository 为 SQL 直连层，不走
/// `dao_conformance_tests!` 宏，以独立测试挂契约组
/// （[`crate::dao::testing::conformance::run_webauthn_credential_repository`]）。
#[cfg(all(test, feature = "db-sqlite", feature = "protocol-webauthn"))]
#[tokio::test(flavor = "multi_thread")]
async fn webauthn_credential_repository_contract_dbnexus_sqlite() {
    let pool = crate::dao::init_dbnexus("sqlite::memory:")
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
