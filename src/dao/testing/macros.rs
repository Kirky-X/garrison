// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! [`crate::dao_conformance_tests!`] 宏展开器。
//!
//! 参考 oauth2-proxy `NewSessionStoreFunc` + `RunSessionStoreTests` 与 dex 的
//! per-backend subTest 表：后端名 + `make` 异步构造闭包 + `caps` 能力层清单
//! 展开为每层一个 `#[tokio::test(flavor = "multi_thread")]` 测试，能力跳过在
//! 宏展开期完成（未声明的层不生成测试）。可选 `serial: true` 展开
//! `#[::serial_test::serial]`（仅测试构建可用），`ignore: "..."` 展开
//! `#[ignore = "..."]`（值为字符串字面量）。

/// 后端实例化宏（导出至 crate root：`crate::dao_conformance_tests!`）。
///
/// # 语法
///
/// ```ignore
/// crate::dao_conformance_tests! {
///     backend: <模块名 ident，同时用作键名前缀>,
///     make: || async { Ok(Arc::new(dao) as Arc<dyn GarrisonDao>) },
///     caps: [basic, atomic, concurrent, ttl, keys],
///     serial: true,               // 可选
///     ignore: "requires X",       // 可选
/// }
/// ```
///
/// `make` 在每个测试内被调用一次（每测试全新空实例）；构造失败 panic
///（fail-loud）。`caps` 中的未知层触发 `compile_error!`。
#[macro_export]
macro_rules! dao_conformance_tests {
    (backend: $backend:ident, make: $make:expr, caps: [$($cap:ident),+ $(,)?] $(,)?) => {
        $crate::__dao_conformance_backend! {
            attrs: [], backend: $backend, make: $make, caps: [$($cap),+]
        }
    };
    (backend: $backend:ident, make: $make:expr, caps: [$($cap:ident),+ $(,)?], serial: true $(,)?) => {
        $crate::__dao_conformance_backend! {
            attrs: [::serial_test::serial], backend: $backend, make: $make, caps: [$($cap),+]
        }
    };
    (backend: $backend:ident, make: $make:expr, caps: [$($cap:ident),+ $(,)?], ignore: $reason:literal $(,)?) => {
        $crate::__dao_conformance_backend! {
            attrs: [ignore = $reason], backend: $backend, make: $make, caps: [$($cap),+]
        }
    };
    (backend: $backend:ident, make: $make:expr, caps: [$($cap:ident),+ $(,)?], serial: true, ignore: $reason:literal $(,)?) => {
        $crate::__dao_conformance_backend! {
            attrs: [::serial_test::serial, ignore = $reason],
            backend: $backend, make: $make, caps: [$($cap),+]
        }
    };
}

/// 生成 `mod <backend>`，内部逐层分派（`#[doc(hidden)]`）。
///
/// `attrs` 以单个 token tree（`[...]`）原子捕获再透传，避免 meta 与 cap
/// 两级重复在展开期被强制同步（macro-rules 无独立重复变量）。
#[doc(hidden)]
#[macro_export]
macro_rules! __dao_conformance_backend {
    (attrs: $attrs:tt, backend: $backend:ident, make: $make:expr, caps: [$($cap:ident),+ $(,)?]) => {
        mod $backend {
            $(
                $crate::__dao_conformance_layer! {
                    attrs: $attrs, backend: $backend, make: $make, cap: $cap
                }
            )+
        }
    };
}

/// 层 → 测试函数分派（未知层 `compile_error!`，`#[doc(hidden)]`）。
#[doc(hidden)]
#[macro_export]
macro_rules! __dao_conformance_layer {
    (attrs: [$($meta:meta),* $(,)?], backend: $backend:ident, make: $make:expr, cap: basic) => {
        $(#[$meta])*
        #[::tokio::test(flavor = "multi_thread")]
        async fn basic() {
            let made: ::core::result::Result<
                ::std::sync::Arc<dyn $crate::dao::GarrisonDao>,
                $crate::error::GarrisonError,
            > = ($make)().await;
            let dao: ::std::sync::Arc<dyn $crate::dao::GarrisonDao> = made
                .expect(concat!("dao-conformance::构造 ", stringify!($backend), " 失败"));
            $crate::dao::testing::conformance::run_basic(
                &dao,
                concat!(stringify!($backend), ":"),
            )
            .await;
        }
    };
    (attrs: [$($meta:meta),* $(,)?], backend: $backend:ident, make: $make:expr, cap: atomic) => {
        $(#[$meta])*
        #[::tokio::test(flavor = "multi_thread")]
        async fn atomic() {
            let made: ::core::result::Result<
                ::std::sync::Arc<dyn $crate::dao::GarrisonDao>,
                $crate::error::GarrisonError,
            > = ($make)().await;
            let dao: ::std::sync::Arc<dyn $crate::dao::GarrisonDao> = made
                .expect(concat!("dao-conformance::构造 ", stringify!($backend), " 失败"));
            $crate::dao::testing::conformance::run_atomic(
                &dao,
                concat!(stringify!($backend), ":"),
            )
            .await;
        }
    };
    (attrs: [$($meta:meta),* $(,)?], backend: $backend:ident, make: $make:expr, cap: concurrent) => {
        $(#[$meta])*
        #[::tokio::test(flavor = "multi_thread")]
        async fn concurrent() {
            let made: ::core::result::Result<
                ::std::sync::Arc<dyn $crate::dao::GarrisonDao>,
                $crate::error::GarrisonError,
            > = ($make)().await;
            let dao: ::std::sync::Arc<dyn $crate::dao::GarrisonDao> = made
                .expect(concat!("dao-conformance::构造 ", stringify!($backend), " 失败"));
            $crate::dao::testing::conformance::run_concurrent(
                &dao,
                concat!(stringify!($backend), ":"),
            )
            .await;
        }
    };
    (attrs: [$($meta:meta),* $(,)?], backend: $backend:ident, make: $make:expr, cap: ttl) => {
        $(#[$meta])*
        #[::tokio::test(flavor = "multi_thread")]
        async fn ttl() {
            let made: ::core::result::Result<
                ::std::sync::Arc<dyn $crate::dao::GarrisonDao>,
                $crate::error::GarrisonError,
            > = ($make)().await;
            let dao: ::std::sync::Arc<dyn $crate::dao::GarrisonDao> = made
                .expect(concat!("dao-conformance::构造 ", stringify!($backend), " 失败"));
            $crate::dao::testing::conformance::run_ttl(
                &dao,
                concat!(stringify!($backend), ":"),
            )
            .await;
        }
    };
    (attrs: [$($meta:meta),* $(,)?], backend: $backend:ident, make: $make:expr, cap: keys) => {
        $(#[$meta])*
        #[::tokio::test(flavor = "multi_thread")]
        async fn keys() {
            let made: ::core::result::Result<
                ::std::sync::Arc<dyn $crate::dao::GarrisonDao>,
                $crate::error::GarrisonError,
            > = ($make)().await;
            let dao: ::std::sync::Arc<dyn $crate::dao::GarrisonDao> = made
                .expect(concat!("dao-conformance::构造 ", stringify!($backend), " 失败"));
            $crate::dao::testing::conformance::run_keys(
                &dao,
                concat!(stringify!($backend), ":"),
            )
            .await;
        }
    };
    (attrs: [$($meta:meta),* $(,)?], backend: $backend:ident, make: $make:expr, cap: $unknown:ident) => {
        ::core::compile_error!(concat!(
            "dao-conformance::未知能力层 ",
            stringify!($unknown),
            "（允许: basic/atomic/concurrent/ttl/keys）"
        ));
    };
}
