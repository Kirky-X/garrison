// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DAO 原子方法**测试回退**实现（编译期契约的配套）。
//!
//! `#[doc(hidden)]` + 测试域专用：生产 DAO 实现**禁止**使用本模块的组合语义
//! （完整编译期门控需 CI 测试命令追加 `testing` feature，CI 现为 full-only，
//! 属本变更 Non-Goals；已记录为后续 change）。
//!
//! # 与生产实现的语义差异（实现方必读）
//!
//! | 方法 | 组合回退语义 | 生产语义（InMemoryDao / oxcache） |
//! |------|-------------|----------------------------------|
//! | `set_if_absent` | get→set 两步，并发可重复插入 | 单锁临界区，SETNX 恰一赢家 |
//! | `rename` | get→set_permanent→delete，**TTL 丢失**且非原子 | 原子迁移并保留 TTL |
//! | `get_and_delete` | get→delete 两步，并发可重复消费 | 单锁 GETDEL，恰一消费者 |
//! | `incr` / `decr` | get→parse→update 组合，并发丢失更新 | 单锁原子计数 |
//! | `compare_and_swap` | get→set 两步，并发可覆盖中间值 | 单锁 CAS |
//!
//! 仅适用于单线程 / `serial_test` 串行化测试环境。生产后端**禁止**使用
//! （参阅 [`crate::dao::GarrisonDao`] trait 文档「原子性编译期契约」）。
//!
//! # 门控状态（遗留缺口，已知限制）
//!
//! 本模块宣称的 `testing` feature 门控**尚未落地**：下方三个 `#[macro_export]`
//! 宏（`atomic_test_fallback!` / `atomic_test_fallback_no_get_and_delete!` /
//! `__atomic_test_fallback_get_and_delete!`）目前**没有**
//! `#[cfg(any(test, feature = "testing"))]` 编译期门控。原因：`testing`
//! feature 虽已在 Cargo.toml 定义，但 CI 测试命令仍为 full-only，
//! tests/acceptance 与 benches 在未启用 `testing` 的情况下直接使用这些宏，
//! 立即门控会使其编译失败（已记录为后续 change）。
//! 因此当前**仅以文档约定约束**：
//!
//! - 这三个宏是**测试回退专用**，任何生产 DAO 实现 / 业务代码**严禁**调用；
//! - 外部 crate 仅应在集成测试 / bench 目标中使用；
//! - 待 CI 追加 `testing` feature 后，将补上 `#[cfg(any(test, feature = "testing"))]`
//! 门控，使生产构建无法触及（届时无需改动宏展开体）。

use crate::dao::GarrisonDao;
use crate::error::GarrisonResult;

/// 组合回退实现的单点逻辑（宏展开体委托至此，杜绝双副本漂移）。
pub mod impls {
    use super::*;

    /// SETNX 组合语义（TOCTOU：并发可重复插入）。
    pub async fn set_if_absent<D: GarrisonDao + ?Sized>(
        dao: &D,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        if dao.get(key).await?.is_some() {
            return Ok(false);
        }
        dao.set(key, value, ttl_seconds).await?;
        Ok(true)
    }

    /// rename 组合语义（TOCTOU 且 TTL 丢失）。
    pub async fn rename<D: GarrisonDao + ?Sized>(
        dao: &D,
        old_key: &str,
        new_key: &str,
    ) -> GarrisonResult<()> {
        let value = dao.get(old_key).await?.ok_or_else(|| {
            crate::error::GarrisonError::InvalidParam(format!("dao-key-missing::{}", old_key))
        })?;
        dao.set_permanent(new_key, &value).await?;
        dao.delete(old_key).await
    }

    /// GETDEL 组合语义（TOCTOU：并发可重复消费）。
    pub async fn get_and_delete<D: GarrisonDao + ?Sized>(
        dao: &D,
        key: &str,
    ) -> GarrisonResult<Option<String>> {
        let value = dao.get(key).await?;
        if value.is_some() {
            dao.delete(key).await?;
        }
        Ok(value)
    }

    /// incr 组合语义（TOCTOU：并发丢失更新；解析失败显式报错）。
    pub async fn incr<D: GarrisonDao + ?Sized>(
        dao: &D,
        key: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<u64> {
        match dao.get(key).await? {
            Some(v) => {
                let cur_val: u64 = v.parse().map_err(|_| {
                    crate::error::GarrisonError::Dao(format!("dao-incr-parse-u64::{}::{}", key, v))
                })?;
                let new_val = cur_val + 1;
                dao.update(key, &new_val.to_string()).await?;
                Ok(new_val)
            },
            None => {
                dao.set(key, "1", ttl_seconds).await?;
                Ok(1)
            },
        }
    }

    /// decr 组合语义（TOCTOU：并发"跨越式递减"）。
    pub async fn decr<D: GarrisonDao + ?Sized>(dao: &D, key: &str) -> GarrisonResult<u64> {
        match dao.get(key).await? {
            Some(v) => {
                let cur_val: u64 = v.parse().map_err(|_| {
                    crate::error::GarrisonError::Dao(format!("dao-decr-parse-u64::{}::{}", key, v))
                })?;
                if cur_val == 0 {
                    return Ok(0);
                }
                let new_val = cur_val - 1;
                if new_val == 0 {
                    dao.delete(key).await?;
                } else {
                    dao.update(key, &new_val.to_string()).await?;
                }
                Ok(new_val)
            },
            None => Ok(0),
        }
    }

    /// CAS 组合语义（TOCTOU：并发可覆盖中间值）。
    pub async fn compare_and_swap<D: GarrisonDao + ?Sized>(
        dao: &D,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        let current = dao.get(key).await?;
        if current.as_deref() == expected {
            if ttl_seconds == 0 {
                dao.set_permanent(key, new_value).await?;
            } else {
                dao.set(key, new_value, ttl_seconds).await?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// 仅供**测试 mock**：展开全部 6 个原子必需方法的组合回退实现。
///
/// # 用法
/// 在 `#[async_trait] impl GarrisonDao for XxxMockDao` 块尾部展开一行：
/// - garrison crate 内部（测试代码）：`crate::atomic_test_fallback!();`
/// - 外部集成测试 / bench：`garrison::atomic_test_fallback!();`
///
/// # ⚠️ 仅供测试（禁止生产使用）
///
/// 展开体为 `async_trait` 脱糖后的签名（`Pin<Box<dyn Future>>`），逻辑委托
/// [`impls`] 单点实现。生产后端禁止使用——本宏当前**未做**
/// `#[cfg(any(test, feature = "testing"))]` 编译期门控（原因与后续计划见
/// 模块文档「门控状态」），生产代码不得依赖此约定之外的行为。
#[macro_export]
#[doc(hidden)]
macro_rules! atomic_test_fallback {
    () => {
        $crate::atomic_test_fallback_no_get_and_delete!();
        $crate::__atomic_test_fallback_get_and_delete!();
    };
}

/// 仅供**测试 mock**：展开 5 个原子必需方法（保留实现方自定义的原子
/// `get_and_delete`，如 SSO ticket 单锁消费场景）。
///
/// # ⚠️ 仅供测试（禁止生产使用）
///
/// 本宏当前未做 `#[cfg(any(test, feature = "testing"))]` 编译期门控
///（原因与后续计划见模块文档「门控状态」）；组合回退实现非原子
///（TOCTOU / TTL 丢失），生产 DAO 实现严禁展开本宏。
#[macro_export]
#[doc(hidden)]
macro_rules! atomic_test_fallback_no_get_and_delete {
    () => {
        #[allow(clippy::type_complexity)]
        fn set_if_absent<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            key: &'life1 str,
            value: &'life2 str,
            ttl_seconds: u64,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<bool>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move {
                $crate::dao::atomic_fallback::impls::set_if_absent(self, key, value, ttl_seconds)
                    .await
            })
        }

        #[allow(clippy::type_complexity)]
        fn rename<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            old_key: &'life1 str,
            new_key: &'life2 str,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<()>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move {
                $crate::dao::atomic_fallback::impls::rename(self, old_key, new_key).await
            })
        }

        #[allow(clippy::type_complexity)]
        fn incr<'life0, 'life1, 'async_trait>(
            &'life0 self,
            key: &'life1 str,
            ttl_seconds: u64,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<u64>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move {
                $crate::dao::atomic_fallback::impls::incr(self, key, ttl_seconds).await
            })
        }

        #[allow(clippy::type_complexity)]
        fn decr<'life0, 'life1, 'async_trait>(
            &'life0 self,
            key: &'life1 str,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<u64>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move { $crate::dao::atomic_fallback::impls::decr(self, key).await })
        }

        #[allow(clippy::type_complexity)]
        fn compare_and_swap<'life0, 'life1, 'life2, 'life3, 'async_trait>(
            &'life0 self,
            key: &'life1 str,
            expected: Option<&'life2 str>,
            new_value: &'life3 str,
            ttl_seconds: u64,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<bool>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            'life3: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(async move {
                $crate::dao::atomic_fallback::impls::compare_and_swap(
                    self,
                    key,
                    expected,
                    new_value,
                    ttl_seconds,
                )
                .await
            })
        }
    };
}

/// 内部宏：`get_and_delete` 薄壳（由 [`atomic_test_fallback!`] 组合引用，
/// 不对外承诺独立使用）。
///
/// # ⚠️ 仅供测试（禁止生产使用）
///
/// 虽然正常情况下仅经 [`atomic_test_fallback!`] 间接展开，但本宏为
/// `#[macro_export]`，其他 crate 可直接调用——当前未做
/// `#[cfg(any(test, feature = "testing"))]` 编译期门控（原因与后续计划见
/// 模块文档「门控状态」）。生产 DAO 实现严禁直接展开本宏。
#[macro_export]
#[doc(hidden)]
macro_rules! __atomic_test_fallback_get_and_delete {
    () => {
        #[allow(clippy::type_complexity)]
        fn get_and_delete<'life0, 'life1, 'async_trait>(
            &'life0 self,
            key: &'life1 str,
        ) -> ::core::pin::Pin<
            Box<
                dyn ::core::future::Future<Output = $crate::error::GarrisonResult<Option<String>>>
                    + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: ::core::marker::Sync + 'async_trait,
        {
            Box::pin(
                async move { $crate::dao::atomic_fallback::impls::get_and_delete(self, key).await },
            )
        }
    };
}
