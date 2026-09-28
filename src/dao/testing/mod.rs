// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DAO 契约测试套件（多后端同一把尺子）。
//!
//! 参考 oauth2-proxy `RunSessionStoreTests` 与 dex 的 per-backend subTest 表：
//! 把「每个 `GarrisonDao` 实现都应满足的行为属性」收敛为组断言函数库
//!（[`conformance`]），再由 [`crate::dao_conformance_tests!`] 宏按能力层
//! 清单（caps）对逐个后端实例化运行，杜绝各后端各自手写漂移断言。
//!
//! # 能力分层
//!
//! | 层 | 内容 | 断言函数 |
//! |----|------|----------|
//! | `basic` | get/set/update/delete/expire/永久键/get_with_ttl/incr/decr/compare_and_update_if_greater/rename 单线程契约 | `run_basic` |
//! | `atomic` | set_if_absent / get_and_delete / compare_and_swap 原子原语的单线程语义 | `run_atomic` |
//! | `concurrent` | SETNX 恰一赢家 / GETDEL 一次性消费 / 计数无丢失与无跨越式递减 / CAS 单调（multi_thread 真并发） | `run_concurrent` |
//! | `ttl` | TTL 过期 / update·rename·incr 保留原窗口 / expire(0) 转永久（墙钟） | `run_ttl` |
//! | `keys` | glob `*`/`?` 扫描与 delete/rename 同步 | `run_keys` |
//!
//! 未声明的能力层不生成测试（宏展开期裁剪）；后端不支持的层（如关闭
//! `dao-key-index` 时 oxcache 的 `keys()` 返回 `NotImplemented`）不挂 caps。
//!
//! # 下游一行接入
//!
//! ```ignore
//! garrison::dao_conformance_tests! {
//!     backend: my_custom_dao,
//!     make: || async { MyCustomDao::new().await.map(|d| Arc::new(d) as Arc<dyn GarrisonDao>) },
//!     caps: [basic, atomic],
//! }
//! ```
//!
//! `make` 每个测试新建一个空实例（每测试全新存储，兼容共享存储后端）；
//! 全部键名以 `<backend>:` 前缀隔离。

pub mod conformance;
mod macros;

#[cfg(test)]
mod instances;
