//! 用户级双态账号锁定子模块（v0.6.0 新增，吸收 keycloak UserLockoutStrategy）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供用户级 temporary + permanent 双态锁定，与 BruteForceStrategy（IP 级）组合使用。
//! 详见 spec `user-lockout`。

// T011 将在此实现 UserLockoutConfig + WaitStrategy + LockoutState
// T012 将在此实现 UserLockoutStrategy

// 临时占位类型，供 T001 编译测试引用（T011 替换为完整实现）
/// 用户级锁定配置（占位，T011 实现完整字段）。
#[derive(Debug, Clone)]
pub struct UserLockoutConfig;
