// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 锁定状态存储抽象占位：`UserLockoutStrategy` 当前经
//! [`GarrisonDao`](crate::dao::GarrisonDao) 持久化
//! [`LockoutState`](crate::account::lockout::LockoutState)（`lockout:{user_id}` key，TTL=0 永久），
//! 专用后端（Redis TTL 自动过期 / SQL / 跨数据中心）留待实现。
