// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 核心模块（stp 的子模块），提供认证、权限、Token 的基础抽象。

/// 认证逻辑模块，定义登录 / 登出抽象。
pub mod auth;

/// 权限校验模块，定义权限 / 角色校验抽象。
pub mod permission;

/// Token 模型模块，定义 Token 数据结构。
pub mod token;
