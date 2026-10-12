// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! session 模块辅助函数。

use super::*;

/// 生成 Account-Session 的存储 key。
pub(crate) fn account_key(login_id: &str) -> String {
    format!("account:session:{}", login_id)
}

/// 生成 Token-Session 的存储 key。
pub(crate) fn token_key(token: &str) -> String {
    format!("{}session:{}", DaoKeyPrefix::Token, token)
}
