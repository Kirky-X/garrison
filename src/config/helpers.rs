//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! config 模块辅助函数（从 mod.rs 迁移）。

use super::*;

/// 构造默认 JwtSecret（空字符串），避免 `Default` 实现中重复 cfg 分支。
///
/// # ⚠️ 安全警告
///
/// 返回的 JWT secret 为**空字符串**，仅用于开发/测试环境的默认配置。
/// **生产环境必须通过配置文件或环境变量设置非空 secret**，否则攻击者可伪造任意 token。
pub(crate) fn default_jwt_secret() -> JwtSecret {
    #[cfg(feature = "protocol-zeroize")]
    {
        String::new().into()
    }
    #[cfg(not(feature = "protocol-zeroize"))]
    {
        String::new()
    }
}
