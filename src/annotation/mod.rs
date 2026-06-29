//! 注解模块，定义鉴权注解枚举。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的注解体系（`@SaCheckLogin` 等），
//! Rust 中以枚举变体表达，配合路由拦截使用。

/// 鉴权注解枚举，列出 12 个核心注解。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的注解集合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Annotation {
    /// 检查登录（对应 `@SaCheckLogin`）。
    CheckLogin,

    /// 检查权限（对应 `@SaCheckPermission`）。
    CheckPermission(String),

    /// 检查角色（对应 `@SaCheckRole`）。
    CheckRole(String),

    /// 检查二级认证（对应 `@SaCheckSafe`）。
    CheckSafe,

    /// 检查是否被禁用（对应 `@SaCheckDisable`）。
    CheckDisable,

    /// OR 逻辑组合（对应 `@SaCheckOr`）。
    CheckOr,

    /// AND 逻辑组合（对应 `@SaCheckAnd`）。
    CheckAnd,

    /// NOT 逻辑组合（对应 `@SaCheckNot`）。
    CheckNot,

    /// 忽略鉴权（对应 `@SaIgnore`）。
    Ignore,

    /// Basic 认证检查（对应 `@SaCheckBasicAuth`）。
    CheckBasicAuth,

    /// Digest 认证检查（对应 `@SaCheckDigestAuth`）。
    CheckDigestAuth,

    /// 签名检查（对应 `@SaCheckSign`）。
    CheckSign,
}

impl Annotation {
    /// 获取注解的字符串名称。
    pub fn name(&self) -> &'static str {
        todo!()
    }
}
