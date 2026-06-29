//! 错误类型定义模块。
//!
//! [借鉴 Sa-Token] Sa-TokenException 异常体系，提供框架统一的错误类型与 Result 别名。

use thiserror::Error;

/// Bulwark 框架统一错误类型。
///
/// 涵盖登录、权限、Token、DAO、配置等各层错误场景。
#[derive(Debug, Error)]
pub enum BulwarkError {
    /// 未登录异常（对应 Sa-Token NotLoginException）。
    #[error("未登录: {0}")]
    NotLogin(String),

    /// 无权限异常（对应 Sa-Token NotPermissionException）。
    #[error("无权限: {0}")]
    NotPermission(String),

    /// 无角色异常（对应 Sa-Token NotRoleException）。
    #[error("无角色: {0}")]
    NotRole(String),

    /// Token 无效异常。
    #[error("Token 无效: {0}")]
    InvalidToken(String),

    /// Token 已过期异常。
    #[error("Token 已过期: {0}")]
    ExpiredToken(String),

    /// DAO 层错误。
    #[error("DAO 错误: {0}")]
    Dao(String),

    /// 配置错误。
    #[error("配置错误: {0}")]
    Config(String),

    /// 内部错误。
    #[error("内部错误: {0}")]
    Internal(String),

    /// 会话错误（对应会话创建/查询/过期/续期等场景）。
    #[error("会话错误: {0}")]
    Session(String),

    /// 注解错误（对应注解校验失败、组合冲突等场景）。
    #[error("注解错误: {0}")]
    Annotation(String),

    /// 上下文错误（对应 BulwarkContext / Request / Response / Storage 异常）。
    #[error("上下文错误: {0}")]
    Context(String),
}

/// Bulwark 框架统一 Result 类型别名。
pub type BulwarkResult<T> = Result<T, BulwarkError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 Session 变体的 Display 输出包含原始消息。
    #[test]
    fn session_variant_display_includes_message() {
        let err = BulwarkError::Session("会话已过期".to_string());
        assert_eq!(err.to_string(), "会话错误: 会话已过期");
    }

    /// 验证 Annotation 变体的 Display 输出包含原始消息。
    #[test]
    fn annotation_variant_display_includes_message() {
        let err = BulwarkError::Annotation("注解校验失败".to_string());
        assert_eq!(err.to_string(), "注解错误: 注解校验失败");
    }

    /// 验证 Context 变体的 Display 输出包含原始消息。
    #[test]
    fn context_variant_display_includes_message() {
        let err = BulwarkError::Context("上下文缺失".to_string());
        assert_eq!(err.to_string(), "上下文错误: 上下文缺失");
    }

    /// 验证新增变体可通过 BulwarkResult 传播。
    #[test]
    fn new_variants_propagate_via_result() {
        fn fallible() -> BulwarkResult<()> {
            Err(BulwarkError::Session("测试".to_string()))
        }
        let result = fallible();
        assert!(matches!(result, Err(BulwarkError::Session(_))));
    }

    /// 验证新增变体与已有变体共存于同一枚举。
    #[test]
    fn new_variants_coexist_with_existing() {
        let errors = vec![
            BulwarkError::NotLogin("a".to_string()),
            BulwarkError::Session("b".to_string()),
            BulwarkError::Annotation("c".to_string()),
            BulwarkError::Context("d".to_string()),
        ];
        assert_eq!(errors.len(), 4);
    }
}
