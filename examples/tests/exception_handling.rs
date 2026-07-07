//! 异常处理示例测试。
//!
//! 验证 run() 完整执行，以及 NotLoginException / BulwarkException 的构造与互转。

use bulwark::error::BulwarkError;
use bulwark::exception::{BulwarkException, NotLoginException};
use bulwark_examples::infrastructure::exception_handling;

#[test]
fn test_run_completes() {
    exception_handling::run().unwrap();
}

#[test]
fn test_not_login_exception_builder() {
    let ex = NotLoginException::new("请先登录").with_login_type("account");
    assert_eq!(ex.message, "请先登录");
    assert_eq!(ex.login_type, "account");
    assert!(format!("{}", ex).contains("请先登录"));
}

#[test]
fn test_bulwark_exception_builder_chain() {
    let biz_ex = BulwarkException::new(-1, "会话已过期")
        .with_token("T1-uuid-token")
        .with_login_id(1001)
        .with_login_type(1)
        .with_extra("device", "web")
        .with_extra("ip", "192.168.1.100")
        .build();
    assert_eq!(biz_ex.code, -1);
    assert_eq!(biz_ex.message, "会话已过期");
    assert_eq!(biz_ex.token_value.as_deref(), Some("T1-uuid-token"));
    assert_eq!(biz_ex.login_id, Some(1001));
    assert_eq!(biz_ex.login_type, 1);
    assert_eq!(biz_ex.extras.get("device"), Some(&"web".to_string()));
    assert_eq!(biz_ex.extras.get("ip"), Some(&"192.168.1.100".to_string()));
}

#[test]
fn test_bulwark_error_to_exception_roundtrip() {
    let not_login_err = BulwarkError::NotLogin("token 缺失".to_string());
    let converted: BulwarkException = not_login_err.into();
    assert_eq!(converted.code, -1, "NotLogin 应映射到 code=-1");
    assert_eq!(converted.message, "token 缺失");

    let not_perm_err = BulwarkError::NotPermission("缺少 user:delete 权限".to_string());
    let converted: BulwarkException = not_perm_err.into();
    assert_eq!(converted.code, -2, "NotPermission 应映射到 code=-2");
    assert_eq!(converted.message, "缺少 user:delete 权限");
}

#[test]
fn test_exception_to_error_conversion() {
    let biz_ex = BulwarkException::new(-1, "会话已过期")
        .with_token("T1-uuid-token")
        .with_login_id(1001)
        .build();
    let err: BulwarkError = biz_ex.into();
    // BulwarkException → BulwarkError 应产生 NotLogin 或 Session 等变体
    let err_str = format!("{}", err);
    assert!(
        !err_str.is_empty(),
        "BulwarkException 转 BulwarkError 后 Display 不应为空"
    );
}
