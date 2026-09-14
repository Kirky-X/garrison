//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! exception 模块测试（从 mod.rs 迁移）。

use super::*;

/// 验证 `NotLoginException::new` 创建实例并设置默认 login_type 为空字符串。
#[test]
fn new_creates_exception_with_empty_login_type() {
    let ex = NotLoginException::new("请先登录");
    assert_eq!(ex.message, "请先登录");
    assert_eq!(ex.login_type, "");
}

/// 验证 `NotLoginException::new` 接受 String 与 &str 等可转换类型。
#[test]
fn new_accepts_string() {
    let msg = String::from("会话已过期");
    let ex = NotLoginException::new(msg);
    assert_eq!(ex.message, "会话已过期");
}

/// 验证 `with_login_type` 设置 login_type 并返回 self（builder 模式）。
#[test]
fn with_login_type_sets_login_type() {
    let ex = NotLoginException::new("未登录").with_login_type("account");
    assert_eq!(ex.login_type, "account");
    assert_eq!(ex.message, "未登录");
}

/// 验证 `with_login_type` 接受 String 类型。
#[test]
fn with_login_type_accepts_string() {
    let lt = String::from("wechat");
    let ex = NotLoginException::new("未登录").with_login_type(lt);
    assert_eq!(ex.login_type, "wechat");
}

/// 验证 `Display` 实现输出 "Not logged in: {message}" 格式。
#[test]
fn display_formats_correctly() {
    let ex = NotLoginException::new("token 已过期");
    assert_eq!(format!("{}", ex), "Not logged in: token 已过期");
}

/// `with_login_type` 后 Display 输出必须跟随 login_type 变化。
///
/// 若 Display 硬编码"未登录"前缀而忽略 login_type 字段，此测试将失败。
#[test]
fn display_includes_custom_login_type() {
    let ex = NotLoginException::new("请先登录").with_login_type("wechat");
    let rendered = format!("{}", ex);
    assert!(
        rendered.contains("wechat"),
        "Display 应包含自定义 login_type，实际: {rendered}"
    );
    assert!(
        rendered.contains("请先登录"),
        "Display 应包含异常消息，实际: {rendered}"
    );
    // 默认（空 login_type）路径不追加标注，保持既有格式
    let default_ex = NotLoginException::new("token 已过期");
    assert_eq!(
        format!("{}", default_ex),
        "Not logged in: token 已过期",
        "空 login_type 时 Display 格式不得变化"
    );
}

/// 验证 `NotLoginException` 实现 `std::error::Error` trait。
#[test]
fn implements_std_error() {
    fn assert_error<T: std::error::Error>(_: &T) {}
    let ex = NotLoginException::new("test");
    assert_error(&ex);
}

/// 验证 builder 链式调用：new + with_login_type。
#[test]
fn builder_chain_works() {
    let ex = NotLoginException::new("未登录").with_login_type("oauth2");
    assert_eq!(ex.message, "未登录");
    assert_eq!(ex.login_type, "oauth2");
}

// ========================================================================
// GarrisonException 测试
// ========================================================================

/// 验证 `GarrisonException::new` 创建实例并设置可选字段为默认值。
#[test]
fn garrison_exception_new_creates_with_defaults() {
    let ex = GarrisonException::new(-1, "请先登录");
    assert_eq!(ex.code, -1);
    assert_eq!(ex.message, "请先登录");
    assert_eq!(ex.login_type, 0);
    assert_eq!(ex.token_value, None);
    assert_eq!(ex.login_id, None);
    assert!(ex.extras.is_empty());
}

/// 验证 `GarrisonException::new` 接受 String 类型消息。
#[test]
fn garrison_exception_new_accepts_string() {
    let msg = String::from("会话已过期");
    let ex = GarrisonException::new(-1, msg);
    assert_eq!(ex.message, "会话已过期");
}

/// 验证 `GarrisonException` 派生 `Clone`。
#[test]
fn garrison_exception_clone_preserves_fields() {
    let mut ex = GarrisonException::new(-1, "请先登录");
    ex.token_value = Some("T1".to_string());
    ex.login_id = Some("1001".to_string());
    let cloned = ex.clone();
    assert_eq!(cloned.code, -1);
    assert_eq!(cloned.message, "请先登录");
    assert_eq!(cloned.token_value, Some("T1".to_string()));
    assert_eq!(cloned.login_id, Some("1001".to_string()));
}

/// 验证 `GarrisonException` 派生 `Debug`。
#[test]
fn garrison_exception_debug_format_works() {
    let ex = GarrisonException::new(-1, "请先登录");
    let debug = format!("{:?}", ex);
    assert!(debug.contains("GarrisonException"));
    assert!(debug.contains("-1"));
    assert!(debug.contains("请先登录"));
}

/// 验证 `Debug` 对 `login_id`（String 化后可能含 PII）与 `token_value` 同样脱敏。
#[test]
fn garrison_exception_debug_masks_login_id() {
    let ex = GarrisonException::new(-1, "请先登录")
        .with_token("tok-abcdef123456")
        .with_login_id("13800138000");
    let debug = format!("{:?}", ex);
    assert!(
        debug.contains("tok-abcd***"),
        "token_value 应仅输出前 8 字符，实际: {debug}"
    );
    assert!(
        debug.contains("1380***"),
        "login_id 应仅输出前 4 字符（PII 脱敏），实际: {debug}"
    );
    assert!(
        !debug.contains("13800138000"),
        "login_id 全文不得出现在 Debug 输出，实际: {debug}"
    );
}

/// 短 token / 短 login_id 不得全量明文输出（统一整体掩码）。
#[test]
fn garrison_exception_debug_masks_short_values() {
    let ex = GarrisonException::new(-1, "请先登录")
        .with_token("T1")
        .with_login_id("1001");
    let debug = format!("{:?}", ex);
    assert!(
        !debug.contains("\"T1\""),
        "短 token 应整体掩码而非原样输出，实际: {debug}"
    );
    assert!(
        !debug.contains("\"1001\""),
        "短 login_id 应整体掩码而非原样输出，实际: {debug}"
    );
    assert!(debug.contains("***"), "掩码占位符应出现，实际: {debug}");
}

/// Debug 与响应体中 extras 的敏感 key 值必须掩码、
/// 超长值截断（web-axum 未启用时仅验证 Debug 路径）。
#[test]
fn garrison_exception_debug_sanitizes_extras() {
    let ex = GarrisonException::new(-1, "请先登录")
        .with_extra("password", "super-secret")
        .with_extra("device", "web");
    let debug = format!("{:?}", ex);
    assert!(
        !debug.contains("super-secret"),
        "extras 敏感 key 值不得明文进入 Debug 输出，实际: {debug}"
    );
    assert!(
        debug.contains("\"device\": \"web\""),
        "非敏感 extras 应保留，实际: {debug}"
    );
}

/// 验证 `GarrisonException` 的 `Display` 输出格式。
#[test]
fn garrison_exception_display_format() {
    let ex = GarrisonException::new(-1, "请先登录");
    assert_eq!(format!("{}", ex), "Business exception[-1]: 请先登录");
}

/// 验证 `GarrisonException` 通过 `From` 转换为 `GarrisonError::Exception`。
#[test]
fn garrison_exception_into_garrison_error() {
    let ex = GarrisonException::new(-1, "请先登录");
    let err: GarrisonError = ex.into();
    assert!(matches!(err, GarrisonError::Exception(_)));
    if let GarrisonError::Exception(e) = err {
        assert_eq!(e.code, -1);
        assert_eq!(e.message, "请先登录");
    }
}

/// 验证既有 `GarrisonError` 变体不受 `Exception` 新增影响。
#[test]
fn existing_garrison_error_variants_unaffected() {
    let err = GarrisonError::NotLogin("请先登录".to_string());
    assert_eq!(err.to_string(), "Not logged in: 请先登录");
    // 确保新增 Exception 变体不破坏既有 match
    let errors: [GarrisonError; 2] = [
        GarrisonError::NotLogin("a".into()),
        GarrisonError::Exception(Box::new(GarrisonException::new(-1, "b"))),
    ];
    assert_eq!(errors.len(), 2);
}

// ========================================================================
// Builder 链式调用测试
// ========================================================================

/// 验证 Builder 链式构造带上下文的异常。
#[test]
fn builder_chain_with_all_setters() {
    let ex = GarrisonException::new(-1, "请先登录")
        .with_token("T1")
        .with_login_id("1001")
        .with_login_type(1)
        .with_extra("device", "web")
        .build();
    assert_eq!(ex.code, -1);
    assert_eq!(ex.message, "请先登录");
    assert_eq!(ex.token_value, Some("T1".to_string()));
    assert_eq!(ex.login_id, Some("1001".to_string()));
    assert_eq!(ex.login_type, 1);
    assert_eq!(ex.extras.get("device"), Some(&"web".to_string()));
}

/// 验证 `login_id` 为 `Option<String>`（与全局 login_id 的 String 迁移一致，
/// `with_login_id` 同时接受 `&str` 与 `String`）。
#[test]
fn login_id_is_string_typed() {
    let ex = GarrisonException::new(-1, "msg")
        .with_login_id("1001")
        .build();
    assert_eq!(ex.login_id, Some("1001".to_string()));
    let owned: String = "2002".to_string();
    let ex2 = GarrisonException::new(-1, "msg")
        .with_login_id(owned)
        .build();
    assert_eq!(ex2.login_id, Some("2002".to_string()));
}

/// 验证 Builder 接受 String 类型参数。
#[test]
fn builder_accepts_string_args() {
    let token = String::from("T2");
    let key = String::from("ip");
    let val = String::from("127.0.0.1");
    let ex = GarrisonException::new(-1, "msg")
        .with_token(token)
        .with_extra(key, val)
        .build();
    assert_eq!(ex.token_value, Some("T2".to_string()));
    assert_eq!(ex.extras.get("ip"), Some(&"127.0.0.1".to_string()));
}

// ========================================================================
// From<GarrisonError> for GarrisonException 测试
// ========================================================================

/// 验证 `From<GarrisonError>` 对 Exception 变体直接返回原始 GarrisonException。
#[test]
fn from_garrison_error_exception_variant() {
    let original = GarrisonException::new(-1, "请先登录")
        .with_token("T1")
        .with_login_id("1001")
        .build();
    let err = GarrisonError::Exception(Box::new(original.clone()));
    let converted: GarrisonException = err.into();
    assert_eq!(converted.code, -1);
    assert_eq!(converted.message, "请先登录");
    assert_eq!(converted.token_value, Some("T1".to_string()));
    assert_eq!(converted.login_id, Some("1001".to_string()));
}

/// 验证 `From<GarrisonError>` 对非 Exception 变体根据语义映射 code。
#[test]
fn from_garrison_error_other_variants_map_code() {
    // NotLogin → code=-1
    let ex: GarrisonException = GarrisonError::NotLogin("请先登录".to_string()).into();
    assert_eq!(ex.code, -1);
    assert_eq!(ex.message, "请先登录");
    // InvalidToken → code=-1
    let ex: GarrisonException = GarrisonError::InvalidToken("bad token".to_string()).into();
    assert_eq!(ex.code, -1);
    // ExpiredToken → code=-1
    let ex: GarrisonException = GarrisonError::ExpiredToken("expired".to_string()).into();
    assert_eq!(ex.code, -1);
    // NotPermission → code=-2
    let ex: GarrisonException = GarrisonError::NotPermission("无权限".to_string()).into();
    assert_eq!(ex.code, -2);
    // NotRole → code=-2
    let ex: GarrisonException = GarrisonError::NotRole("无角色".to_string()).into();
    assert_eq!(ex.code, -2);
    // 其他 → code=500
    let ex: GarrisonException = GarrisonError::Dao("db down".to_string()).into();
    assert_eq!(ex.code, 500);
}

// ========================================================================
// IntoResponse for GarrisonException 测试
// ========================================================================

/// 验证 code=-1 的 GarrisonException 映射为 401 Unauthorized（独立 IntoResponse 实现）。
#[cfg(feature = "web-axum")]
#[test]
fn garrison_exception_into_response_401() {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let ex = GarrisonException::new(-1, "请先登录").build();
    let response = ex.into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 验证 code=-2 的 GarrisonException 映射为 403 Forbidden（独立 IntoResponse 实现）。
#[cfg(feature = "web-axum")]
#[test]
fn garrison_exception_into_response_403() {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let ex = GarrisonException::new(-2, "无权限").build();
    let response = ex.into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// 验证其他 code 的 GarrisonException 映射为 500 Internal Server Error（独立 IntoResponse 实现）。
#[cfg(feature = "web-axum")]
#[test]
fn garrison_exception_into_response_500() {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let ex = GarrisonException::new(500, "业务异常").build();
    let response = ex.into_response();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// into_response 响应体中 extras 的敏感 key 值必须掩码，
/// 不得原样序列化给客户端。
#[cfg(feature = "web-axum")]
#[tokio::test]
async fn garrison_exception_into_response_masks_extras() {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let ex = GarrisonException::new(-1, "请先登录")
        .with_extra("password", "super-secret")
        .with_extra("device", "web")
        .build();
    let response = ex.into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("读取响应体");
    let text = String::from_utf8(bytes.to_vec()).expect("响应体应为 UTF-8");
    assert!(
        !text.contains("super-secret"),
        "响应体不得包含未掩码的 extras 敏感值，实际: {text}"
    );
    assert!(
        text.contains("***"),
        "extras 敏感值应掩码为 ***，实际: {text}"
    );
    assert!(text.contains("web"), "非敏感 extras 应保留，实际: {text}");
}
