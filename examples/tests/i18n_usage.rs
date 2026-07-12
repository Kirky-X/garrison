//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! i18n_usage 示例测试（i18n feature）。
//!
//! 验证 BulwarkLocale + set_locale + translate_error 行为：
//! - 默认 locale 为 Zh
//! - set_locale 返回 RAII guard，drop 后恢复
//! - 嵌套 set_locale 支持
//! - translate_error 中英文翻译正确
//! - Display trait 依据 locale 切换
//!
//! 注：i18n 使用 thread_local 栈，测试间天然隔离，无需 `#[serial]`。

#![cfg(feature = "i18n")]

use bulwark::error::BulwarkError;
use bulwark::exception::BulwarkException;
use bulwark::i18n::{current_locale, set_locale, translate_error, BulwarkLocale};

#[test]
fn test_default_locale_is_zh() {
    // 未调用 set_locale 时栈为空，返回默认值
    let locale = current_locale();
    assert_eq!(locale, BulwarkLocale::Zh);
}

#[test]
fn test_set_locale_changes_and_restores_on_drop() {
    let original = current_locale();
    {
        let _guard = set_locale(BulwarkLocale::En);
        assert_eq!(current_locale(), BulwarkLocale::En);
    }
    assert_eq!(current_locale(), original);
}

#[test]
fn test_set_locale_nesting() {
    let original = current_locale();
    {
        let _g1 = set_locale(BulwarkLocale::En);
        assert_eq!(current_locale(), BulwarkLocale::En);
        {
            let _g2 = set_locale(BulwarkLocale::Zh);
            assert_eq!(current_locale(), BulwarkLocale::Zh);
        }
        assert_eq!(current_locale(), BulwarkLocale::En);
    }
    assert_eq!(current_locale(), original);
}

#[test]
fn test_translate_error_zh_not_login() {
    let _guard = set_locale(BulwarkLocale::Zh);
    let err = BulwarkError::NotLogin("请先登录".to_string());
    assert_eq!(translate_error(&err), "未登录: 请先登录");
}

#[test]
fn test_translate_error_en_not_login() {
    let _guard = set_locale(BulwarkLocale::En);
    let err = BulwarkError::NotLogin("please login first".to_string());
    assert_eq!(translate_error(&err), "Not logged in: please login first");
}

#[test]
fn test_translate_error_zh_all_variants() {
    let _guard = set_locale(BulwarkLocale::Zh);
    let cases = vec![
        (BulwarkError::NotLogin("a".into()), "未登录: a"),
        (BulwarkError::NotPermission("a".into()), "无权限: a"),
        (BulwarkError::NotRole("a".into()), "无角色: a"),
        (BulwarkError::InvalidToken("a".into()), "Token 无效: a"),
        (BulwarkError::ExpiredToken("a".into()), "Token 已过期: a"),
        (BulwarkError::Dao("a".into()), "DAO 错误: a"),
        (BulwarkError::Internal("a".into()), "内部错误: a"),
        (BulwarkError::NotImplemented("a".into()), "未实现: a"),
    ];
    for (err, expected) in cases {
        assert_eq!(translate_error(&err), expected, "mismatch for {:?}", err);
    }
}

#[test]
fn test_translate_error_en_all_variants() {
    let _guard = set_locale(BulwarkLocale::En);
    let cases = vec![
        (BulwarkError::NotLogin("a".into()), "Not logged in: a"),
        (
            BulwarkError::NotPermission("a".into()),
            "Permission denied: a",
        ),
        (BulwarkError::NotRole("a".into()), "Role denied: a"),
        (BulwarkError::InvalidToken("a".into()), "Invalid token: a"),
        (BulwarkError::ExpiredToken("a".into()), "Token expired: a"),
        (BulwarkError::Dao("a".into()), "DAO error: a"),
        (BulwarkError::Internal("a".into()), "Internal error: a"),
        (
            BulwarkError::NotImplemented("a".into()),
            "Not implemented: a",
        ),
    ];
    for (err, expected) in cases {
        assert_eq!(translate_error(&err), expected, "mismatch for {:?}", err);
    }
}

#[test]
fn test_translate_error_exception_variant_zh() {
    let _guard = set_locale(BulwarkLocale::Zh);
    let err = BulwarkError::Exception(BulwarkException::new(-1, "请先登录"));
    assert_eq!(translate_error(&err), "业务异常[-1]: 请先登录");
}

#[test]
fn test_translate_error_exception_variant_en() {
    let _guard = set_locale(BulwarkLocale::En);
    let err = BulwarkError::Exception(BulwarkException::new(-1, "please login"));
    assert_eq!(
        translate_error(&err),
        "Business exception[-1]: please login"
    );
}

#[test]
fn test_display_trait_switches_with_locale() {
    let err = BulwarkError::NotLogin("test".to_string());

    let _zh = set_locale(BulwarkLocale::Zh);
    assert_eq!(err.to_string(), "未登录: test");
    drop(_zh);

    let _en = set_locale(BulwarkLocale::En);
    assert_eq!(err.to_string(), "Not logged in: test");
}

#[test]
fn test_sample_errors_returns_non_empty() {
    let errors = bulwark_examples::infrastructure::i18n_usage::sample_errors();
    assert!(!errors.is_empty(), "sample_errors 应返回非空列表");
    // 验证包含关键变体
    let names: Vec<&str> = errors.iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&"NotLogin"));
    assert!(names.contains(&"NotPermission"));
    assert!(names.contains(&"Exception"));
}
