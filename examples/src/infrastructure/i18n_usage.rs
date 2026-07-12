//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! i18n_usage 示例（i18n feature）。
//!
//! 演示异常消息国际化：
//! 1. `BulwarkLocale` 枚举（`Zh` 默认 / `En`）
//! 2. `current_locale()` 读取当前线程 locale
//! 3. `set_locale(locale)` 返回 RAII `LocaleGuard`，drop 时自动恢复
//! 4. `translate_error(&BulwarkError)` 依据当前 locale 翻译错误消息
//! 5. 嵌套 `set_locale` 调用（栈式 scope）
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin i18n_usage --features i18n
//! ```

use bulwark::error::BulwarkError;
use bulwark::exception::BulwarkException;
use bulwark::i18n::{current_locale, set_locale, translate_error, BulwarkLocale};

/// 返回一组覆盖主要变体的错误样本，用于演示翻译。
///
/// 包含 `NotLogin` / `NotPermission` / `NotRole` / `InvalidToken` / `ExpiredToken` /
/// `Dao` / `Internal` / `NotImplemented` / `Exception` 等。
pub fn sample_errors() -> Vec<(&'static str, BulwarkError)> {
    vec![
        ("NotLogin", BulwarkError::NotLogin("请先登录".to_string())),
        (
            "NotPermission",
            BulwarkError::NotPermission("user:delete".to_string()),
        ),
        ("NotRole", BulwarkError::NotRole("superadmin".to_string())),
        (
            "InvalidToken",
            BulwarkError::InvalidToken("签名不匹配".to_string()),
        ),
        (
            "ExpiredToken",
            BulwarkError::ExpiredToken("token 已过期".to_string()),
        ),
        ("Dao", BulwarkError::Dao("连接超时".to_string())),
        ("Internal", BulwarkError::Internal("未知错误".to_string())),
        (
            "NotImplemented",
            BulwarkError::NotImplemented("此功能尚未实现".to_string()),
        ),
        (
            "Exception",
            BulwarkError::Exception(BulwarkException::new(-1, "请先登录")),
        ),
    ]
}

/// 运行 i18n_usage 示例。
///
/// 演示 locale 切换 + 错误翻译的完整流程：
/// 1. 默认中文 locale
/// 2. 切换英文 locale
/// 3. 嵌套 locale scope
/// 4. 所有错误变体的中英文翻译对照
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark i18n 国际化示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 默认 locale（Zh）
    // ----------------------------------------------------------------
    println!("[默认 locale] current_locale() = {:?}", current_locale());
    assert_eq!(current_locale(), BulwarkLocale::Zh);
    println!();

    // ----------------------------------------------------------------
    // 2. set_locale + RAII guard
    // ----------------------------------------------------------------
    println!("[set_locale] 切换到英文 + RAII guard:");
    {
        let _guard = set_locale(BulwarkLocale::En);
        println!(
            "    set_locale(En) 后 current_locale() = {:?}",
            current_locale()
        );
        assert_eq!(current_locale(), BulwarkLocale::En);

        let err = BulwarkError::NotLogin("please login first".to_string());
        println!(
            "    translate_error(NotLogin) = \"{}\"",
            translate_error(&err)
        );
        assert_eq!(translate_error(&err), "Not logged in: please login first");
    }
    println!(
        "    guard drop 后 current_locale() = {:?}",
        current_locale()
    );
    assert_eq!(current_locale(), BulwarkLocale::Zh);
    println!();

    // ----------------------------------------------------------------
    // 3. 嵌套 set_locale
    // ----------------------------------------------------------------
    println!("[嵌套] set_locale 支持栈式 scope:");
    {
        let _g1 = set_locale(BulwarkLocale::En);
        println!("    外层 set_locale(En) → {:?}", current_locale());
        assert_eq!(current_locale(), BulwarkLocale::En);

        {
            let _g2 = set_locale(BulwarkLocale::Zh);
            println!("    内层 set_locale(Zh) → {:?}", current_locale());
            assert_eq!(current_locale(), BulwarkLocale::Zh);

            let err = BulwarkError::NotLogin("内层中文".to_string());
            println!("    内层 translate_error = \"{}\"", translate_error(&err));
        }

        println!("    内层 guard drop 后 → {:?}", current_locale());
        assert_eq!(current_locale(), BulwarkLocale::En);
    }
    println!("    外层 guard drop 后 → {:?}", current_locale());
    assert_eq!(current_locale(), BulwarkLocale::Zh);
    println!();

    // ----------------------------------------------------------------
    // 4. 所有错误变体中英文对照
    // ----------------------------------------------------------------
    println!("[翻译对照] 所有错误变体的中英文翻译:");
    let errors = sample_errors();

    println!("\n    [中文 locale (Zh)]:");
    let _zh_guard = set_locale(BulwarkLocale::Zh);
    for (name, err) in &errors {
        println!("    {:<16} → {}", name, translate_error(err));
    }
    drop(_zh_guard);

    println!("\n    [英文 locale (En)]:");
    let _en_guard = set_locale(BulwarkLocale::En);
    for (name, err) in &errors {
        println!("    {:<16} → {}", name, translate_error(err));
    }
    drop(_en_guard);
    println!();

    // ----------------------------------------------------------------
    // 5. Display trait 集成（i18n feature 下 Display 委托 translate_error）
    // ----------------------------------------------------------------
    println!("[Display 集成] BulwarkError::Display 依据 locale 切换:");
    let err = BulwarkError::NotLogin("test".to_string());

    let _zh = set_locale(BulwarkLocale::Zh);
    println!("    Zh locale: err = \"{}\"", err);
    assert_eq!(err.to_string(), "未登录: test");

    drop(_zh);
    let _en = set_locale(BulwarkLocale::En);
    println!("    En locale: err = \"{}\"", err);
    assert_eq!(err.to_string(), "Not logged in: test");
    drop(_en);

    println!();
    println!("=== 示例完成 ===");
    Ok(())
}
