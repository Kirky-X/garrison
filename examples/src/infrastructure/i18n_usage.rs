// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! i18n_usage 示例（i18n 基础层无条件编译，无需 feature）。
//!
//! 演示异常消息国际化：GarrisonLocale（Zh 默认 / En）、current_locale 读取、set_locale 返回 RAII guard（drop 自动恢复）、translate_error 依据 locale 翻译、嵌套栈式 scope。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin i18n_usage --features i18n
//! ```
use garrison::error::GarrisonError;
use garrison::exception::GarrisonException;
use garrison::i18n::{current_locale, detect_locale, set_locale, translate_error, GarrisonLocale};

/// 返回覆盖主要变体的错误样本（NotLogin / NotPermission / NotRole / InvalidToken / ExpiredToken / Dao / Internal / NotImplemented / Exception），用于演示翻译。
pub fn sample_errors() -> Vec<(&'static str, GarrisonError)> {
    vec![
        ("NotLogin", GarrisonError::NotLogin("请先登录".to_string())),
        (
            "NotPermission",
            GarrisonError::NotPermission("user:delete".to_string()),
        ),
        ("NotRole", GarrisonError::NotRole("superadmin".to_string())),
        (
            "InvalidToken",
            GarrisonError::InvalidToken("签名不匹配".to_string()),
        ),
        (
            "ExpiredToken",
            GarrisonError::ExpiredToken("token 已过期".to_string()),
        ),
        ("Dao", GarrisonError::Dao("连接超时".to_string())),
        ("Internal", GarrisonError::Internal("未知错误".to_string())),
        (
            "NotImplemented",
            GarrisonError::NotImplemented("此功能尚未实现".to_string()),
        ),
        (
            "Exception",
            GarrisonError::Exception(Box::new(GarrisonException::new(-1, "请先登录"))),
        ),
    ]
}

/// 运行 i18n_usage 示例：系统语言检测、set_locale RAII guard、嵌套 scope、错误变体中英文翻译对照、Display 集成。
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Garrison i18n 国际化示例 ===\n");

    // 1. 系统语言检测（默认跟随系统，检测失败回退 En）
    let detected = detect_locale();
    println!(
        "[系统语言检测] detect_locale() = {:?}（无显式 set_locale 时 current_locale() 与之\
         一致，显式设置优先于检测值）",
        detected
    );
    assert_eq!(current_locale(), detected);
    println!();

    // 2. set_locale + RAII guard
    println!("[set_locale] 切换到英文 + RAII guard:");
    {
        let _guard = set_locale(GarrisonLocale::En);
        println!(
            "    set_locale(En) 后 current_locale() = {:?}",
            current_locale()
        );
        assert_eq!(current_locale(), GarrisonLocale::En);

        let err = GarrisonError::NotLogin("please login first".to_string());
        println!(
            "    translate_error(NotLogin) = \"{}\"",
            translate_error(&err)
        );
        assert_eq!(translate_error(&err), "Not logged in: please login first");
    }
    println!(
        "    guard drop 后 current_locale() = {:?}（回到缓存的检测值）",
        current_locale()
    );
    assert_eq!(current_locale(), detected);
    println!();

    // 3. 嵌套 set_locale
    println!("[嵌套] set_locale 支持栈式 scope:");
    {
        let _g1 = set_locale(GarrisonLocale::En);
        println!("    外层 set_locale(En) → {:?}", current_locale());
        assert_eq!(current_locale(), GarrisonLocale::En);

        {
            let _g2 = set_locale(GarrisonLocale::Zh);
            println!("    内层 set_locale(Zh) → {:?}", current_locale());
            assert_eq!(current_locale(), GarrisonLocale::Zh);

            let err = GarrisonError::NotLogin("内层中文".to_string());
            println!("    内层 translate_error = \"{}\"", translate_error(&err));
        }

        println!("    内层 guard drop 后 → {:?}", current_locale());
        assert_eq!(current_locale(), GarrisonLocale::En);
    }
    println!("    外层 guard drop 后 → {:?}", current_locale());
    assert_eq!(current_locale(), detected);
    println!();

    // 4. 所有错误变体中英文对照
    println!("[翻译对照] 所有错误变体的中英文翻译:");
    let errors = sample_errors();

    println!("\n    [中文 locale (Zh)]:");
    let _zh_guard = set_locale(GarrisonLocale::Zh);
    for (name, err) in &errors {
        println!("    {:<16} → {}", name, translate_error(err));
    }
    drop(_zh_guard);

    println!("\n    [英文 locale (En)]:");
    let _en_guard = set_locale(GarrisonLocale::En);
    for (name, err) in &errors {
        println!("    {:<16} → {}", name, translate_error(err));
    }
    drop(_en_guard);
    println!();

    // 5. Display trait 集成（i18n feature 下 Display 委托 translate_error）
    println!("[Display 集成] GarrisonError::Display 依据 locale 切换:");
    let err = GarrisonError::NotLogin("test".to_string());

    let _zh = set_locale(GarrisonLocale::Zh);
    println!("    Zh locale: err = \"{}\"", err);
    assert_eq!(err.to_string(), "未登录: test");

    drop(_zh);
    let _en = set_locale(GarrisonLocale::En);
    println!("    En locale: err = \"{}\"", err);
    assert_eq!(err.to_string(), "Not logged in: test");
    drop(_en);

    println!();
    println!("=== 示例完成 ===");
    Ok(())
}
