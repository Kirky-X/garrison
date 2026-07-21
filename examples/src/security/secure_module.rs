//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 安全模块示例：演示脱敏 / XSS 防护 / 输入消毒 / 同形异义字检测。
//!
//! 对应模块：`src/secure/`（各 `secure-*` feature 开启时可用）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin secure_module --features full
//! ```

use garrison::error::GarrisonResult;

#[cfg(feature = "secure-masking")]
use garrison::secure::masking::{MaskType, SensitiveDataMasker};

#[cfg(feature = "secure-xss")]
use garrison::secure::xss::{XssMode, XssProtector};

#[cfg(feature = "secure-sanitize")]
use garrison::secure::sanitize::sanitize_input;

#[cfg(feature = "secure-confusable")]
use garrison::secure::confusable::check_confusable;

/// 运行安全模块示例。
///
/// 演示：
/// 1. SensitiveDataMasker：手机号 / 身份证 / 邮箱 / 银行卡脱敏
/// 2. XssProtector：全量转义 + 白名单过滤
/// 3. sanitize_input：移除 null 字节 / 控制字符 / trim / 长度限制
/// 4. check_confusable：检测 Unicode 同形异义字
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 安全模块示例 ===\n");

    // 1. 敏感数据脱敏
    #[cfg(feature = "secure-masking")]
    {
        println!("[1] SensitiveDataMasker 敏感数据脱敏:");
        let masker = SensitiveDataMasker::new();

        let phone = masker.mask_value("13812345678", &MaskType::Phone);
        println!("    手机号   13812345678     → {}", phone);
        assert_eq!(phone, "138****5678");

        let id_card = masker.mask_value("110101199001011234", &MaskType::IdCard);
        println!("    身份证   110101199001011234 → {}", id_card);
        assert_eq!(id_card, "110***********1234");

        let email = masker.mask_value("alice@example.com", &MaskType::Email);
        println!("    邮箱     alice@example.com → {}", email);
        assert_eq!(email, "a***@example.com");

        let bank = masker.mask_value("6222021234567890", &MaskType::BankCard);
        println!("    银行卡   6222021234567890  → {}", bank);
        assert_eq!(bank, "622202******7890");
        println!();
    }

    // 2. XSS 防护
    #[cfg(feature = "secure-xss")]
    {
        println!("[2] XssProtector XSS 防护:");

        let escape_all = XssProtector::new(XssMode::EscapeAll);
        let escaped = escape_all.sanitize("<script>alert('xss')</script>");
        println!("    EscapeAll: <script>alert('xss')</script>");
        println!("      → {}", escaped);
        assert_eq!(
            escaped,
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        );

        let whitelist = XssProtector::new(XssMode::Whitelist(vec!["b", "i"]));
        let filtered = whitelist.sanitize("<b>bold</b><script>x</script>");
        println!("    Whitelist [b,i]: <b>bold</b><script>x</script>");
        println!("      → {}", filtered);
        assert_eq!(filtered, "<b>bold</b>&lt;script&gt;x&lt;/script&gt;");
        println!();
    }

    // 3. 输入消毒
    #[cfg(feature = "secure-sanitize")]
    {
        println!("[3] sanitize_input 输入消毒:");

        let cleaned = sanitize_input("  hello\0world  ", 100)?;
        println!("    '  hello\\0world  ' → '{}'", cleaned);
        assert_eq!(cleaned, "helloworld");

        let ctrl = sanitize_input("a\x01b\x02c", 100)?;
        println!("    'a\\x01b\\x02c' → '{}'", ctrl);
        assert_eq!(ctrl, "abc");

        let too_long = sanitize_input("hello world", 5);
        println!("    'hello world' (max=5) → {:?}", too_long.is_err());
        assert!(too_long.is_err());
        println!();
    }

    // 4. 同形异义字检测
    #[cfg(feature = "secure-confusable")]
    {
        println!("[4] check_confusable 同形异义字检测:");

        let clean = check_confusable("user:read");
        println!("    'user:read' → {} 个警告（纯 ASCII）", clean.len());
        assert!(clean.is_empty());

        // 首字符为 Cyrillic 'а' (U+0430)，视觉与 Latin 'a' 相同
        let suspicious = check_confusable("\u{0430}dmin");
        println!(
            "    'аdmin'（首字符 Cyrillic а）→ {} 个警告",
            suspicious.len()
        );
        assert!(!suspicious.is_empty());
        println!(
            "      char={} → confusable_with={}",
            suspicious[0].char, suspicious[0].confusable_with
        );
        assert_eq!(suspicious[0].confusable_with, 'a');
        println!();
    }

    println!("=== 示例执行完成 ===");
    Ok(())
}
