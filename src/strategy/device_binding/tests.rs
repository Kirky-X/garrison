//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 设备绑定模块测试:Disabled 策略行为验证（T012）。

use super::*;

/// `is_new_device` 对任意输入返回 `Ok(false)`。
#[tokio::test]
async fn is_new_device_always_returns_false() {
    let policy = Disabled;
    let result = policy.is_new_device("1001", "web-chrome").await.unwrap();
    assert!(!result, "Disabled is_new_device 应始终返回 false");
}

/// `require_secondary_auth` 对任意输入返回 `Ok(false)`。
#[tokio::test]
async fn require_secondary_auth_always_returns_false() {
    let policy = Disabled;
    let result = policy
        .require_secondary_auth("1001", "mobile-ios")
        .await
        .unwrap();
    assert!(!result, "Disabled require_secondary_auth 应始终返回 false");
}

/// 不同 `login_id` 下 `is_new_device` 与 `require_secondary_auth` 均返回 false。
#[tokio::test]
async fn different_login_ids_all_return_false() {
    let policy = Disabled;
    for login_id in &["1001", "2002", "anonymous", ""] {
        let is_new = policy.is_new_device(login_id, "web").await.unwrap();
        assert!(
            !is_new,
            "login_id={} 时 is_new_device 应返回 false",
            login_id
        );
        let require = policy
            .require_secondary_auth(login_id, "web")
            .await
            .unwrap();
        assert!(
            !require,
            "login_id={} 时 require_secondary_auth 应返回 false",
            login_id
        );
    }
}

/// 不同 `device_id` 下 `is_new_device` 与 `require_secondary_auth` 均返回 false。
#[tokio::test]
async fn different_device_ids_all_return_false() {
    let policy = Disabled;
    for device_id in &["web-chrome", "mobile-ios", "", "unknown-device"] {
        let is_new = policy.is_new_device("1001", device_id).await.unwrap();
        assert!(
            !is_new,
            "device_id={} 时 is_new_device 应返回 false",
            device_id
        );
        let require = policy
            .require_secondary_auth("1001", device_id)
            .await
            .unwrap();
        assert!(
            !require,
            "device_id={} 时 require_secondary_auth 应返回 false",
            device_id
        );
    }
}
