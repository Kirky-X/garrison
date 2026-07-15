//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! abac_policy 示例测试。
//!
//! 验证 run() 完整执行（内部已包含 Allow/Deny 断言）。

use bulwark_examples::authorization::abac_policy;

#[tokio::test]
async fn test_run_completes() {
    abac_policy::run().await.unwrap();
}
