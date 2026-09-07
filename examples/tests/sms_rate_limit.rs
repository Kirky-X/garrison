//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! sms_rate_limit 示例测试（sms-rate-limit feature）。
//!
//! 验证 run() 完整执行（key 空间设计/限速配置/使用流程说明，无外部短信网关依赖）。

#![cfg(feature = "sms-rate-limit")]

use garrison_examples::infrastructure::sms_rate_limit;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    sms_rate_limit::run().await.unwrap();
}
