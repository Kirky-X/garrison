//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! three_tier_cache 示例测试（three-tier-cache feature）。
//!
//! 验证 run() 完整执行（缓存配置/查询流程/构造与集成说明，纯本地逻辑）。

#![cfg(feature = "three-tier-cache")]

use garrison_examples::infrastructure::three_tier_cache;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    three_tier_cache::run().await.unwrap();
}
