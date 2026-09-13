//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! readme_quickstart 示例测试（README 快速开始回归钉）。
//!
//! 验证 README.md「最小示例」代码完整可运行：
//! 登录 → 校验登录状态 → 校验权限 → 登出。

#![cfg(feature = "cache-memory")]

use garrison_examples::web::readme_quickstart;

// multi_thread：oxcache 内存后端初始化依赖多线程 runtime（与 cache_redis 测试一致）
#[tokio::test(flavor = "multi_thread")]
async fn readme_quickstart_flow_runs() {
    readme_quickstart::run().await.unwrap();
}
