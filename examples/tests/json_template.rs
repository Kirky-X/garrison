//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! json_template 示例测试。
//!
//! 验证 run() 完整执行（内部已包含 JSON render/serialize 断言）。

use garrison_examples::infrastructure::json_template;

#[test]
fn test_run_completes() {
    json_template::run().unwrap();
}
