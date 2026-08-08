//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 状态机示例集成测试。

#[tokio::test]
async fn state_machine_runs_successfully() {
    garrison_examples::extension::state_machine::run()
        .await
        .expect("state_machine 示例应成功执行");
}
