//! permission_check 示例测试。
//!
//! 验证 run() 完整执行（内部已包含权限/角色校验断言）。

use bulwark_examples::permission_check;

#[tokio::test]
async fn test_run_completes() {
    permission_check::run().await.unwrap();
}
