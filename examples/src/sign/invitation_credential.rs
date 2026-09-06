//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 邀请码定向注册示例：演示 InvitationHandler 的签发/校验/消费/吊销与注册编排钩子。
//!
//! 对应模块：`src/protocol/invitation/mod.rs`（feature: protocol-invitation）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin invitation_credential --features protocol-invitation
//! ```

use async_trait::async_trait;
use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::GarrisonResult;
use garrison::protocol::invitation::{
    InvitationHandler, InvitationRecord, InvitationRedeemHook, InvitationSpec,
};
use std::sync::Arc;
use tokio::sync::Mutex;

// ============================================================================
// 注册编排钩子：应用侧在 redeem 回调中完成账号创建与角色授予
// ============================================================================

struct AccountProvisioningHook {
    accounts: Mutex<Vec<String>>,
}

#[async_trait]
impl InvitationRedeemHook for AccountProvisioningHook {
    async fn on_redeem(&self, record: &InvitationRecord) -> GarrisonResult<()> {
        let redeemer = record
            .redeemed_by
            .last()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        // 应用侧：创建账号、写入凭证、授予 bound_roles（此处以内存表模拟）
        self.accounts.lock().await.push(format!(
            "{redeemer} roles={:?} tenant={:?}",
            record.bound_roles, record.tenant_id
        ));
        Ok(())
    }
}

/// 运行邀请码定向注册示例。
///
/// 演示 create（单/批量）/ validate（只读预检）/ redeem（原子消费 + hook 编排）/
/// revoke（幂等吊销）与 list（管理面）全链路。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 邀请码定向注册示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构建 InvitationHandler（注入注册编排钩子）
    // ----------------------------------------------------------------
    // DAO 使用 garrison 内置的生产级内存实现（含原子 get_and_delete / set_if_absent / incr）
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let hook = Arc::new(AccountProvisioningHook {
        accounts: Mutex::new(Vec::new()),
    });
    let handler = InvitationHandler::new(dao).with_hook(hook.clone());
    println!("[1] InvitationHandler 构建完成（默认防爆破：10 次 / 600 秒窗口）\n");

    // ----------------------------------------------------------------
    // 2. create 签发单次邀请码（TTL 600 秒，绑定角色与租户）
    // ----------------------------------------------------------------
    let spec = InvitationSpec {
        issuer_id: "admin-1".to_string(),
        tenant_id: Some("tenant-acme".to_string()),
        bound_roles: vec!["member".to_string()],
        max_uses: 1, // 单次有效
        ttl_seconds: 600,
    };
    let invitation = handler.create(spec).await?;
    println!("[2] create（单次邀请码）:");
    println!(
        "    code         = {}-{}",
        &invitation.code[..4],
        &invitation.code[4..]
    );
    println!("    issuer_id    = {}", invitation.issuer_id);
    println!("    max_uses     = {}（单次）", invitation.max_uses);
    println!("    expires_at   = {}（600 秒后）", invitation.expires_at);
    println!("    ✓ 广播 InvitationCreated 事件（需 listener feature）\n");

    // ----------------------------------------------------------------
    // 3. validate 只读预检（注册页提交前校验，不消费）
    // ----------------------------------------------------------------
    let report = handler.validate(&invitation.code).await?;
    println!("[3] validate（只读预检）:");
    println!("    有效 = {}", report.is_valid());
    assert!(report.is_valid());
    // 小写 + 连字符输入同样命中（输入规范化）
    let display = format!(
        "{}-{}-{}",
        &invitation.code[..2].to_lowercase(),
        &invitation.code[2..6].to_lowercase(),
        &invitation.code[6..].to_lowercase()
    );
    assert!(handler.validate(&display).await?.is_valid());
    println!("    输入规范化（小写/连字符）→ 同样命中 ✓\n");

    // ----------------------------------------------------------------
    // 4. redeem 原子消费（hook 编排账号创建），二次消费被拒
    // ----------------------------------------------------------------
    let redeemed = handler
        .redeem(&invitation.code, "user-1001", "10.0.0.8")
        .await?;
    println!("[4] redeem（原子消费 + 注册编排）:");
    println!("    used_count   = {}", redeemed.used_count);
    println!("    redeemed_by  = {:?}", redeemed.redeemed_by);
    assert_eq!(redeemed.used_count, 1);
    let accounts = hook.accounts.lock().await;
    println!("    hook 已创建账号: {:?}", *accounts);
    assert_eq!(accounts.len(), 1);
    drop(accounts);
    // 二次消费：单次码已删除 → NotFound
    let again = handler
        .redeem(&invitation.code, "user-1002", "10.0.0.9")
        .await;
    assert!(again.is_err());
    println!("    二次消费 → Err（单次码已删除，防 double-spend）✓\n");

    // ----------------------------------------------------------------
    // 5. create_batch 批量签发 N 次有效邀请码
    // ----------------------------------------------------------------
    let batch_spec = InvitationSpec {
        issuer_id: "admin-1".to_string(),
        tenant_id: None,
        bound_roles: vec!["guest".to_string()],
        max_uses: 5, // 5 次有效
        ttl_seconds: 3600,
    };
    let batch = handler.create_batch(batch_spec, 3).await?;
    println!("[5] create_batch（3 个 5 次有效的团队码）:");
    assert_eq!(batch.len(), 3);
    // 消费其中 5 次后再消费 → Exhausted
    let code = &batch[0].code;
    for i in 0..5 {
        handler
            .redeem(code, &format!("user-{i}"), "10.0.0.7")
            .await?;
    }
    let exhausted = handler.redeem(code, "user-overflow", "10.0.0.7").await;
    assert!(exhausted.is_err());
    println!("    第 5 次消费成功后第 6 次 → Err（次数用尽）✓\n");

    // ----------------------------------------------------------------
    // 6. list 管理面（按邀请人列出）与 revoke 吊销
    // ----------------------------------------------------------------
    let listed = handler.list("admin-1").await?;
    println!("[6] list / revoke:");
    println!(
        "    admin-1 名下邀请码数 = {}（含 2 个未消费团队码）",
        listed.len()
    );
    assert_eq!(listed.len(), 2);
    // 吊销剩余团队码
    handler.revoke(&batch[1].code, "admin-1").await?;
    let report = handler.validate(&batch[1].code).await?;
    assert!(!report.is_valid());
    println!("    revoke 后 validate → Revoked ✓");
    // 重复吊销幂等
    handler.revoke(&batch[1].code, "admin-1").await?;
    println!("    重复 revoke → Ok(())（幂等语义）✓\n");

    println!("=== 示例执行完成 ===");
    Ok(())
}
