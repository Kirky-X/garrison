//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 状态机生命周期完整流程示例：Token 状态机 + User 状态机。
//!
//! 演示 Garrison 状态机模块的完整业务链路：
//! 1. Token 状态机：Issued → Active → Refreshed → Revoked（全生命周期）
//! 2. Token 状态机：非法转换拦截（Expired 终态不可恢复）
//! 3. User 状态机：Pending → Active → Suspended → Active → Inactive → Deleted
//! 4. User 状态机：非法转换拦截（Deleted 终态不可恢复）
//! 5. 业务场景：Token 续期 + 用户封禁联动
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin state_machine --features full
//! ```

use garrison::error::GarrisonResult;
use garrison::state::{TokenState, UserStatus};

/// 运行状态机完整流程示例。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison 状态机生命周期完整流程 ===\n");

    // ================================================================
    // 场景一：Token 状态机完整生命周期
    // ================================================================
    demo_token_lifecycle()?;

    // ================================================================
    // 场景二：Token 非法转换拦截
    // ================================================================
    demo_token_invalid_transitions()?;

    // ================================================================
    // 场景三：User 状态机完整生命周期
    // ================================================================
    demo_user_lifecycle()?;

    // ================================================================
    // 场景四：User 非法转换拦截
    // ================================================================
    demo_user_invalid_transitions()?;

    // ================================================================
    // 场景五：业务场景联动
    // ================================================================
    demo_business_scenario()?;

    println!("\n=== 状态机生命周期演示完成 ===");
    println!("已展示功能：");
    println!("  • Token 状态机（Issued → Active → Refreshed → Revoked）");
    println!("  • Token 非法转换拦截（终态不可恢复）");
    println!("  • User 状态机（Pending → Active → Suspended → Inactive → Deleted）");
    println!("  • User 非法转换拦截（Deleted 终态不可恢复）");
    println!("  • 业务场景联动（Token 续期 + 用户封禁）");

    Ok(())
}

/// 场景一：Token 状态机完整生命周期。
///
/// 模拟一个 Token 从签发到最终撤销的完整路径：
/// Issued → Active → Active(续期) → Refreshed → Revoked
fn demo_token_lifecycle() -> GarrisonResult<()> {
    println!("--- 场景一：Token 完整生命周期 ---");

    // 1. Token 签发
    let state = TokenState::Issued;
    println!("[1] Token 签发 → {}", state);
    assert_eq!(state, TokenState::Issued);

    // 2. 客户端首次携带使用 → Active
    let state = state.transition_to(TokenState::Active)?;
    println!("[2] 首次使用 → {}（客户端首次携带 Token 访问 API）", state);
    assert_eq!(state, TokenState::Active);

    // 3. 续期（每次访问 +30min TTL）
    let state = state.transition_to(TokenState::Active)?;
    println!("[3] 续期 → {}（访问续期，TTL +30min）", state);

    // 4. Refresh Token → 旧 Token 变为 Refreshed
    let state = state.transition_to(TokenState::Refreshed)?;
    println!(
        "[4] Refresh → {}（新 Token 已签发，旧 Token 标记为 Refreshed）",
        state
    );
    assert_eq!(state, TokenState::Refreshed);

    // 5. 旧 Token 立即作废
    let state = state.transition_to(TokenState::Revoked)?;
    println!(
        "[5] 旧 Token 作废 → {}（Refreshed → Revoked，立即生效）",
        state
    );
    assert_eq!(state, TokenState::Revoked);

    // 6. Revoked 为终态
    assert!(!state.can_transition_to(TokenState::Active));
    println!("    ✓ Revoked 为终态，不可再转换\n");

    Ok(())
}

/// 场景二：Token 非法转换拦截。
///
/// 验证各种非法转换路径被正确拒绝。
fn demo_token_invalid_transitions() -> GarrisonResult<()> {
    println!("--- 场景二：Token 非法转换拦截 ---");

    // 1. Issued 不能直接到 Expired/Revoked/Refreshed
    let issued = TokenState::Issued;
    assert!(!issued.can_transition_to(TokenState::Expired));
    println!("[1] Issued → Expired：✗（必须先经过 Active）");
    assert!(!issued.can_transition_to(TokenState::Revoked));
    println!("[2] Issued → Revoked：✗（必须先经过 Active）");

    // 2. Expired 为终态，不可转换
    let expired = TokenState::Expired;
    assert!(!expired.can_transition_to(TokenState::Active));
    assert!(!expired.can_transition_to(TokenState::Revoked));
    println!("[3] Expired → *：✗（终态，不可恢复）");

    // 3. Revoked 为终态
    let revoked = TokenState::Revoked;
    assert!(!revoked.can_transition_to(TokenState::Active));
    println!("[4] Revoked → *：✗（终态，不可恢复）");

    // 4. Refreshed 只能到 Revoked
    let refreshed = TokenState::Refreshed;
    assert!(!refreshed.can_transition_to(TokenState::Active));
    assert!(!refreshed.can_transition_to(TokenState::Expired));
    assert!(refreshed.can_transition_to(TokenState::Revoked));
    println!("[5] Refreshed → Revoked：✓（唯一合法路径）");
    println!("[6] Refreshed → Active/Expired：✗（旧 Token 立即作废）");

    // 5. transition_to 返回正确错误
    let result = TokenState::Expired.transition_to(TokenState::Active);
    assert!(result.is_err());
    let err = result.unwrap_err();
    println!("    ✓ transition_to 非法路径返回: {}", err);

    println!();
    Ok(())
}

/// 场景三：User 状态机完整生命周期。
///
/// 模拟用户从注册到注销的完整路径：
/// Pending → Active → Suspended → Active → Inactive → Deleted
fn demo_user_lifecycle() -> GarrisonResult<()> {
    println!("--- 场景三：User 完整生命周期 ---");

    // 1. 注册 → Pending
    let status = UserStatus::Pending;
    println!("[1] 用户注册 → {}（待激活）", status);

    // 2. 邮箱验证 → Active
    let status = status.transition_to(UserStatus::Active)?;
    println!("[2] 邮箱验证通过 → {}（活跃）", status);

    // 3. 违规 → Suspended
    let status = status.transition_to(UserStatus::Suspended)?;
    println!("[3] 违规行为 → {}（管理员封禁）", status);

    // 4. 申诉成功 → Active
    let status = status.transition_to(UserStatus::Active)?;
    println!("[4] 申诉成功 → {}（管理员解封）", status);

    // 5. 长期未登录 → Inactive
    let status = status.transition_to(UserStatus::Inactive)?;
    println!("[5] 90天未登录 → {}（休眠）", status);

    // 6. 用户注销 → Deleted
    let status = status.transition_to(UserStatus::Deleted)?;
    println!("[6] 用户注销 → {}（终态）", status);
    assert_eq!(status, UserStatus::Deleted);

    println!("    ✓ Deleted 为终态，生命周期结束\n");

    Ok(())
}

/// 场景四：User 非法转换拦截。
fn demo_user_invalid_transitions() -> GarrisonResult<()> {
    println!("--- 场景四：User 非法转换拦截 ---");

    // 1. Pending 不能直接到 Inactive/Deleted
    let pending = UserStatus::Pending;
    assert!(!pending.can_transition_to(UserStatus::Inactive));
    println!("[1] Pending → Inactive：✗（必须先经 Active 或 Suspended）");
    assert!(!pending.can_transition_to(UserStatus::Deleted));
    println!("[2] Pending → Deleted：✗（必须先经 Active 或 Suspended）");

    // 2. Active 不能回到 Pending
    let active = UserStatus::Active;
    assert!(!active.can_transition_to(UserStatus::Pending));
    println!("[3] Active → Pending：✗（不可逆）");

    // 3. Suspended 不能直接到 Inactive
    let suspended = UserStatus::Suspended;
    assert!(!suspended.can_transition_to(UserStatus::Inactive));
    println!("[4] Suspended → Inactive：✗（必须先经 Active）");

    // 4. Deleted 为终态
    let deleted = UserStatus::Deleted;
    assert!(!deleted.can_transition_to(UserStatus::Active));
    assert!(!deleted.can_transition_to(UserStatus::Pending));
    println!("[5] Deleted → *：✗（终态，不可恢复）");

    // 5. transition_to 返回正确错误
    let result = UserStatus::Deleted.transition_to(UserStatus::Active);
    assert!(result.is_err());
    println!("    ✓ transition_to 非法路径返回: {}", result.unwrap_err());

    println!();
    Ok(())
}

/// 场景五：业务场景联动。
///
/// 模拟真实业务中 Token 状态与 User 状态的联动关系：
/// - 用户被封禁时，其所有 Active Token 应被撤销
/// - Token 续期时需检查 User 状态是否为 Active
fn demo_business_scenario() -> GarrisonResult<()> {
    println!("--- 场景五：业务场景联动 ---");

    // 模拟：用户活跃 → Token 正常使用 → 用户被封禁 → Token 强制撤销
    println!("[1] 用户活跃期 Token 正常续期...");
    let mut user_status = UserStatus::Active;
    let mut token_state = TokenState::Issued;

    // Token 激活
    token_state = token_state.transition_to(TokenState::Active)?;
    println!("    User={}, Token={}", user_status, token_state);

    // Token 续期
    token_state = token_state.transition_to(TokenState::Active)?;
    println!("    Token 续期 → {}", token_state);

    // 用户被封禁
    println!("\n[2] 用户违规，管理员封禁...");
    user_status = user_status.transition_to(UserStatus::Suspended)?;
    println!("    User → {}", user_status);

    // Token 必须撤销（不能继续续期）
    println!("[3] 用户封禁联动：强制撤销所有 Token...");
    token_state = token_state.transition_to(TokenState::Revoked)?;
    println!(
        "    Token → {}（因 User=Suspended，Token 不可续期）",
        token_state
    );

    // 验证：被封禁用户的 Token 不能续期
    assert_eq!(token_state, TokenState::Revoked);
    assert!(!token_state.can_transition_to(TokenState::Active));
    println!("    ✓ 被封禁用户的 Token 已作废，无法恢复");

    // 模拟另一场景：用户休眠后重新登录
    println!("\n[4] 用户休眠后重新登录...");
    let mut user_status = UserStatus::Inactive;
    user_status = user_status.transition_to(UserStatus::Active)?;
    println!("    User: Inactive → {}（重新登录激活）", user_status);

    // 签发新 Token
    let mut token_state = TokenState::Issued;
    token_state = token_state.transition_to(TokenState::Active)?;
    println!("    新 Token 签发 → {}", token_state);

    println!();
    Ok(())
}
