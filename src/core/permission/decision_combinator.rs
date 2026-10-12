// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 决策组合器（forbid 优先语义）：[`DecisionCombinator::combine`] 聚合多个 [`Decision`]，
//! 优先级 Forbid > Deny > Allow（任一 Forbid 即返回第一个 Forbid；无 Forbid 有 Deny 返回第一个
//! Deny；全 Allow 返回 Allow，空列表按 fail-closed 返回 deny）。Forbid 优先确保"强制拒绝"
//! 不可被其他策略的 Allow 覆盖。

use super::{Decision, DecisionReason};

/// 决策组合器，聚合多个 [`Decision`] 为单个最终决策（优先级 Forbid > Deny > Allow）。
pub struct DecisionCombinator;

impl DecisionCombinator {
    /// 聚合多个决策为单个最终决策，优先级 Forbid > Deny > Allow：遇第一个 Forbid 立即返回
    ///（短路），否则返回第一个 Deny，否则 Allow。
    ///
    /// 空列表返回 `Decision::deny(ExplicitDeny)`（fail-closed）：空列表通常表示策略未填充的
    /// bug，fail-closed 确保不因 bug 导致权限绕过。
    pub fn combine(decisions: &[Decision]) -> Decision {
        if decisions.is_empty() {
            return Decision::deny(DecisionReason::ExplicitDeny);
        }
        let mut first_deny: Option<&Decision> = None;
        for d in decisions {
            if d.is_forbid() {
                return d.clone();
            }
            if !d.allowed && first_deny.is_none() {
                first_deny = Some(d);
            }
        }
        if let Some(d) = first_deny {
            return d.clone();
        }
        Decision::allow()
    }
}

#[cfg(test)]
mod tests {
    use super::super::DecisionReason;
    use super::*;

    /// combine 含 Forbid 时返回 Forbid（优先级最高）：[allow, forbid("r1"), deny(NoMatching)]。
    #[test]
    fn combine_returns_forbid_when_any_forbid() {
        let decisions = vec![
            Decision::allow(),
            Decision::forbid("r1"),
            Decision::deny(DecisionReason::NoMatchingPermission),
        ];
        let result = DecisionCombinator::combine(&decisions);
        assert!(!result.allowed, "含 Forbid 时结果应为拒绝");
        assert!(result.is_forbid(), "含 Forbid 时结果 reason 应为 Forbid");
        assert_eq!(
            result.reason,
            DecisionReason::Forbid("r1".to_string()),
            "应返回第一个 Forbid"
        );
    }

    /// 无 Forbid 但有 Deny 时返回第一个 Deny：[allow, deny(NoMatchingPermission), allow]。
    #[test]
    fn combine_returns_deny_when_no_forbid_but_has_deny() {
        let decisions = vec![
            Decision::allow(),
            Decision::deny(DecisionReason::NoMatchingPermission),
            Decision::allow(),
        ];
        let result = DecisionCombinator::combine(&decisions);
        assert!(!result.allowed, "含 Deny 时结果应为拒绝");
        assert!(!result.is_forbid(), "无 Forbid 时结果 reason 不应为 Forbid");
        assert_eq!(
            result.reason,
            DecisionReason::NoMatchingPermission,
            "应返回第一个 Deny 的 reason"
        );
    }

    /// 全部 Allow 时返回 Allow。
    #[test]
    fn combine_returns_allow_when_all_allow() {
        let decisions = vec![Decision::allow(), Decision::allow()];
        let result = DecisionCombinator::combine(&decisions);
        assert!(result.allowed, "全部 Allow 时结果应为允许");
        assert_eq!(
            result.reason,
            DecisionReason::ExplicitAllow,
            "全部 Allow 时 reason 应为 ExplicitAllow"
        );
    }

    /// 空列表返回 Deny（fail-closed 安全默认）。
    #[test]
    fn combine_returns_deny_for_empty_list() {
        let decisions: Vec<Decision> = vec![];
        let result = DecisionCombinator::combine(&decisions);
        assert!(!result.allowed, "空列表应返回 Deny（fail-closed）");
        assert_eq!(
            result.reason,
            DecisionReason::ExplicitDeny,
            "空列表 reason 应为 ExplicitDeny"
        );
    }

    /// 多个 Forbid 时返回第一个（[forbid("r1"), forbid("r2")] → forbid("r1")）。
    #[test]
    fn combine_returns_first_forbid() {
        let decisions = vec![Decision::forbid("r1"), Decision::forbid("r2")];
        let result = DecisionCombinator::combine(&decisions);
        assert!(result.is_forbid(), "多个 Forbid 时结果应为 Forbid");
        assert_eq!(
            result.reason,
            DecisionReason::Forbid("r1".to_string()),
            "应返回第一个 Forbid（r1）"
        );
    }

    /// 多个 Deny 时返回第一个。
    #[test]
    fn combine_returns_first_deny() {
        let decisions = vec![
            Decision::deny(DecisionReason::NoMatchingPermission),
            Decision::deny(DecisionReason::ExplicitDeny),
        ];
        let result = DecisionCombinator::combine(&decisions);
        assert!(!result.allowed, "多个 Deny 时结果应为拒绝");
        assert!(!result.is_forbid(), "无 Forbid 时结果不应为 Forbid");
        assert_eq!(
            result.reason,
            DecisionReason::NoMatchingPermission,
            "应返回第一个 Deny 的 reason（NoMatchingPermission）"
        );
    }

    /// Forbid + Deny 时返回 Forbid（Forbid 优先于 Deny）。
    #[test]
    fn combine_forbid_plus_deny() {
        let decisions = vec![
            Decision::forbid("r"),
            Decision::deny(DecisionReason::NoMatchingPermission),
        ];
        let result = DecisionCombinator::combine(&decisions);
        assert!(result.is_forbid(), "Forbid + Deny 时应返回 Forbid");
        assert_eq!(
            result.reason,
            DecisionReason::Forbid("r".to_string()),
            "应返回 Forbid(\"r\")"
        );
    }

    /// Deny + Allow 时返回 Deny（Deny 优先于 Allow）。
    #[test]
    fn combine_deny_plus_allow() {
        let decisions = vec![
            Decision::deny(DecisionReason::NoMatchingPermission),
            Decision::allow(),
        ];
        let result = DecisionCombinator::combine(&decisions);
        assert!(!result.allowed, "Deny + Allow 时应返回 Deny");
        assert!(!result.is_forbid(), "无 Forbid 时结果不应为 Forbid");
        assert_eq!(
            result.reason,
            DecisionReason::NoMatchingPermission,
            "应返回 Deny 的 reason（NoMatchingPermission）"
        );
    }

    /// Deny 在前、Forbid 在后仍返回 Forbid（始终最高优先级）；回归测试防止 feature-gate
    /// 重新引入导致 Forbid 降级为 Deny。
    #[test]
    fn combine_deny_before_forbid_still_returns_forbid() {
        let decisions = vec![
            Decision::deny(DecisionReason::NoMatchingPermission),
            Decision::forbid("restricted-resource"),
        ];
        let result = DecisionCombinator::combine(&decisions);
        assert!(
            result.is_forbid(),
            "Deny 在前、Forbid 在后时仍应返回 Forbid（Forbid 最高优先级）"
        );
        assert_eq!(
            result.reason,
            DecisionReason::Forbid("restricted-resource".to_string()),
            "应返回 Forbid 的 reason"
        );
    }
}
