//! 角色层级 Repository 模块（v0.5.0 新增，依据 proposal H6）。
//!
//! 提供 `role_hierarchy` 表的 CRUD 与 TC（传递闭包）预计算能力。
//! 依据 cedar 工程思想：登录时预计算角色层级的间接祖先并缓存到 oxcache，
//! 避免每次权限校验都做 DFS。
//!
//! ## 核心抽象
//!
//! - [`RoleHierarchyRecord`]：`role_hierarchy` 表行结构（child_role → parent_role + tenant_id）
//! - [`RoleHierarchyService`]：TC 预计算 + 缓存 + 增量失效（T045-T050 实现）
//!
//! ## 表结构
//!
//! ```sql
//! CREATE TABLE role_hierarchy (
//!     tenant_id INTEGER NOT NULL DEFAULT 0,
//!     child_role TEXT NOT NULL,
//!     parent_role TEXT NOT NULL,
//!     PRIMARY KEY (tenant_id, child_role, parent_role)
//! );
//! ```

// ============================================================================
// Row struct 定义（依据 proposal H6 + tasks T042）
// ============================================================================

/// `role_hierarchy` 表行结构（T042 Green）。
///
/// 表示一条 `child_role → parent_role` 的继承边（在同一 `tenant_id` 下）。
///
/// # 字段命名
///
/// 使用 `child_role` / `parent_role`（对称清晰，与 SQL schema 一致），
/// 而非 `role` / `parent_role`（避免 `role` 单字段歧义）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoleHierarchyRecord {
    /// 子角色编码（继承方）。
    pub child_role: String,
    /// 父角色编码（被继承方）。
    pub parent_role: String,
    /// 租户 ID。
    pub tenant_id: i64,
}

// ============================================================================
// RoleHierarchyService（T045-T050 将实现完整能力）
// ============================================================================

/// 角色层级服务（TC 预计算 + 缓存 + 增量失效）。
///
/// 完整实现在 T045-T050 逐步构建：
/// - T045-T046: `compute_closure` DFS 遍历计算传递闭包
/// - T047-T048: `get_ancestors` 先查 oxcache 未命中则 `compute_closure` 并缓存
/// - T049-T050: `add_edge` + `invalidate_cache` 增量失效
pub struct RoleHierarchyService;

impl RoleHierarchyService {
    /// 占位构造（T045-T046 将改为接收 `dao: Arc<dyn BulwarkDao>`）。
    pub fn new() -> Self {
        Self
    }
}

impl Default for RoleHierarchyService {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 测试模块
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // T041: RoleHierarchyRecord 构造测试
    // ========================================================================

    /// T041 Red→Green：`RoleHierarchyRecord` 可构造且字段可读。
    ///
    /// 断言 `RoleHierarchyRecord { child_role, parent_role, tenant_id }`
    /// 三字段可正确初始化与读取。
    ///
    /// # 命名说明（Rule 7 冲突暴露）
    ///
    /// tasks.md T041 原描述用 `role` 字段，T043 SQL 用 `child_role`。
    /// 决策：统一用 `child_role` / `parent_role`（对称清晰，与 SQL 一致），
    /// 避免 `role` 单字段在 Rust 中与 `RoleRow` 混淆。
    #[test]
    fn role_hierarchy_record_constructs_with_role_parent_tenant() {
        let record = RoleHierarchyRecord {
            child_role: "user".to_string(),
            parent_role: "admin".to_string(),
            tenant_id: 0,
        };
        assert_eq!(record.child_role, "user");
        assert_eq!(record.parent_role, "admin");
        assert_eq!(record.tenant_id, 0);
    }

    /// RoleHierarchyRecord 支持 Clone / Debug / PartialEq / Serialize / Deserialize。
    #[test]
    fn role_hierarchy_record_derives_clone_debug_eq_serde() {
        let r1 = RoleHierarchyRecord {
            child_role: "user".to_string(),
            parent_role: "admin".to_string(),
            tenant_id: 0,
        };
        let r2 = r1.clone();
        assert_eq!(r1, r2);
        let json = serde_json::to_string(&r1).unwrap();
        let r3: RoleHierarchyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r1, r3);
        // Debug 可格式化
        let _debug = format!("{:?}", r1);
    }

    /// RoleHierarchyService::new() 可构造（占位，T045+ 扩展）。
    #[test]
    fn role_hierarchy_service_new_constructs() {
        let _svc = RoleHierarchyService::new();
        let _default = RoleHierarchyService::default();
    }
}
