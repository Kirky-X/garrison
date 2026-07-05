//! Repository 层模块（0.4.2 新增，依据 spec repository-layer）。
//!
//! 为 9 张核心表定义 Repository trait，提供 CRUD 抽象。
//! SQLite 实现见 `sqlite` 子模块（启用 `db-sqlite` feature）。
//!
//! ## 设计偏差
//!
//! - **D4（已撤销）**：v0.4.2 曾以 origin FRD `VARCHAR(64)/string` 为由采用 `tenant_id: i64`。
//!   v0.5.0 推翻此偏差，统一采用 `tenant_id: i64`：性能更优（INTEGER 索引/存储紧凑）、
//!   类型安全（避免字符串业务码解析）、与 spec/tenant-isolation `TenantContext.tenant_id: i64` 一致。
//!   origin FRD `VARCHAR(64)` 视为可偏离项；若需保留业务码（如 `tenant_001`），
//!   由调用方维护 `i64 ↔ String` 映射表，DAO 层只认 i64。
//! - **D5**: spec/design 要求 `create` 返回 `LoginId`，但 dao 模块不应依赖 stp 模块（分层原则）。
//!   采用 `String` 返回新插入的 ID（UUID 字符串）。
//!
//! ## 9 张核心表
//!
//! | 表名 | trait | tenant_id | 说明 |
//! |:---|:---|:---:|:---|
//! | app_user | [`UserRepository`] | 是 | 用户主表 |
//! | app_role | [`RoleRepository`] | 是 | 角色表 |
//! | app_permission | [`PermissionRepository`] | 否 | 权限表（全局共享） |
//! | app_user_role | [`UserRoleRepository`] | 是 | 用户-角色关联 |
//! | app_role_permission | [`RolePermissionRepository`] | 是 | 角色-权限关联 |
//! | app_auth_method | [`AuthMethodRepository`] | 是 | 认证方式表 |
//! | app_session | [`SessionRepository`] | 是 | 会话表 |
//! | app_login_log | [`LoginLogRepository`] | 是 | 登录日志表 |
//! | app_user_ext | [`UserExtRepository`] | 是 | 用户扩展字段表 |

use crate::error::BulwarkResult;

// ============================================================================
// Row struct 定义（依据 001_init.sql schema）
// ============================================================================

/// 用户表行（app_user）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserRow {
    /// 用户 ID（UUID 字符串）。
    pub id: String,
    /// 用户名。
    pub username: String,
    /// 密码哈希（argon2/bcrypt）。
    pub password_hash: String,
    /// 状态（pending/active/suspended/inactive/deleted）。
    pub status: String,
    /// 租户 ID。
    pub tenant_id: i64,
    /// 创建时间（ISO 8601 字符串）。
    pub created_at: String,
    /// 更新时间。
    pub updated_at: String,
    /// 最后登录时间（可空）。
    pub last_login_at: Option<String>,
}

/// 新建用户参数。
#[derive(Debug, Clone)]
pub struct NewUser {
    /// 用户 ID（UUID，由调用方生成）。
    pub id: String,
    /// 用户名。
    pub username: String,
    /// 密码哈希。
    pub password_hash: String,
    /// 状态。
    pub status: String,
}

/// 更新用户参数（所有字段可选，None 表示不更新）。
#[derive(Debug, Clone, Default)]
pub struct UpdateUser {
    /// 用户名。
    pub username: Option<String>,
    /// 密码哈希。
    pub password_hash: Option<String>,
    /// 状态。
    pub status: Option<String>,
    /// 最后登录时间。
    pub last_login_at: Option<String>,
}

/// 角色表行（app_role）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RoleRow {
    /// 角色 ID（UUID）。
    pub id: String,
    /// 角色编码（业务用）。
    pub code: String,
    /// 角色名（展示用）。
    pub name: String,
    /// 描述。
    pub description: Option<String>,
    /// 租户 ID。
    pub tenant_id: i64,
    /// 是否系统内置角色。
    pub is_system: bool,
    /// 创建时间。
    pub created_at: String,
    /// 更新时间。
    pub updated_at: String,
}

/// 新建角色参数。
#[derive(Debug, Clone)]
pub struct NewRole {
    /// 角色 ID（UUID）。
    pub id: String,
    /// 角色编码。
    pub code: String,
    /// 角色名。
    pub name: String,
    /// 描述。
    pub description: Option<String>,
    /// 是否系统内置。
    pub is_system: bool,
}

/// 权限表行（app_permission，全局表无 tenant_id）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PermissionRow {
    /// 权限 ID（UUID）。
    pub id: String,
    /// 权限编码（全局唯一）。
    pub code: String,
    /// 权限名。
    pub name: String,
    /// 资源类型（如 user/role/order）。
    pub resource_type: Option<String>,
    /// 动作（如 read/write/delete）。
    pub action: Option<String>,
    /// 创建时间。
    pub created_at: String,
    /// 更新时间。
    pub updated_at: String,
}

/// 新建权限参数。
#[derive(Debug, Clone)]
pub struct NewPermission {
    /// 权限 ID（UUID）。
    pub id: String,
    /// 权限编码。
    pub code: String,
    /// 权限名。
    pub name: String,
    /// 资源类型。
    pub resource_type: Option<String>,
    /// 动作。
    pub action: Option<String>,
}

/// 用户-角色关联表行（app_user_role）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserRoleRow {
    /// 用户 ID。
    pub user_id: String,
    /// 角色 ID。
    pub role_id: String,
    /// 授权范围。
    pub scope: Option<String>,
    /// 授权时间。
    pub grant_time: String,
    /// 租户 ID。
    pub tenant_id: i64,
}

/// 角色-权限关联表行（app_role_permission）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RolePermissionRow {
    /// 角色 ID。
    pub role_id: String,
    /// 权限 ID。
    pub permission_id: String,
    /// 租户 ID。
    pub tenant_id: i64,
}

/// 认证方式表行（app_auth_method）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthMethodRow {
    /// 认证方式 ID（UUID）。
    pub id: String,
    /// 用户 ID。
    pub user_id: String,
    /// 认证类型（passkey/password/oauth/did）。
    pub method_type: String,
    /// 外部 ID（如 OAuth provider user id）。
    pub external_id: Option<String>,
    /// JSON 元数据。
    pub metadata: Option<String>,
    /// 创建时间。
    pub create_time: String,
    /// 租户 ID。
    pub tenant_id: i64,
}

/// 新建认证方式参数。
#[derive(Debug, Clone)]
pub struct NewAuthMethod {
    /// 认证方式 ID（UUID）。
    pub id: String,
    /// 用户 ID。
    pub user_id: String,
    /// 认证类型。
    pub method_type: String,
    /// 外部 ID。
    pub external_id: Option<String>,
    /// JSON 元数据。
    pub metadata: Option<String>,
}

/// 会话表行（app_session）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionRow {
    /// 会话 ID（Token）。
    pub session_id: String,
    /// 用户 ID。
    pub user_id: String,
    /// 设备 ID。
    pub device_id: Option<String>,
    /// 登录 IP。
    pub ip: Option<String>,
    /// User-Agent。
    pub user_agent: Option<String>,
    /// 登录时间。
    pub login_time: String,
    /// 最后活跃时间。
    pub last_active: String,
    /// 过期时间。
    pub expire_time: Option<String>,
    /// 租户 ID。
    pub tenant_id: i64,
}

/// 新建会话参数。
#[derive(Debug, Clone)]
pub struct NewSession {
    /// 会话 ID（Token）。
    pub session_id: String,
    /// 用户 ID。
    pub user_id: String,
    /// 设备 ID。
    pub device_id: Option<String>,
    /// 登录 IP。
    pub ip: Option<String>,
    /// User-Agent。
    pub user_agent: Option<String>,
    /// 过期时间。
    pub expire_time: Option<String>,
}

/// 登录日志表行（app_login_log）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginLogRow {
    /// 日志 ID（UUID）。
    pub id: String,
    /// 用户 ID（可空，登录失败时可能无 user）。
    pub user_id: Option<String>,
    /// 动作（login/logout/refresh/kickout/kicked）。
    pub action: String,
    /// IP。
    pub ip: Option<String>,
    /// 设备 ID。
    pub device_id: Option<String>,
    /// 是否成功。
    pub success: bool,
    /// 失败原因。
    pub fail_reason: Option<String>,
    /// 创建时间。
    pub create_time: String,
    /// 租户 ID。
    pub tenant_id: i64,
}

/// 新建登录日志参数。
#[derive(Debug, Clone)]
pub struct NewLoginLog {
    /// 日志 ID（UUID）。
    pub id: String,
    /// 用户 ID。
    pub user_id: Option<String>,
    /// 动作。
    pub action: String,
    /// IP。
    pub ip: Option<String>,
    /// 设备 ID。
    pub device_id: Option<String>,
    /// 是否成功。
    pub success: bool,
    /// 失败原因。
    pub fail_reason: Option<String>,
}

/// 用户扩展字段表行（app_user_ext）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserExtRow {
    /// 扩展字段 ID（UUID）。
    pub id: String,
    /// 用户 ID。
    pub user_id: String,
    /// 扩展字段键（如 email/phone/avatar）。
    pub field_key: String,
    /// 扩展字段值。
    pub field_value: Option<String>,
    /// 字段类型（string/number/boolean/json/datetime）。
    pub field_type: String,
    /// 创建时间。
    pub created_at: String,
    /// 更新时间。
    pub updated_at: String,
    /// 租户 ID。
    pub tenant_id: i64,
}

// ============================================================================
// Repository trait 定义（依据 spec R-001 ~ R-004）
// ============================================================================

/// 用户表 Repository trait（依据 spec R-001）。
///
/// 所有方法首参 `tenant_id` 用于多租户过滤（依据 spec R-004）。
#[async_trait::async_trait]
pub trait UserRepository: Send + Sync {
    /// 按 ID 查询用户。
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> BulwarkResult<Option<UserRow>>;

    /// 按 username 查询用户。
    async fn find_by_username(
        &self,
        tenant_id: i64,
        username: &str,
    ) -> BulwarkResult<Option<UserRow>>;

    /// 创建用户，返回新插入的 ID。
    async fn create(&self, tenant_id: i64, user: NewUser) -> BulwarkResult<String>;

    /// 更新用户。
    async fn update(&self, tenant_id: i64, id: &str, user: UpdateUser) -> BulwarkResult<()>;

    /// 删除用户（幂等，不存在返回 Ok(())）。
    async fn delete(&self, tenant_id: i64, id: &str) -> BulwarkResult<()>;

    /// 分页查询用户。
    async fn list(&self, tenant_id: i64, offset: i64, limit: i64) -> BulwarkResult<Vec<UserRow>>;
}

/// 角色表 Repository trait。
#[async_trait::async_trait]
pub trait RoleRepository: Send + Sync {
    /// 按 ID 查询角色。
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> BulwarkResult<Option<RoleRow>>;

    /// 按 code 查询角色。
    async fn find_by_code(&self, tenant_id: i64, code: &str) -> BulwarkResult<Option<RoleRow>>;

    /// 创建角色。
    async fn create(&self, tenant_id: i64, role: NewRole) -> BulwarkResult<String>;

    /// 更新角色。
    async fn update(
        &self,
        tenant_id: i64,
        id: &str,
        code: Option<String>,
        name: Option<String>,
        description: Option<String>,
    ) -> BulwarkResult<()>;

    /// 删除角色（幂等）。
    async fn delete(&self, tenant_id: i64, id: &str) -> BulwarkResult<()>;

    /// 分页查询角色。
    async fn list(&self, tenant_id: i64, offset: i64, limit: i64) -> BulwarkResult<Vec<RoleRow>>;
}

/// 权限表 Repository trait（全局表，无 tenant_id）。
#[async_trait::async_trait]
pub trait PermissionRepository: Send + Sync {
    /// 按 ID 查询权限。
    async fn find_by_id(&self, id: &str) -> BulwarkResult<Option<PermissionRow>>;

    /// 按 code 查询权限。
    async fn find_by_code(&self, code: &str) -> BulwarkResult<Option<PermissionRow>>;

    /// 创建权限。
    async fn create(&self, permission: NewPermission) -> BulwarkResult<String>;

    /// 更新权限。
    async fn update(
        &self,
        id: &str,
        name: Option<String>,
        resource_type: Option<String>,
        action: Option<String>,
    ) -> BulwarkResult<()>;

    /// 删除权限（幂等）。
    async fn delete(&self, id: &str) -> BulwarkResult<()>;

    /// 分页查询权限。
    async fn list(&self, offset: i64, limit: i64) -> BulwarkResult<Vec<PermissionRow>>;
}

/// 用户-角色关联 Repository trait。
#[async_trait::async_trait]
pub trait UserRoleRepository: Send + Sync {
    /// 查询用户的所有角色关联。
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> BulwarkResult<Vec<UserRoleRow>>;

    /// 查询角色的所有用户关联。
    async fn find_by_role_id(
        &self,
        tenant_id: i64,
        role_id: &str,
    ) -> BulwarkResult<Vec<UserRoleRow>>;

    /// 分配角色给用户。
    async fn assign(
        &self,
        tenant_id: i64,
        user_id: &str,
        role_id: &str,
        scope: Option<String>,
    ) -> BulwarkResult<()>;

    /// 撤销用户的角色（幂等）。
    async fn revoke(&self, tenant_id: i64, user_id: &str, role_id: &str) -> BulwarkResult<()>;

    /// 分页查询。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<UserRoleRow>>;
}

/// 角色-权限关联 Repository trait。
#[async_trait::async_trait]
pub trait RolePermissionRepository: Send + Sync {
    /// 查询角色的所有权限关联。
    async fn find_by_role_id(
        &self,
        tenant_id: i64,
        role_id: &str,
    ) -> BulwarkResult<Vec<RolePermissionRow>>;

    /// 查询权限的所有角色关联。
    async fn find_by_permission_id(
        &self,
        tenant_id: i64,
        permission_id: &str,
    ) -> BulwarkResult<Vec<RolePermissionRow>>;

    /// 分配权限给角色。
    async fn assign(&self, tenant_id: i64, role_id: &str, permission_id: &str)
        -> BulwarkResult<()>;

    /// 撤销角色的权限（幂等）。
    async fn revoke(&self, tenant_id: i64, role_id: &str, permission_id: &str)
        -> BulwarkResult<()>;

    /// 分页查询。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<RolePermissionRow>>;
}

/// 认证方式 Repository trait。
#[async_trait::async_trait]
pub trait AuthMethodRepository: Send + Sync {
    /// 按 ID 查询认证方式。
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> BulwarkResult<Option<AuthMethodRow>>;

    /// 查询用户的所有认证方式。
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> BulwarkResult<Vec<AuthMethodRow>>;

    /// 创建认证方式。
    async fn create(&self, tenant_id: i64, method: NewAuthMethod) -> BulwarkResult<String>;

    /// 删除认证方式（幂等）。
    async fn delete(&self, tenant_id: i64, id: &str) -> BulwarkResult<()>;

    /// 分页查询。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<AuthMethodRow>>;
}

/// 会话 Repository trait。
#[async_trait::async_trait]
pub trait SessionRepository: Send + Sync {
    /// 按 session_id 查询会话。
    async fn find_by_session_id(
        &self,
        tenant_id: i64,
        session_id: &str,
    ) -> BulwarkResult<Option<SessionRow>>;

    /// 查询用户的所有会话。
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> BulwarkResult<Vec<SessionRow>>;

    /// 创建会话。
    async fn create(&self, tenant_id: i64, session: NewSession) -> BulwarkResult<String>;

    /// 更新最后活跃时间。
    async fn update_last_active(&self, tenant_id: i64, session_id: &str) -> BulwarkResult<()>;

    /// 删除会话（幂等）。
    async fn delete(&self, tenant_id: i64, session_id: &str) -> BulwarkResult<()>;

    /// 分页查询。
    async fn list(&self, tenant_id: i64, offset: i64, limit: i64)
        -> BulwarkResult<Vec<SessionRow>>;
}

/// 登录日志 Repository trait。
#[async_trait::async_trait]
pub trait LoginLogRepository: Send + Sync {
    /// 按 ID 查询日志。
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> BulwarkResult<Option<LoginLogRow>>;

    /// 查询用户的登录日志（分页）。
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<LoginLogRow>>;

    /// 创建日志。
    async fn create(&self, tenant_id: i64, log: NewLoginLog) -> BulwarkResult<String>;

    /// 分页查询。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<LoginLogRow>>;
}

/// 用户扩展字段 Repository trait。
#[async_trait::async_trait]
pub trait UserExtRepository: Send + Sync {
    /// 查询用户的所有扩展字段。
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> BulwarkResult<Vec<UserExtRow>>;

    /// 按 user_id + field_key 查询。
    async fn find_by_user_and_key(
        &self,
        tenant_id: i64,
        user_id: &str,
        field_key: &str,
    ) -> BulwarkResult<Option<UserExtRow>>;

    /// 插入或更新扩展字段（依据 UK(user_id, field_key)）。
    async fn upsert(
        &self,
        tenant_id: i64,
        user_id: &str,
        field_key: &str,
        field_value: Option<String>,
        field_type: &str,
    ) -> BulwarkResult<()>;

    /// 删除扩展字段（幂等）。
    async fn delete(&self, tenant_id: i64, user_id: &str, field_key: &str) -> BulwarkResult<()>;

    /// 分页查询。
    async fn list(&self, tenant_id: i64, offset: i64, limit: i64)
        -> BulwarkResult<Vec<UserExtRow>>;
}

// ============================================================================
// SQLite 实现子模块（依据 spec repository-layer R-003）。
// 启用 db-sqlite feature 时编译，基于 dbnexus DbPool + sea-orm Statement 参数化查询。
// ============================================================================
/// SQLite 实现子模块。
#[cfg(feature = "db-sqlite")]
pub mod sqlite;

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Row struct 构造测试（验证字段可正确初始化）
    // ========================================================================

    /// UserRow 可构造且字段正确。
    #[test]
    fn user_row_constructs_with_all_fields() {
        let row = UserRow {
            id: "u-001".to_string(),
            username: "alice".to_string(),
            password_hash: "$argon2id$...".to_string(),
            status: "active".to_string(),
            tenant_id: 0,
            created_at: "2026-07-04T00:00:00Z".to_string(),
            updated_at: "2026-07-04T00:00:00Z".to_string(),
            last_login_at: None,
        };
        assert_eq!(row.id, "u-001");
        assert_eq!(row.username, "alice");
        assert_eq!(row.status, "active");
    }

    /// RoleRow 可构造且 is_system 为 false。
    #[test]
    fn role_row_constructs_with_is_system_false() {
        let row = RoleRow {
            id: "r-001".to_string(),
            code: "admin".to_string(),
            name: "Administrator".to_string(),
            description: None,
            tenant_id: 0,
            is_system: false,
            created_at: "2026-07-04T00:00:00Z".to_string(),
            updated_at: "2026-07-04T00:00:00Z".to_string(),
        };
        assert_eq!(row.code, "admin");
        assert!(!row.is_system);
    }

    /// PermissionRow 可构造且无 tenant_id 字段。
    #[test]
    fn permission_row_constructs_without_tenant_id() {
        let row = PermissionRow {
            id: "p-001".to_string(),
            code: "user:read".to_string(),
            name: "Read User".to_string(),
            resource_type: Some("user".to_string()),
            action: Some("read".to_string()),
            created_at: "2026-07-04T00:00:00Z".to_string(),
            updated_at: "2026-07-04T00:00:00Z".to_string(),
        };
        assert_eq!(row.code, "user:read");
    }

    /// UserRoleRow 可构造。
    #[test]
    fn user_role_row_constructs() {
        let row = UserRoleRow {
            user_id: "u-001".to_string(),
            role_id: "r-001".to_string(),
            scope: None,
            grant_time: "2026-07-04T00:00:00Z".to_string(),
            tenant_id: 0,
        };
        assert_eq!(row.user_id, "u-001");
    }

    /// RolePermissionRow 可构造。
    #[test]
    fn role_permission_row_constructs() {
        let row = RolePermissionRow {
            role_id: "r-001".to_string(),
            permission_id: "p-001".to_string(),
            tenant_id: 0,
        };
        assert_eq!(row.role_id, "r-001");
    }

    /// AuthMethodRow 可构造。
    #[test]
    fn auth_method_row_constructs() {
        let row = AuthMethodRow {
            id: "am-001".to_string(),
            user_id: "u-001".to_string(),
            method_type: "password".to_string(),
            external_id: None,
            metadata: None,
            create_time: "2026-07-04T00:00:00Z".to_string(),
            tenant_id: 0,
        };
        assert_eq!(row.method_type, "password");
    }

    /// SessionRow 可构造。
    #[test]
    fn session_row_constructs() {
        let row = SessionRow {
            session_id: "sess-001".to_string(),
            user_id: "u-001".to_string(),
            device_id: Some("web".to_string()),
            ip: Some("127.0.0.1".to_string()),
            user_agent: None,
            login_time: "2026-07-04T00:00:00Z".to_string(),
            last_active: "2026-07-04T00:00:00Z".to_string(),
            expire_time: None,
            tenant_id: 0,
        };
        assert_eq!(row.session_id, "sess-001");
    }

    /// LoginLogRow 可构造且 success 为 true。
    #[test]
    fn login_log_row_constructs_with_success_true() {
        let row = LoginLogRow {
            id: "log-001".to_string(),
            user_id: Some("u-001".to_string()),
            action: "login".to_string(),
            ip: Some("127.0.0.1".to_string()),
            device_id: None,
            success: true,
            fail_reason: None,
            create_time: "2026-07-04T00:00:00Z".to_string(),
            tenant_id: 0,
        };
        assert!(row.success);
        assert_eq!(row.action, "login");
    }

    /// UserExtRow 可构造。
    #[test]
    fn user_ext_row_constructs() {
        let row = UserExtRow {
            id: "ext-001".to_string(),
            user_id: "u-001".to_string(),
            field_key: "email".to_string(),
            field_value: Some("alice@example.com".to_string()),
            field_type: "string".to_string(),
            created_at: "2026-07-04T00:00:00Z".to_string(),
            updated_at: "2026-07-04T00:00:00Z".to_string(),
            tenant_id: 0,
        };
        assert_eq!(row.field_key, "email");
    }

    // ========================================================================
    // New* struct 构造测试
    // ========================================================================

    /// NewUser 可构造。
    #[test]
    fn new_user_constructs() {
        let new = NewUser {
            id: "u-001".to_string(),
            username: "alice".to_string(),
            password_hash: "$argon2id$...".to_string(),
            status: "active".to_string(),
        };
        assert_eq!(new.id, "u-001");
    }

    /// NewRole 可构造。
    #[test]
    fn new_role_constructs() {
        let new = NewRole {
            id: "r-001".to_string(),
            code: "admin".to_string(),
            name: "Administrator".to_string(),
            description: None,
            is_system: false,
        };
        assert_eq!(new.code, "admin");
    }

    /// NewPermission 可构造。
    #[test]
    fn new_permission_constructs() {
        let new = NewPermission {
            id: "p-001".to_string(),
            code: "user:read".to_string(),
            name: "Read User".to_string(),
            resource_type: Some("user".to_string()),
            action: Some("read".to_string()),
        };
        assert_eq!(new.code, "user:read");
    }

    /// NewAuthMethod 可构造。
    #[test]
    fn new_auth_method_constructs() {
        let new = NewAuthMethod {
            id: "am-001".to_string(),
            user_id: "u-001".to_string(),
            method_type: "password".to_string(),
            external_id: None,
            metadata: None,
        };
        assert_eq!(new.method_type, "password");
    }

    /// NewSession 可构造。
    #[test]
    fn new_session_constructs() {
        let new = NewSession {
            session_id: "sess-001".to_string(),
            user_id: "u-001".to_string(),
            device_id: Some("web".to_string()),
            ip: None,
            user_agent: None,
            expire_time: None,
        };
        assert_eq!(new.session_id, "sess-001");
    }

    /// NewLoginLog 可构造。
    #[test]
    fn new_login_log_constructs() {
        let new = NewLoginLog {
            id: "log-001".to_string(),
            user_id: Some("u-001".to_string()),
            action: "login".to_string(),
            ip: None,
            device_id: None,
            success: true,
            fail_reason: None,
        };
        assert_eq!(new.action, "login");
    }

    /// UpdateUser 可构造且默认全 None。
    #[test]
    fn update_user_default_all_none() {
        let update = UpdateUser::default();
        assert!(update.username.is_none());
        assert!(update.password_hash.is_none());
        assert!(update.status.is_none());
        assert!(update.last_login_at.is_none());
    }

    // ========================================================================
    // Row struct 序列化测试（验证 Serialize/Deserialize 派生）
    // ========================================================================

    /// UserRow 可序列化为 JSON 且可反序列化。
    #[test]
    fn user_row_serializes_and_deserializes() {
        let row = UserRow {
            id: "u-001".to_string(),
            username: "alice".to_string(),
            password_hash: "$argon2id$...".to_string(),
            status: "active".to_string(),
            tenant_id: 0,
            created_at: "2026-07-04T00:00:00Z".to_string(),
            updated_at: "2026-07-04T00:00:00Z".to_string(),
            last_login_at: None,
        };
        let json = serde_json::to_string(&row).unwrap();
        let deserialized: UserRow = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "u-001");
        assert_eq!(deserialized.username, "alice");
    }

    /// PermissionRow 可序列化且无 tenant_id 字段。
    #[test]
    fn permission_row_serializes_without_tenant_id() {
        let row = PermissionRow {
            id: "p-001".to_string(),
            code: "user:read".to_string(),
            name: "Read User".to_string(),
            resource_type: None,
            action: None,
            created_at: "2026-07-04T00:00:00Z".to_string(),
            updated_at: "2026-07-04T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(
            !json.contains("tenant_id"),
            "PermissionRow JSON 不应包含 tenant_id"
        );
    }

    // ========================================================================
    // trait Send + Sync 编译期检查（依据 spec R-002）
    // ========================================================================

    /// 所有 Repository trait 为 Send + Sync（编译期检查）。
    ///
    /// 注：`?Sized` 允许 `dyn Trait` 作为类型参数（dyn Trait 不实现 Sized）。
    #[test]
    fn all_repository_traits_are_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        // 这些 trait object 检查仅验证 trait 本身满足 Send + Sync 约束
        // （具体 impl 在 T019 Green 阶段验证）
        assert_send_sync::<dyn UserRepository>();
        assert_send_sync::<dyn RoleRepository>();
        assert_send_sync::<dyn PermissionRepository>();
        assert_send_sync::<dyn UserRoleRepository>();
        assert_send_sync::<dyn RolePermissionRepository>();
        assert_send_sync::<dyn AuthMethodRepository>();
        assert_send_sync::<dyn SessionRepository>();
        assert_send_sync::<dyn LoginLogRepository>();
        assert_send_sync::<dyn UserExtRepository>();
    }
}
