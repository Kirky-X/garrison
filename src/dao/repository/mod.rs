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
//! | app_user_device | [`UserDeviceRepository`] | 是 | 用户设备表（v0.5.1 新增，M2） |

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

/// 用户设备表行（app_user_device，v0.5.1 新增，依据 design.md D4）。
///
/// 记录用户登录设备指纹与 UA 信息，支持设备阻断与多设备管理。
/// 时间字段用 i64（epoch seconds），与 design.md D4 schema 一致。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserDeviceRow {
    /// 设备 ID（UUID v4）。
    pub id: String,
    /// 租户 ID。
    pub tenant_id: i64,
    /// 登录 ID（关联 app_login_log 或外部 login 概念）。
    pub login_id: i64,
    /// 设备标识（UA hash 或设备指纹）。
    pub device_identifier: String,
    /// 设备名（从 UA 解析，如 "Chrome on Windows"）。
    pub device_name: Option<String>,
    /// 原始 User-Agent 字符串。
    pub user_agent: Option<String>,
    /// 是否被阻止。
    pub is_blocked: bool,
    /// 最后活跃时间（epoch seconds，可空）。
    pub last_seen_at: Option<i64>,
    /// 创建时间（epoch seconds）。
    pub created_at: i64,
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

/// 单用户最大设备数（依据 design.md D4，默认 10）。
///
/// `register_device` 在 (tenant_id, login_id) 下设备数达到此值时拒绝新注册。
pub const MAX_DEVICES: usize = 10;

/// 用户设备 Repository trait（v0.5.1 新增，依据 design.md D4）。
///
/// 提供设备注册 / 阻断 / 查询能力，`register_device` 在设备数超过 [`MAX_DEVICES`] 时
/// 返回 `BulwarkError::InvalidParam`。重复注册同一设备（相同 identifier）幂等返回已有 ID。
#[async_trait::async_trait]
pub trait UserDeviceRepository: Send + Sync {
    /// 注册设备，返回设备 ID（UUID）。
    ///
    /// - 若 (tenant_id, login_id, identifier) 已存在，更新 last_seen_at 并返回已有 ID（幂等）。
    /// - 若当前设备数 >= [`MAX_DEVICES`]，返回 `BulwarkError::InvalidParam`。
    async fn register_device(
        &self,
        tenant_id: i64,
        login_id: i64,
        identifier: &str,
        ua: &str,
    ) -> BulwarkResult<String>;

    /// 阻止设备（设置 is_blocked = 1）。
    async fn block_device(&self, device_id: &str) -> BulwarkResult<()>;

    /// 解除阻止（设置 is_blocked = 0）。
    async fn unblock_device(&self, device_id: &str) -> BulwarkResult<()>;

    /// 列出用户的所有设备（按 tenant_id + login_id 过滤）。
    async fn list_user_devices(
        &self,
        tenant_id: i64,
        login_id: i64,
    ) -> BulwarkResult<Vec<UserDeviceRow>>;

    /// 统计用户设备数。
    async fn count_user_devices(&self, tenant_id: i64, login_id: i64) -> BulwarkResult<usize>;
}

// ============================================================================
// Dbnexus Repository 实现子模块（依据 spec repository-layer R-003 + P3 重构）。
// 启用 db-sqlite 或 db-postgres feature 时编译，基于 dbnexus DbPool + sea-orm
// Statement 参数化查询，通过 make_statement 运行时占位符转换支持两种后端。
// ============================================================================
/// Dbnexus Repository 实现子模块（backend-agnostic，支持 SQLite / PostgreSQL）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
pub mod sqlite;

/// 角色层级子模块（v0.5.0 新增，依据 proposal H6）。
///
/// always compiled（`RoleHierarchyRecord` 不依赖 db-sqlite）。
/// `RoleHierarchyService` 在 T045-T050 扩展时依赖 `BulwarkDao` trait（always compiled）。
pub mod role_hierarchy;

// ============================================================================
// Backend-agnostic 辅助函数（v0.5.0 新增，依据 P3 重构决策）。
// 启用 db-sqlite 或 db-postgres feature 时编译。
// 运行时根据 DbBackend 转换 SQL 占位符（SQLite ? / PostgreSQL $1,$2）。
// ============================================================================

/// 转换 SQL 占位符为指定后端的方言。
///
/// - `DbBackend::Sqlite`：保留 `?` 占位符
/// - `DbBackend::Postgres`：将第 n 个 `?` 替换为 `$n`
/// - 其他后端：保留 `?`（由调用方确保兼容性）
///
/// # 示例
///
/// ```
/// use sea_orm::DbBackend;
/// use bulwark::dao::repository::convert_placeholders;
///
/// let sql = "WHERE id = ? AND name = ?";
/// assert_eq!(convert_placeholders(sql, DbBackend::Sqlite), "WHERE id = ? AND name = ?");
/// assert_eq!(convert_placeholders(sql, DbBackend::Postgres), "WHERE id = $1 AND name = $2");
/// ```
#[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
pub fn convert_placeholders(sql: &str, backend: sea_orm::DbBackend) -> String {
    use sea_orm::DbBackend;
    if backend != DbBackend::Postgres {
        return sql.to_string();
    }
    let mut result = String::with_capacity(sql.len() + 16);
    let mut n = 0u32;
    for c in sql.chars() {
        if c == '?' {
            n += 1;
            result.push('$');
            result.push_str(&n.to_string());
        } else {
            result.push(c);
        }
    }
    result
}

/// 构造 backend-agnostic 的 [`sea_orm::Statement`]，根据 conn 的 backend 自动转换占位符。
///
/// 封装 [`convert_placeholders`] + [`sea_orm::Statement::from_sql_and_values`]，
/// 让 Repository 实现无需关心后端差异——传入 `?` 占位符的 SQL 即可，
/// Postgres backend 会自动转换为 `$1`, `$2`, ...
///
/// # 示例
///
/// ```ignore
/// use bulwark::dao::repository::make_statement;
/// use sea_orm::Value;
///
/// // 实际使用时传入真实的 DatabaseConnection（Sqlite 或 Postgres 后端）
/// let stmt = make_statement(&conn, "WHERE id = ?", vec![Value::Int(Some(1))]);
/// ```
#[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
pub fn make_statement(
    conn: &impl sea_orm::ConnectionTrait,
    sql: &str,
    values: Vec<sea_orm::Value>,
) -> sea_orm::Statement {
    let backend = conn.get_database_backend();
    let sql = convert_placeholders(sql, backend);
    sea_orm::Statement::from_sql_and_values(backend, sql, values)
}

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

    /// UserDeviceRow 可构造且字段正确。
    #[test]
    fn user_device_row_constructs() {
        let row = UserDeviceRow {
            id: "dev-001".to_string(),
            tenant_id: 42,
            login_id: 1001,
            device_identifier: "ua-hash-abc".to_string(),
            device_name: Some("Chrome on Windows".to_string()),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0)".to_string()),
            is_blocked: false,
            last_seen_at: Some(1750000000),
            created_at: 1749000000,
        };
        assert_eq!(row.id, "dev-001");
        assert_eq!(row.tenant_id, 42);
        assert_eq!(row.login_id, 1001);
        assert_eq!(row.device_identifier, "ua-hash-abc");
        assert!(!row.is_blocked);
    }

    /// MAX_DEVICES 常量值为 10。
    #[test]
    fn max_devices_is_ten() {
        assert_eq!(MAX_DEVICES, 10);
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
        assert_send_sync::<dyn UserDeviceRepository>();
    }

    // ========================================================================
    // convert_placeholders 测试（T134，依据 P3 重构决策）
    // ========================================================================

    /// SQLite 后端保留 `?` 占位符不变。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
    #[test]
    fn convert_placeholders_sqlite_keeps_question_mark() {
        use sea_orm::DbBackend;
        let sql = "WHERE id = ? AND name = ?";
        let result = convert_placeholders(sql, DbBackend::Sqlite);
        assert_eq!(result, "WHERE id = ? AND name = ?");
    }

    /// PostgreSQL 后端将 `?` 替换为 `$1`, `$2`, ...
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
    #[test]
    fn convert_placeholders_postgres_replaces_with_dollar_n() {
        use sea_orm::DbBackend;
        let sql = "WHERE id = ? AND name = ?";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(result, "WHERE id = $1 AND name = $2");
    }

    /// 单个占位符也能正确转换。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
    #[test]
    fn convert_placeholders_postgres_single_placeholder() {
        use sea_orm::DbBackend;
        let sql = "WHERE id = ?";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(result, "WHERE id = $1");
    }

    /// 无占位符的 SQL 不受影响。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
    #[test]
    fn convert_placeholders_no_placeholder_unchanged() {
        use sea_orm::DbBackend;
        let sql = "SELECT 1";
        assert_eq!(convert_placeholders(sql, DbBackend::Postgres), "SELECT 1");
        assert_eq!(convert_placeholders(sql, DbBackend::Sqlite), "SELECT 1");
    }

    /// 多个占位符（5 个）能正确编号。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
    #[test]
    fn convert_placeholders_postgres_five_placeholders() {
        use sea_orm::DbBackend;
        let sql = "VALUES (?, ?, ?, ?, ?)";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(result, "VALUES ($1, $2, $3, $4, $5)");
    }

    // ========================================================================
    // make_statement 测试（T135，依据 P3 重构决策）
    // ========================================================================

    /// Mock 连接，仅用于测试 `make_statement` 的 backend 检测逻辑。
    /// 其他方法未实现（`make_statement` 仅调用 `get_database_backend`）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
    struct MockConn {
        backend: sea_orm::DbBackend,
    }

    #[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
    #[async_trait::async_trait]
    impl sea_orm::ConnectionTrait for MockConn {
        fn get_database_backend(&self) -> sea_orm::DbBackend {
            self.backend
        }

        async fn execute_raw(
            &self,
            _stmt: sea_orm::Statement,
        ) -> Result<sea_orm::ExecResult, sea_orm::DbErr> {
            unimplemented!("MockConn only for get_database_backend")
        }

        async fn execute_unprepared(
            &self,
            _sql: &str,
        ) -> Result<sea_orm::ExecResult, sea_orm::DbErr> {
            unimplemented!("MockConn only for get_database_backend")
        }

        async fn query_one_raw(
            &self,
            _stmt: sea_orm::Statement,
        ) -> Result<Option<sea_orm::QueryResult>, sea_orm::DbErr> {
            unimplemented!("MockConn only for get_database_backend")
        }

        async fn query_all_raw(
            &self,
            _stmt: sea_orm::Statement,
        ) -> Result<Vec<sea_orm::QueryResult>, sea_orm::DbErr> {
            unimplemented!("MockConn only for get_database_backend")
        }
    }

    /// SQLite backend：`make_statement` 保留 `?` 占位符。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
    #[test]
    fn make_statement_sqlite_uses_question_mark() {
        let conn = MockConn {
            backend: sea_orm::DbBackend::Sqlite,
        };
        let stmt = make_statement(
            &conn,
            "WHERE id = ? AND name = ?",
            vec![
                sea_orm::Value::Int(Some(1)),
                sea_orm::Value::String(Some("alice".into())),
            ],
        );
        assert_eq!(stmt.sql, "WHERE id = ? AND name = ?");
    }

    /// Postgres backend：`make_statement` 将 `?` 替换为 `$1`, `$2`。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres"))]
    #[test]
    fn make_statement_postgres_uses_dollar_n() {
        let conn = MockConn {
            backend: sea_orm::DbBackend::Postgres,
        };
        let stmt = make_statement(
            &conn,
            "WHERE id = ? AND name = ?",
            vec![
                sea_orm::Value::Int(Some(1)),
                sea_orm::Value::String(Some("alice".into())),
            ],
        );
        assert_eq!(stmt.sql, "WHERE id = $1 AND name = $2");
    }

    // ========================================================================
    // PostgreSQL 后端集成测试（v0.5.0 新增，依据 P3 重构 T137）
    // ========================================================================
    //
    // 验证 DbnexusUserRepository 在 PostgreSQL 后端下能正确执行 find_by_id，
    // 间接验证 make_statement 运行时占位符转换（? → $1, $2）在真实 PG 上工作。
    //
    // 此测试需要真实 PostgreSQL 实例，默认 #[ignore]。
    // 运行方式：
    //   export DATABASE_URL=postgres://user:pass@localhost:5432/testdb
    //   cargo test --features db-postgres --lib \
    //     repository::tests::dbnexus_user_repository_works_with_postgres_backend -- --ignored

    /// 验证 DbnexusUserRepository 在 PostgreSQL 后端下 find_by_id 正确执行。
    ///
    /// 测试流程：建表 → 插入用户 → find_by_id → 断言字段 → 清理。
    /// 如果占位符转换失败（? 未转为 $n），PostgreSQL 会返回语法错误。
    #[cfg(feature = "db-postgres")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "需要真实 PostgreSQL，设置 DATABASE_URL 后 cargo test -- --ignored 运行"]
    async fn dbnexus_user_repository_works_with_postgres_backend() {
        use crate::dao::init_dbnexus;
        use crate::dao::repository::sqlite::DbnexusUserRepository;
        use sea_orm::ConnectionTrait;

        let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            panic!("DATABASE_URL 未设置，请指向 PostgreSQL 连接字符串");
        });

        // 1. 初始化 PostgreSQL 连接池
        let pool = init_dbnexus(&database_url)
            .await
            .expect("初始化 PostgreSQL 连接池失败");

        // 2. 建表（PostgreSQL 兼容 DDL，用 BIGINT 匹配 i64）
        {
            let session = pool.get_session("admin").await.expect("获取 session 失败");
            let conn = session.connection().expect("获取 connection 失败");
            // 清理残留表（按依赖逆序）
            let _ = conn
                .execute_unprepared("DROP TABLE IF EXISTS app_user_ext")
                .await;
            let _ = conn
                .execute_unprepared("DROP TABLE IF EXISTS app_login_log")
                .await;
            let _ = conn
                .execute_unprepared("DROP TABLE IF EXISTS app_session")
                .await;
            let _ = conn
                .execute_unprepared("DROP TABLE IF EXISTS app_auth_method")
                .await;
            let _ = conn
                .execute_unprepared("DROP TABLE IF EXISTS app_role_permission")
                .await;
            let _ = conn
                .execute_unprepared("DROP TABLE IF EXISTS app_user_role")
                .await;
            let _ = conn
                .execute_unprepared("DROP TABLE IF EXISTS app_permission")
                .await;
            let _ = conn
                .execute_unprepared("DROP TABLE IF EXISTS app_role")
                .await;
            let _ = conn
                .execute_unprepared("DROP TABLE IF EXISTS app_user")
                .await;
            // 创建 app_user 表
            conn.execute_unprepared(
                "CREATE TABLE app_user (
                    id              TEXT    PRIMARY KEY,
                    username        TEXT    NOT NULL,
                    password_hash   TEXT    NOT NULL,
                    status          TEXT    NOT NULL DEFAULT 'pending',
                    tenant_id       BIGINT  NOT NULL DEFAULT 0,
                    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_login_at   TEXT
                )",
            )
            .await
            .expect("创建 app_user 表失败");
        }

        // 3. 构造 Repository
        let repo = DbnexusUserRepository::new(pool.clone());

        // 4. 插入测试用户
        let tenant_id: i64 = 42;
        repo.create(
            tenant_id,
            NewUser {
                id: "u-pg-test".to_string(),
                username: "pg-test-user".to_string(),
                password_hash: "$argon2id$fake-hash".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("插入测试用户失败");

        // 5. find_by_id 验证占位符转换（? → $1, $2 在真实 PG 上执行）
        let found = repo
            .find_by_id(tenant_id, "u-pg-test")
            .await
            .expect("find_by_id 查询失败")
            .expect("测试用户未找到");

        // 6. 断言返回数据正确
        assert_eq!(found.id, "u-pg-test");
        assert_eq!(found.username, "pg-test-user");
        assert_eq!(found.password_hash, "$argon2id$fake-hash");
        assert_eq!(found.status, "active");
        assert_eq!(found.tenant_id, tenant_id);

        // 7. 清理
        repo.delete(tenant_id, "u-pg-test")
            .await
            .expect("清理测试数据失败");
    }
}
