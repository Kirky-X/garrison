// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Repository 层模块。
//!
//! 为 9 张核心表定义 Repository trait，提供 CRUD 抽象。
//! SQLite 实现见 `sqlite` 子模块（启用 `db-sqlite` feature）。
//!
//! ## 设计要点
//!
//! - `tenant_id` 统一采用 `i64`：性能更优（INTEGER 索引/存储紧凑）、
//!   类型安全（避免字符串业务码解析）、与 spec/tenant-isolation `TenantContext.tenant_id: i64` 一致。
//!   原始设计将 `VARCHAR(64)` 视为可偏离项；若需保留业务码（如 `tenant_001`），
//!   由调用方维护 `i64 ↔ String` 映射表，DAO 层只认 i64。
//! - `create` 返回 `String` 而非 `LoginId`：dao 模块不应依赖 stp 模块（分层原则），
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
//! | app_user_device | [`UserDeviceRepository`] | 是 | 用户设备表（M2） |

use crate::error::{GarrisonError, GarrisonResult};

// ============================================================================
// Row struct 定义
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

/// 用户列表行（app_user，不含 password_hash 的投影）。
///
/// [`UserRepository::list`] 专用于管理后台分页展示等场景，返回本类型
/// 而非 [`UserRow`]——从类型上排除 `password_hash`，杜绝凭证数据经
/// 分页/浏览接口被意外序列化到 API 响应或日志（编译期防护，替代此前
/// 仅文档警告的做法）。需要哈希的认证查询请使用 `find_by_id` /
/// `find_by_username`（返回 [`UserRow`]）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserListRow {
    /// 用户 ID（UUID 字符串）。
    pub id: String,
    /// 用户名。
    pub username: String,
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

// ============================================================================
// 导入哈希参数防御上限（防单次登录 OOM / CPU DoS）
// ============================================================================

/// 导入密码哈希的 Argon2 内存成本上限（KiB，1 GiB）。
///
/// 防御出处（对齐 zitadel passwap `ValidateEncodedHash` 的防御意图）：导入的
/// 哈希是**不可信输入**，PHC 参数自描述——无上限的恶意串（如 `m=17179869176`）
/// 会让单次登录 verify 申请巨量内存（OOM）或巨量迭代（CPU 耗尽）。上限取
/// 常规登录档位（默认 m=19456 KiB）之上的宽裕值：覆盖合法迁移来源，拒绝
/// 资源攻击载荷。
pub const ARGON2_IMPORT_MAX_M_COST: u32 = 1_048_576;

/// 导入密码哈希的 Argon2 迭代次数上限（防御出处同 [`ARGON2_IMPORT_MAX_M_COST`]）。
pub const ARGON2_IMPORT_MAX_T: u32 = 10;

/// 导入密码哈希的 Argon2 并行度上限（防御出处同 [`ARGON2_IMPORT_MAX_M_COST`]）。
pub const ARGON2_IMPORT_MAX_P: u32 = 4;

/// 导入密码哈希的 bcrypt cost 上限（防御出处同 [`ARGON2_IMPORT_MAX_M_COST`]）。
pub const BCRYPT_IMPORT_MAX_COST: u32 = 15;

/// 从 PHC 串提取 Argon2 参数段 `(m_cost, t_cost, p_cost)`。
///
/// 遍历 `$` 分段，找到首个同时含 `m=`/`t=`/`p=` 三键的段（跳过版本段、盐段、
/// hash 段——base64 无 padding，不含 `=`，不会误配）。缺任一键返回 `None`。
fn parse_argon2_import_params(hash: &str) -> Option<(u32, u32, u32)> {
    for segment in hash.split('$') {
        let mut m = None;
        let mut t = None;
        let mut p = None;
        for kv in segment.split(',') {
            if let Some((key, value)) = kv.split_once('=') {
                match key {
                    "m" => m = value.parse().ok(),
                    "t" => t = value.parse().ok(),
                    "p" => p = value.parse().ok(),
                    _ => {},
                }
            }
        }
        if let (Some(m), Some(t), Some(p)) = (m, t, p) {
            return Some((m, t, p));
        }
    }
    None
}

/// 校验外部导入的密码哈希：格式白名单 + 参数上限（防御门，出处见常量文档）。
///
/// 全部凭据导入/写入入口（`UserRepository::create` / `update` 的
/// `password_hash`、password 类型 credential 的写路径）必须先过本门。
///
/// # 白名单
///
/// 仅接受 `$argon2id$` / `$2b$` / `$2a$` / `$2y$` 前缀：argon2i/argon2d 已被
/// argon2id 取代，scrypt 等其他算法超出本框架 verify 能力——导入即不可验证，
/// 直接拒绝。
///
/// # Errors
///
/// 返回 [`GarrisonError::InvalidParam`]：白名单外前缀、Argon2 参数段缺失或
/// 不全、bcrypt cost 段缺失或非数字、任一参数超上限。整体拒绝，不静默降级。
pub fn validate_imported_hash(hash: &str) -> GarrisonResult<()> {
    if hash.starts_with("$argon2id$") {
        let (m_cost, t_cost, p_cost) = parse_argon2_import_params(hash).ok_or_else(|| {
            GarrisonError::InvalidParam(
                "import-hash-argon2-format::params-segment-missing-or-incomplete".to_string(),
            )
        })?;
        if m_cost > ARGON2_IMPORT_MAX_M_COST {
            return Err(GarrisonError::InvalidParam(format!(
                "import-hash-argon2-m-cost::{}>{}",
                m_cost, ARGON2_IMPORT_MAX_M_COST
            )));
        }
        if t_cost > ARGON2_IMPORT_MAX_T {
            return Err(GarrisonError::InvalidParam(format!(
                "import-hash-argon2-t-cost::{}>{}",
                t_cost, ARGON2_IMPORT_MAX_T
            )));
        }
        if p_cost > ARGON2_IMPORT_MAX_P {
            return Err(GarrisonError::InvalidParam(format!(
                "import-hash-argon2-p-cost::{}>{}",
                p_cost, ARGON2_IMPORT_MAX_P
            )));
        }
        return Ok(());
    }
    if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        let cost = hash
            .split('$')
            .nth(2)
            .and_then(|cost| cost.parse::<u32>().ok())
            .ok_or_else(|| {
                GarrisonError::InvalidParam(
                    "import-hash-bcrypt-format::cost-segment-missing-or-invalid".to_string(),
                )
            })?;
        if cost > BCRYPT_IMPORT_MAX_COST {
            return Err(GarrisonError::InvalidParam(format!(
                "import-hash-bcrypt-cost::{}>{}",
                cost, BCRYPT_IMPORT_MAX_COST
            )));
        }
        return Ok(());
    }
    Err(GarrisonError::InvalidParam(format!(
        "import-hash-unsupported::<{}>",
        hash.get(..10).unwrap_or(hash)
    )))
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

/// 用户设备表行（app_user_device）。
///
/// 记录用户登录设备指纹与 UA 信息，支持设备阻断与多设备管理。
/// 时间字段用 i64（epoch seconds）。
/// `login_id` 为字符串类型（与全局 login_id 类型一致）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UserDeviceRow {
    /// 设备 ID（UUID v4）。
    pub id: String,
    /// 租户 ID。
    pub tenant_id: i64,
    /// 登录 ID（字符串形式，关联 app_login_log 或外部 login 概念）。
    pub login_id: String,
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
// Repository trait 定义
// ============================================================================

/// 用户表 Repository trait。
///
/// 所有方法首参 `tenant_id` 用于多租户过滤。
#[async_trait::async_trait]
pub trait UserRepository: Send + Sync {
    /// 按 ID 查询用户。
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> GarrisonResult<Option<UserRow>>;

    /// 按 username 查询用户。
    async fn find_by_username(
        &self,
        tenant_id: i64,
        username: &str,
    ) -> GarrisonResult<Option<UserRow>>;

    /// 创建用户，返回新插入的 ID。
    async fn create(&self, tenant_id: i64, user: NewUser) -> GarrisonResult<String>;

    /// 更新用户。
    async fn update(&self, tenant_id: i64, id: &str, user: UpdateUser) -> GarrisonResult<()>;

    /// 删除用户（幂等，不存在返回 Ok(())）。
    async fn delete(&self, tenant_id: i64, id: &str) -> GarrisonResult<()>;

    /// 分页查询用户（按 `id` 稳定排序，保证 LIMIT/OFFSET 分页确定性）。
    ///
    /// 返回 [`UserListRow`]（不含 `password_hash` 的投影）：分页/浏览场景
    /// 无需凭证数据，从类型上排除密码哈希泄漏。需要哈希的认证查询请使用
    /// `find_by_id` / `find_by_username`。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<UserListRow>>;
}

/// 角色表 Repository trait。
#[async_trait::async_trait]
pub trait RoleRepository: Send + Sync {
    /// 按 ID 查询角色。
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> GarrisonResult<Option<RoleRow>>;

    /// 按 code 查询角色。
    async fn find_by_code(&self, tenant_id: i64, code: &str) -> GarrisonResult<Option<RoleRow>>;

    /// 创建角色。
    async fn create(&self, tenant_id: i64, role: NewRole) -> GarrisonResult<String>;

    /// 更新角色。
    async fn update(
        &self,
        tenant_id: i64,
        id: &str,
        code: Option<String>,
        name: Option<String>,
        description: Option<String>,
    ) -> GarrisonResult<()>;

    /// 删除角色（幂等）。
    async fn delete(&self, tenant_id: i64, id: &str) -> GarrisonResult<()>;

    /// 分页查询角色。
    async fn list(&self, tenant_id: i64, offset: i64, limit: i64) -> GarrisonResult<Vec<RoleRow>>;
}

/// 权限表 Repository trait（全局表，无 tenant_id）。
#[async_trait::async_trait]
pub trait PermissionRepository: Send + Sync {
    /// 按 ID 查询权限。
    async fn find_by_id(&self, id: &str) -> GarrisonResult<Option<PermissionRow>>;

    /// 按 code 查询权限。
    async fn find_by_code(&self, code: &str) -> GarrisonResult<Option<PermissionRow>>;

    /// 创建权限。
    async fn create(&self, permission: NewPermission) -> GarrisonResult<String>;

    /// 更新权限。
    async fn update(
        &self,
        id: &str,
        name: Option<String>,
        resource_type: Option<String>,
        action: Option<String>,
    ) -> GarrisonResult<()>;

    /// 删除权限（幂等）。
    async fn delete(&self, id: &str) -> GarrisonResult<()>;

    /// 分页查询权限。
    async fn list(&self, offset: i64, limit: i64) -> GarrisonResult<Vec<PermissionRow>>;
}

/// 用户-角色关联 Repository trait。
#[async_trait::async_trait]
pub trait UserRoleRepository: Send + Sync {
    /// 查询用户的所有角色关联。
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> GarrisonResult<Vec<UserRoleRow>>;

    /// 查询角色的所有用户关联。
    async fn find_by_role_id(
        &self,
        tenant_id: i64,
        role_id: &str,
    ) -> GarrisonResult<Vec<UserRoleRow>>;

    /// 分配角色给用户。
    async fn assign(
        &self,
        tenant_id: i64,
        user_id: &str,
        role_id: &str,
        scope: Option<String>,
    ) -> GarrisonResult<()>;

    /// 撤销用户的角色（幂等）。
    async fn revoke(&self, tenant_id: i64, user_id: &str, role_id: &str) -> GarrisonResult<()>;

    /// 分页查询。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<UserRoleRow>>;
}

/// 角色-权限关联 Repository trait。
#[async_trait::async_trait]
pub trait RolePermissionRepository: Send + Sync {
    /// 查询角色的所有权限关联。
    async fn find_by_role_id(
        &self,
        tenant_id: i64,
        role_id: &str,
    ) -> GarrisonResult<Vec<RolePermissionRow>>;

    /// 查询权限的所有角色关联。
    async fn find_by_permission_id(
        &self,
        tenant_id: i64,
        permission_id: &str,
    ) -> GarrisonResult<Vec<RolePermissionRow>>;

    /// 分配权限给角色。
    async fn assign(
        &self,
        tenant_id: i64,
        role_id: &str,
        permission_id: &str,
    ) -> GarrisonResult<()>;

    /// 撤销角色的权限（幂等）。
    async fn revoke(
        &self,
        tenant_id: i64,
        role_id: &str,
        permission_id: &str,
    ) -> GarrisonResult<()>;

    /// 分页查询。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<RolePermissionRow>>;
}

/// 认证方式 Repository trait。
#[async_trait::async_trait]
pub trait AuthMethodRepository: Send + Sync {
    /// 按 ID 查询认证方式。
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> GarrisonResult<Option<AuthMethodRow>>;

    /// 查询用户的所有认证方式。
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> GarrisonResult<Vec<AuthMethodRow>>;

    /// 创建认证方式。
    async fn create(&self, tenant_id: i64, method: NewAuthMethod) -> GarrisonResult<String>;

    /// 删除认证方式（幂等）。
    async fn delete(&self, tenant_id: i64, id: &str) -> GarrisonResult<()>;

    /// 分页查询。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<AuthMethodRow>>;
}

/// 会话 Repository trait。
#[async_trait::async_trait]
pub trait SessionRepository: Send + Sync {
    /// 按 session_id 查询会话。
    async fn find_by_session_id(
        &self,
        tenant_id: i64,
        session_id: &str,
    ) -> GarrisonResult<Option<SessionRow>>;

    /// 查询用户的所有会话。
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> GarrisonResult<Vec<SessionRow>>;

    /// 创建会话。
    async fn create(&self, tenant_id: i64, session: NewSession) -> GarrisonResult<String>;

    /// 更新最后活跃时间。
    async fn update_last_active(&self, tenant_id: i64, session_id: &str) -> GarrisonResult<()>;

    /// 删除会话（幂等）。
    async fn delete(&self, tenant_id: i64, session_id: &str) -> GarrisonResult<()>;

    /// 分页查询。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<SessionRow>>;
}

/// 登录日志 Repository trait。
#[async_trait::async_trait]
pub trait LoginLogRepository: Send + Sync {
    /// 按 ID 查询日志。
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> GarrisonResult<Option<LoginLogRow>>;

    /// 查询用户的登录日志（分页）。
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<LoginLogRow>>;

    /// 创建日志。
    async fn create(&self, tenant_id: i64, log: NewLoginLog) -> GarrisonResult<String>;

    /// 分页查询。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<LoginLogRow>>;
}

/// 用户扩展字段 Repository trait。
#[async_trait::async_trait]
pub trait UserExtRepository: Send + Sync {
    /// 查询用户的所有扩展字段。
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> GarrisonResult<Vec<UserExtRow>>;

    /// 按 user_id + field_key 查询。
    async fn find_by_user_and_key(
        &self,
        tenant_id: i64,
        user_id: &str,
        field_key: &str,
    ) -> GarrisonResult<Option<UserExtRow>>;

    /// 插入或更新扩展字段。
    async fn upsert(
        &self,
        tenant_id: i64,
        user_id: &str,
        field_key: &str,
        field_value: Option<String>,
        field_type: &str,
    ) -> GarrisonResult<()>;

    /// 删除扩展字段（幂等）。
    async fn delete(&self, tenant_id: i64, user_id: &str, field_key: &str) -> GarrisonResult<()>;

    /// 分页查询。
    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<UserExtRow>>;
}

// ============================================================================
// 登录标识唯一性（app_user_identifier）
// ============================================================================

/// 标识注册结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// 注册成功（该标识此前未被占用）。
    ///
    /// # 租户隔离语义（渗透-租户隔离-标识符注册表-1 修复）
    ///
    /// 全局主键 `(id_type, id_value)` 冲突但命中行属**其他租户**时同样返回本变体
    /// （中性「已注册」，不带 `by_user_id`）：调用方视作注册完成即可，
    /// 不得从返回值推断该标识在当前租户可用。
    Registered,
    /// 标识已被占用（携带占用者 user_id）。
    ///
    /// 仅**同租户**冲突携带 `by_user_id`（同信任域，供业务方决定冲突语义）。
    Taken {
        /// 当前占用该标识的用户 ID。
        by_user_id: String,
    },
}

/// 登录标识 Repository trait。
///
/// 提供 phone/email 等登录标识的**数据库级原子防重**：`(id_type, id_value)` 为全局主键
/// （设计使然，登录标识数据库级防重），数据库唯一约束兜底并发注册。
/// `register` 返回 [`RegisterOutcome`] 供业务方决定冲突语义
/// （拒绝注册 / 引导登录 / 走账号合并流程）。
///
/// # 租户隔离（渗透-租户隔离-标识符注册表-1）
///
/// 全局主键意味着不同租户无法注册同一标识：冲突命中他租户行时
/// `register` 返回中性 [`RegisterOutcome::Registered`]（不带 `by_user_id`，
/// 不向其他租户泄露 user_id）；同租户冲突才返回
/// [`RegisterOutcome::Taken`]。租户感知归属查询用
/// [`find_owner_in_tenant`](Self::find_owner_in_tenant)。
#[async_trait::async_trait]
pub trait UserIdentifierRepository: Send + Sync {
    /// 注册登录标识。
    ///
    /// `id_value` 由调用方归一化（框架提供 trim；格式校验属业务层）。
    /// INSERT 冲突时按租户作用域回查归属：同租户冲突返回 `Taken { by_user_id }`；
    /// 他租户占用（或冲突行并发消失）返回中性 `Registered`——不泄露其他租户的
    /// 记录归属。
    async fn register(
        &self,
        tenant_id: i64,
        id_type: &str,
        id_value: &str,
        user_id: &str,
    ) -> GarrisonResult<RegisterOutcome>;

    /// 查询标识当前归属（**全局**维度，未注册返回 `Ok(None)`）。
    ///
    /// # 泄露警告
    ///
    /// 本方法无租户谓词（全局主键的反查原语）：多租户部署中调用方必须
    /// 自行确保 `id_value` 不来自不可信输入，否则返回的 `user_id` 会向
    /// 调用方泄露该标识在**其他租户**的归属。租户上下文场景请改用
    /// [`find_owner_in_tenant`](Self::find_owner_in_tenant)。
    async fn find_owner(&self, id_type: &str, id_value: &str) -> GarrisonResult<Option<String>>;

    /// 查询标识在指定租户内的归属（租户感知，未注册或属他租户返回 `Ok(None)`）。
    ///
    /// 与 [`find_owner`](Self::find_owner) 的区别：SQL 带 `tenant_id` 谓词，
    /// 跨租户命中一律返回 `None`（不泄露归属），供 `register` 冲突回查与
    /// 多租户找回密码等租户上下文场景使用。
    async fn find_owner_in_tenant(
        &self,
        tenant_id: i64,
        id_type: &str,
        id_value: &str,
    ) -> GarrisonResult<Option<String>>;
}

/// 单用户最大设备数。
///
/// `register_device` 在 (tenant_id, login_id) 下设备数达到此值时拒绝新注册。
pub const MAX_DEVICES: usize = 5;

/// 用户设备 Repository trait。
///
/// 提供设备注册 / 阻断 / 查询能力，`register_device` 在设备数超过 [`MAX_DEVICES`] 时
/// 返回 `GarrisonError::InvalidParam`。重复注册同一设备（相同 identifier）幂等返回已有 ID。
///
/// `login_id` 为 `&str`（与全局 login_id 类型一致）。
#[async_trait::async_trait]
pub trait UserDeviceRepository: Send + Sync {
    /// 注册设备，返回设备 ID（UUID）。
    ///
    /// - 若 (tenant_id, login_id, identifier) 已存在，更新 last_seen_at 并返回已有 ID（幂等）。
    /// - 若当前设备数 >= [`MAX_DEVICES`]，返回 `GarrisonError::InvalidParam`。
    ///
    /// # 原子性（MAX_DEVICES 上限）
    ///
    /// 参考实现（`DbnexusUserDeviceRepository`）将「设备计数检查 + 插入」合并为
    /// 单条条件 `INSERT ... SELECT ... WHERE (SELECT COUNT(*)) < MAX_DEVICES` 语句，
    /// 消除 check-then-act TOCTOU：SQLite（单写者）下完全原子；PostgreSQL / MySQL
    /// 在 READ COMMITTED 及以上隔离级别下，两条并发语句仍可能各自看到语句级快照
    /// 而同时插入（极小窗口）——彻底封死需 DB 级触发器 / 计数约束或更高隔离级别，
    /// DAO 层无跨语句事务 API，故按此最小化方案实现并在此声明剩余窗口。
    async fn register_device(
        &self,
        tenant_id: i64,
        login_id: &str,
        identifier: &str,
        ua: &str,
    ) -> GarrisonResult<String>;

    /// 阻止设备（设置 is_blocked = 1）。
    ///
    /// 必须同时传 `tenant_id` 与 `device_id`（SQL `WHERE tenant_id = ? AND id = ?`）：
    /// 这是 `app_user_device` 唯一的按 id 直写路径，缺租户谓词会构成跨租户封禁
    /// 原语（渗透-租户隔离-设备接口-1）。跨租户 `device_id` 命中 0 行（no-op 幂等）。
    async fn block_device(&self, tenant_id: i64, device_id: &str) -> GarrisonResult<()>;

    /// 解除阻止（设置 is_blocked = 0）。
    ///
    /// 租户谓词契约同 [`block_device`](Self::block_device)。
    async fn unblock_device(&self, tenant_id: i64, device_id: &str) -> GarrisonResult<()>;

    /// 列出用户的所有设备（按 tenant_id + login_id 过滤）。
    async fn list_user_devices(
        &self,
        tenant_id: i64,
        login_id: &str,
    ) -> GarrisonResult<Vec<UserDeviceRow>>;

    /// 统计用户设备数。
    async fn count_user_devices(&self, tenant_id: i64, login_id: &str) -> GarrisonResult<usize>;
}

/// WebAuthn 凭据绑定结果。
///
/// `(tenant_id, credential_id)` 为主键，数据库唯一约束兜底并发绑定；
/// `create` 冲突时回查归属返回 `AlreadyBound`（与登录标识注册同款语义），
/// 供业务方决定处置（拒绝注册 / 引导登录）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebauthnBindOutcome {
    /// 绑定成功（该凭据此前未被占用）。
    Bound,
    /// 凭据已被绑定（携带占用者 user_id；不泄露其他行内容）。
    AlreadyBound {
        /// 当前占用该凭据的用户 ID。
        by_user_id: String,
    },
}

/// WebAuthn 凭据行（app_webauthn_credential）。
///
/// 承载凭据模型核心字段：`credential_id` 唯一（主键成分）、公钥（COSEKey
/// JSON）、sign_count（克隆检测依据）、backup flags（BE 只升不降 / BS 跟随
/// 最新断言）、attestation（注册期格式标识，可空）。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WebauthnCredentialRow {
    /// 租户 ID。
    pub tenant_id: i64,
    /// 绑定用户 ID。
    pub user_id: String,
    /// 凭据 ID（base64url，与 COSE credentialId 一致；主键成分）。
    pub credential_id: String,
    /// 公钥（JSON 序列化的 COSEKey，含算法与坐标）。
    pub public_key: String,
    /// 签名计数器（sign_count；业务层拒绝 count ≤ 上次值的断言——克隆嫌疑）。
    pub sign_count: u32,
    /// 备份资格（backup eligible；只升不降）。
    pub backup_eligible: bool,
    /// 备份状态（backup state；跟随最新断言）。
    pub backup_state: bool,
    /// attestation 格式标识（如 "none" / "packed"；可空）。
    pub attestation: Option<String>,
    /// 创建时间（epoch seconds）。
    pub created_at: i64,
    /// 更新时间（epoch seconds）。
    pub updated_at: i64,
}

/// WebAuthn 凭据 Repository trait。
///
/// 提供 Passkey 凭据的持久化能力：绑定（数据库级原子防重）/ 按凭据查询 /
/// 按用户列举 / 认证器状态更新（sign_count + backup flags）/ 解绑（幂等）。
///
/// 业务不变式（DAO 层不裁决，由 protocol/webauthn service 执行）：
/// - sign_count 单调性（count ≤ 上次 → 克隆嫌疑拒绝）；
/// - backup_eligible 只升不降（BE 升级单向）。
#[async_trait::async_trait]
pub trait WebauthnCredentialRepository: Send + Sync {
    /// 绑定凭据。
    ///
    /// `(tenant_id, credential_id)` 冲突时回查归属返回
    /// [`WebauthnBindOutcome::AlreadyBound`]（数据库唯一约束兜底并发）。
    async fn create(&self, row: &WebauthnCredentialRow) -> GarrisonResult<WebauthnBindOutcome>;

    /// 按凭据 ID 查询（未绑定返回 `Ok(None)`）。
    async fn find_by_credential_id(
        &self,
        tenant_id: i64,
        credential_id: &str,
    ) -> GarrisonResult<Option<WebauthnCredentialRow>>;

    /// 列出用户全部凭据（按 tenant_id + user_id 过滤）。
    async fn list_by_user(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> GarrisonResult<Vec<WebauthnCredentialRow>>;

    /// 更新认证器状态（sign_count / backup flags），updated_at 同步刷新。
    ///
    /// 凭据不存在时返回 `GarrisonError::InvalidParam`（不静默吞错）。
    async fn update_authenticator_state(
        &self,
        tenant_id: i64,
        credential_id: &str,
        sign_count: u32,
        backup_eligible: bool,
        backup_state: bool,
    ) -> GarrisonResult<()>;

    /// 解绑凭据（幂等：不存在返回 `Ok(())`）。
    async fn delete(&self, tenant_id: i64, credential_id: &str) -> GarrisonResult<()>;
}

// ============================================================================
// 密码历史（app_password_history）
// ============================================================================

/// 密码历史 Repository trait。
///
/// 记录用户历史密码 hash（`PasswordHasher::hash` 产物，PHC 字符串），
/// 供 `account-policy` 的 `HistoryRule` 拒绝重用最近 N 条历史密码。
/// 追加时机：找回密码重置成功、常规改密与注册路径（host 责任）。
#[async_trait::async_trait]
pub trait PasswordHistoryRepository: Send + Sync {
    /// 追加一条历史 hash（created_at 取当前 epoch 秒）。
    async fn append(
        &self,
        tenant_id: i64,
        user_id: &str,
        password_hash: &str,
    ) -> GarrisonResult<()>;

    /// 取最近 `limit` 条历史 hash（按 created_at 倒序，新在前）。
    async fn recent(
        &self,
        tenant_id: i64,
        user_id: &str,
        limit: u32,
    ) -> GarrisonResult<Vec<String>>;
}

// ============================================================================
// Dbnexus Repository 实现子模块。
// 启用 db-sqlite 或 db-postgres feature 时编译，基于 dbnexus DbPool + sea-orm
// Statement 参数化查询，通过 make_statement 运行时占位符转换支持两种后端。
// ============================================================================
/// Dbnexus Repository 实现子模块（backend-agnostic，支持 SQLite / PostgreSQL）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub mod sqlite;

/// PostgreSQL Repository 实现子模块。
///
/// 复用 `sqlite` 模块的 backend-agnostic 实现（通过 `make_statement` 自动转换占位符），
/// 仅以 Postgres 命名空间 re-export 类型别名，避免代码重复。详见 `postgres/mod.rs` 文档。
#[cfg(feature = "db-postgres")]
pub mod postgres;

/// MySQL Repository 实现子模块。
///
/// 复用 `sqlite` 模块的 backend-agnostic 实现（通过 `make_statement` 自动转换占位符），
/// 仅以 MySQL 命名空间 re-export 类型别名，避免代码重复。详见 `postgres/mod.rs` 文档。
#[cfg(feature = "db-mysql")]
pub mod mysql;

/// 角色层级子模块。
///
/// always compiled（`RoleHierarchyRecord` 不依赖 db-sqlite）。
/// `RoleHierarchyService` 在 扩展时依赖 `GarrisonDao` trait（always compiled）。
pub mod role_hierarchy;

// ============================================================================
// Backend-agnostic 辅助函数。
// 启用 db-sqlite 或 db-postgres feature 时编译。
// 运行时根据 DbBackend 转换 SQL 占位符（SQLite ? / PostgreSQL $1,$2）。
// ============================================================================

/// 转换 SQL 占位符为指定后端的方言。
///
/// - `DbBackend::Sqlite`：保留 `?` 占位符
/// - `DbBackend::Postgres`：将第 n 个 `?` 替换为 `$n`
/// - 其他后端：保留 `?`（由调用方确保兼容性）
///
/// # 跳过的上下文
///
/// 以下上下文中的 `?` 不被替换（避免参数序号错位）：
/// - 单引号字符串字面量（含 `''` 转义）
/// - `--` 行注释（至行尾）
/// - `/* */` 块注释（支持嵌套，与 PostgreSQL 语义一致）
///
/// # 示例
///
/// ```
/// use dbnexus::sea_orm::DbBackend;
/// use garrison::dao::repository::convert_placeholders;
///
/// let sql = "WHERE id = ? AND name = ?";
/// assert_eq!(convert_placeholders(sql, DbBackend::Sqlite), "WHERE id = ? AND name = ?");
/// assert_eq!(convert_placeholders(sql, DbBackend::Postgres), "WHERE id = $1 AND name = $2");
/// ```
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub fn convert_placeholders(sql: &str, backend: dbnexus::sea_orm::DbBackend) -> String {
    use dbnexus::sea_orm::DbBackend;
    if backend != DbBackend::Postgres {
        return sql.to_string();
    }
    let mut result = String::with_capacity(sql.len() + 16);
    let mut n = 0u32;
    // 状态机：跳过字符串字面量与注释内的 `?`，避免参数序号错位。
    // - `''` 在 SQL 标准中是字符串内转义单引号（一个字面 `'`），保持 in_string=true。
    // - `--` 行注释：跳过至行尾（含换行符）。
    // - `/* */` 块注释：支持嵌套（PostgreSQL 语义），首个未匹配的 `*/` 结束最内层。
    let mut in_string = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut block_depth = 0usize;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if in_line_comment {
            // 行注释：原样输出直到行尾
            if c == '\n' {
                in_line_comment = false;
            }
            result.push(c);
            continue;
        }
        if in_block_comment {
            // 块注释：原样输出，支持嵌套
            if c == '/' && chars.peek() == Some(&'*') {
                result.push('/');
                result.push('*');
                chars.next();
                block_depth += 1;
            } else if c == '*' && chars.peek() == Some(&'/') {
                result.push('*');
                result.push('/');
                chars.next();
                block_depth -= 1;
                if block_depth == 0 {
                    in_block_comment = false;
                }
            } else {
                result.push(c);
            }
            continue;
        }
        match c {
            '-' if !in_string && chars.peek() == Some(&'-') => {
                // 行注释开始：`--` 至行尾，注释内的 `?` 不替换
                result.push('-');
                result.push('-');
                chars.next();
                in_line_comment = true;
            },
            '/' if !in_string && chars.peek() == Some(&'*') => {
                // 块注释开始：`/*` 至匹配的 `*/`，注释内的 `?` 不替换
                result.push('/');
                result.push('*');
                chars.next();
                in_block_comment = true;
                block_depth = 1;
            },
            '\'' if in_string => {
                // 在字符串内遇 `'`，look-ahead 判断是否为 `''` 转义
                if chars.peek() == Some(&'\'') {
                    // `''` 转义：保留两个 `'`，仍在字符串内
                    result.push('\'');
                    result.push('\'');
                    chars.next();
                } else {
                    // 字符串字面量结束
                    result.push('\'');
                    in_string = false;
                }
            },
            '\'' => {
                // 进入字符串字面量
                result.push('\'');
                in_string = true;
            },
            '?' if !in_string => {
                n += 1;
                result.push('$');
                result.push_str(&n.to_string());
            },
            c => result.push(c),
        }
    }
    result
}

/// 构造 backend-agnostic 的 [`dbnexus::sea_orm::Statement`]，根据 conn 的 backend 自动转换占位符。
///
/// 封装 [`convert_placeholders`] + [`dbnexus::sea_orm::Statement::from_sql_and_values`]，
/// 让 Repository 实现无需关心后端差异——传入 `?` 占位符的 SQL 即可，
/// Postgres backend 会自动转换为 `$1`, `$2`, ...
///
/// # 示例
///
/// ```ignore
/// use garrison::dao::repository::make_statement;
/// use dbnexus::sea_orm::Value;
///
/// // 实际使用时传入真实的 DatabaseConnection（Sqlite 或 Postgres 后端）
/// let stmt = make_statement(&conn, "WHERE id = ?", vec![Value::Int(Some(1))]);
/// ```
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub fn make_statement(
    conn: &impl dbnexus::sea_orm::ConnectionTrait,
    sql: &str,
    values: Vec<dbnexus::sea_orm::Value>,
) -> dbnexus::sea_orm::Statement {
    let backend = conn.get_database_backend();
    let sql = convert_placeholders(sql, backend);
    dbnexus::sea_orm::Statement::from_sql_and_values(backend, sql, values)
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
            login_id: "1001".to_string(),
            device_identifier: "ua-hash-abc".to_string(),
            device_name: Some("Chrome on Windows".to_string()),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0)".to_string()),
            is_blocked: false,
            last_seen_at: Some(1750000000),
            created_at: 1749000000,
        };
        assert_eq!(row.id, "dev-001");
        assert_eq!(row.tenant_id, 42);
        assert_eq!(row.login_id, "1001");
        assert_eq!(row.device_identifier, "ua-hash-abc");
        assert!(!row.is_blocked);
    }

    /// MAX_DEVICES 常量值为 5。
    #[test]
    fn max_devices_is_five() {
        assert_eq!(MAX_DEVICES, 5);
    }

    // ========================================================================
    // New* struct 构造测试
    // ========================================================================

    /// NewUser 可构造。
    #[test]
    fn new_user_constructs() {
        let new = NewUser {
            username: "alice".to_string(),
            password_hash: "$argon2id$...".to_string(),
            status: "active".to_string(),
        };
        assert_eq!(new.username, "alice");
    }

    /// NewRole 可构造。
    #[test]
    fn new_role_constructs() {
        let new = NewRole {
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
    // trait Send + Sync 编译期检查
    // ========================================================================

    /// 所有 Repository trait 为 Send + Sync（编译期检查）。
    ///
    /// 注：`?Sized` 允许 `dyn Trait` 作为类型参数（dyn Trait 不实现 Sized）。
    #[test]
    fn all_repository_traits_are_send_sync() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        // 这些 trait object 检查仅验证 trait 本身满足 Send + Sync 约束，
        // 具体 impl 由各后端实现的测试单独验证
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
    // convert_placeholders 测试（依据 P3 重构决策）
    // ========================================================================

    /// SQLite 后端保留 `?` 占位符不变。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_sqlite_keeps_question_mark() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "WHERE id = ? AND name = ?";
        let result = convert_placeholders(sql, DbBackend::Sqlite);
        assert_eq!(result, "WHERE id = ? AND name = ?");
    }

    /// PostgreSQL 后端将 `?` 替换为 `$1`, `$2`, ...
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_postgres_replaces_with_dollar_n() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "WHERE id = ? AND name = ?";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(result, "WHERE id = $1 AND name = $2");
    }

    /// 单个占位符也能正确转换。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_postgres_single_placeholder() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "WHERE id = ?";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(result, "WHERE id = $1");
    }

    /// 无占位符的 SQL 不受影响。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_no_placeholder_unchanged() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT 1";
        assert_eq!(convert_placeholders(sql, DbBackend::Postgres), "SELECT 1");
        assert_eq!(convert_placeholders(sql, DbBackend::Sqlite), "SELECT 1");
    }

    /// 多个占位符（5 个）能正确编号。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_postgres_five_placeholders() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "VALUES (?, ?, ?, ?, ?)";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(result, "VALUES ($1, $2, $3, $4, $5)");
    }

    /// Postgres 后端跳过单引号字符串字面量内的 `?`，引号外仍替换为 `$n`。
    ///
    /// 场景：SQL 注释/字面量中的 `?`（如 `note = '?'`）不应被当作占位符替换，
    /// 否则参数序号错位导致后续 `$n` 与绑定参数不匹配。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_skips_question_mark_inside_string_literal() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT * FROM t WHERE note = '?' AND id = ?";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT * FROM t WHERE note = '?' AND id = $1",
            "引号内 ? 不应替换，引号外 ? 应替换为 $1"
        );
    }

    /// Postgres 后端处理连续 `''` 转义单引号后仍正确替换占位符。
    ///
    /// 场景：SQL 字面量 `''` 表示一个字面单引号字符（不结束字符串），
    /// 因此 `'' AS empty` 之后 `?` 仍在字符串外，应被替换为 `$1`。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_handles_escaped_single_quote() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT '' AS empty, ? AS v";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT '' AS empty, $1 AS v",
            "连续 '' 转义单引号后 ? 仍应替换为 $1"
        );
    }

    /// 覆盖 SQL 字符串字面量内的 `''` 转义分支（L743-L748）。
    ///
    /// 场景：SQL 标准中字符串字面量内的 `''` 表示一个字面单引号字符
    /// （不结束字符串），如 `'a''b'` 表示字符串 `a'b`。状态机应保持
    /// `in_string=true`，使转义后的 `?` 在字符串外被替换为 `$1`。
    /// 仅覆盖独立 `''`（空字符串字面量），未触发字符串内转义分支。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_handles_escaped_quote_inside_string_literal() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT 'a''b' AS s, ? AS v";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT 'a''b' AS s, $1 AS v",
            "字符串字面量内 '' 转义分支：状态机应保持 in_string=true，转义后 ? 应替换为 $1"
        );
    }

    /// `--` 行注释内的 `?` 不被替换，注释后的 `?` 正常编号。
    ///
    /// 场景：`SELECT ? -- comment with ?` 若注释内 `?` 被替换，
    /// 会导致参数序号错位（绑定值与占位符不匹配）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_skips_question_mark_in_line_comment() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT ? -- comment with ? here\nWHERE id = ?";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT $1 -- comment with ? here\nWHERE id = $2",
            "行注释内 ? 不应替换，注释结束后 ? 应继续编号为 $2"
        );
    }

    /// `/* */` 块注释内的 `?` 不被替换。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_skips_question_mark_in_block_comment() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT ?, /* hint: ? not a placeholder */ ? AS b";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT $1, /* hint: ? not a placeholder */ $2 AS b",
            "块注释内 ? 不应替换，注释外 ? 正常编号"
        );
    }

    /// 嵌套块注释（PostgreSQL 语义）内层的 `?` 也不替换。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_handles_nested_block_comments() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT ? /* outer /* inner ? */ still comment ? */ , ? AS b";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT $1 /* outer /* inner ? */ still comment ? */ , $2 AS b",
            "嵌套块注释内的 ? 均不应替换，第一个未匹配 */ 结束内层、第二个结束外层"
        );
    }

    /// 字符串字面量内的 `--` / `/*` 不应被误判为注释开始。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn convert_placeholders_comment_markers_inside_string_are_literal() {
        use dbnexus::sea_orm::DbBackend;
        let sql = "SELECT '-- not a comment /* neither */ ?' AS s, ? AS v";
        let result = convert_placeholders(sql, DbBackend::Postgres);
        assert_eq!(
            result, "SELECT '-- not a comment /* neither */ ?' AS s, $1 AS v",
            "字符串字面量内的注释标记应按字面量处理，其中 ? 不替换也不计数"
        );
    }

    // ========================================================================
    // make_statement 测试（依据 P3 重构决策）
    // ========================================================================

    /// Mock 连接，仅用于测试 `make_statement` 的 backend 检测逻辑。
    /// 其他方法未实现（`make_statement` 仅调用 `get_database_backend`）。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    struct MockConn {
        backend: dbnexus::sea_orm::DbBackend,
    }

    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[async_trait::async_trait]
    impl dbnexus::sea_orm::ConnectionTrait for MockConn {
        fn get_database_backend(&self) -> dbnexus::sea_orm::DbBackend {
            self.backend
        }

        async fn execute_raw(
            &self,
            _stmt: dbnexus::sea_orm::Statement,
        ) -> Result<dbnexus::sea_orm::ExecResult, dbnexus::sea_orm::DbErr> {
            Err(dbnexus::sea_orm::DbErr::Custom(
                "MockConn only supports get_database_backend".into(),
            ))
        }

        async fn execute_unprepared(
            &self,
            _sql: &str,
        ) -> Result<dbnexus::sea_orm::ExecResult, dbnexus::sea_orm::DbErr> {
            Err(dbnexus::sea_orm::DbErr::Custom(
                "MockConn only supports get_database_backend".into(),
            ))
        }

        async fn query_one_raw(
            &self,
            _stmt: dbnexus::sea_orm::Statement,
        ) -> Result<Option<dbnexus::sea_orm::QueryResult>, dbnexus::sea_orm::DbErr> {
            Err(dbnexus::sea_orm::DbErr::Custom(
                "MockConn only supports get_database_backend".into(),
            ))
        }

        async fn query_all_raw(
            &self,
            _stmt: dbnexus::sea_orm::Statement,
        ) -> Result<Vec<dbnexus::sea_orm::QueryResult>, dbnexus::sea_orm::DbErr> {
            Err(dbnexus::sea_orm::DbErr::Custom(
                "MockConn only supports get_database_backend".into(),
            ))
        }
    }

    /// SQLite backend：`make_statement` 保留 `?` 占位符。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn make_statement_sqlite_uses_question_mark() {
        let conn = MockConn {
            backend: dbnexus::sea_orm::DbBackend::Sqlite,
        };
        let stmt = make_statement(
            &conn,
            "WHERE id = ? AND name = ?",
            vec![
                dbnexus::sea_orm::Value::Int(Some(1)),
                dbnexus::sea_orm::Value::String(Some("alice".into())),
            ],
        );
        assert_eq!(stmt.sql, "WHERE id = ? AND name = ?");
    }

    /// Postgres backend：`make_statement` 将 `?` 替换为 `$1`, `$2`。
    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[test]
    fn make_statement_postgres_uses_dollar_n() {
        let conn = MockConn {
            backend: dbnexus::sea_orm::DbBackend::Postgres,
        };
        let stmt = make_statement(
            &conn,
            "WHERE id = ? AND name = ?",
            vec![
                dbnexus::sea_orm::Value::Int(Some(1)),
                dbnexus::sea_orm::Value::String(Some("alice".into())),
            ],
        );
        assert_eq!(stmt.sql, "WHERE id = $1 AND name = $2");
    }

    // ========================================================================
    // PostgreSQL 后端集成测试
    // ========================================================================
    //
    // 验证 DbnexusUserRepository 在 PostgreSQL 后端下能正确执行 find_by_id，
    // 间接验证 make_statement 运行时占位符转换（? → $1, $2）在真实 PG 上工作。
    //
    // 此测试需要真实 PostgreSQL 实例，默认 #[ignore]。
    // 运行方式：
    // export DATABASE_URL=postgres://user:pass@localhost:5432/testdb
    // cargo test --features db-postgres --lib \
    // repository::tests::dbnexus_user_repository_works_with_postgres_backend -- --ignored

    /// 验证 DbnexusUserRepository 在 PostgreSQL 后端下 find_by_id 正确执行。
    ///
    /// 测试流程：建表 → 插入用户 → find_by_id → 断言字段 → 清理。
    /// 如果占位符转换失败（? 未转为 $n），PostgreSQL 会返回语法错误。
    #[cfg(feature = "db-postgres")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial_test::serial]
    #[ignore = "需要真实 PostgreSQL，设置 DATABASE_URL 后 cargo test -- --ignored 运行"]
    async fn dbnexus_user_repository_works_with_postgres_backend() {
        use crate::dao::init_dbnexus;
        use crate::dao::repository::sqlite::DbnexusUserRepository;
        use dbnexus::sea_orm::ConnectionTrait;

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

        let repo = DbnexusUserRepository::new(pool.clone());

        let tenant_id: i64 = 42;
        let user_id = repo
            .create(
                tenant_id,
                NewUser {
                    username: "pg-test-user".to_string(),
                    password_hash: "$argon2id$m=8,t=1,p=1$fake-hash".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("插入测试用户失败");

        // 5. find_by_id 验证占位符转换（? → $1, $2 在真实 PG 上执行）
        let found = repo
            .find_by_id(tenant_id, &user_id)
            .await
            .expect("find_by_id 查询失败")
            .expect("测试用户未找到");

        assert_eq!(found.id, user_id);
        assert_eq!(found.username, "pg-test-user");
        assert_eq!(found.password_hash, "$argon2id$m=8,t=1,p=1$fake-hash");
        assert_eq!(found.status, "active");
        assert_eq!(found.tenant_id, tenant_id);

        repo.delete(tenant_id, &user_id)
            .await
            .expect("清理测试数据失败");

        // 8. 删除手动建的表。本测试不经迁移器建表；若 app_user 残留，
        //    run_embedded_postgres 的 001_init 将撞「表已存在」。两个 postgres
        //    集成测试共用 DATABASE_URL（#[serial] 串行，先后顺序均可）。
        {
            let session = pool.get_session("admin").await.expect("获取 session 失败");
            let conn = session.connection().expect("获取 connection 失败");
            conn.execute_unprepared("DROP TABLE IF EXISTS app_user")
                .await
                .expect("清理 app_user 表失败");
        }
    }

    // ========================================================================
    // 导入哈希校验门
    // ========================================================================

    /// 上限常量值锁定：Argon2 m ≤ 1 GiB / t ≤ 10 / p ≤ 4，bcrypt cost ≤ 15
    /// （防单次登录 OOM / CPU DoS 的防御基线）。
    #[test]
    fn imported_hash_limit_constants_match_defense_baseline() {
        assert_eq!(ARGON2_IMPORT_MAX_M_COST, 1_048_576);
        assert_eq!(ARGON2_IMPORT_MAX_T, 10);
        assert_eq!(ARGON2_IMPORT_MAX_P, 4);
        assert_eq!(BCRYPT_IMPORT_MAX_COST, 15);
    }

    /// 越界参数：m/t/p 各超上限、bcrypt cost 超上限 → Err，错误含具体阶段标识
    /// （显性拒绝，不静默放行或截断）。
    #[test]
    fn imported_hash_rejects_out_of_range_params() {
        let m_over = "$argon2id$v=19$m=2097152,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        match validate_imported_hash(m_over) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-argon2-m-cost"),
                "m 超上限错误应含 import-hash-argon2-m-cost，实际: {}",
                msg
            ),
            other => panic!("m 超上限应返回 InvalidParam，实际: {:?}", other.map(|_| ())),
        }
        let t_over = "$argon2id$v=19$m=19456,t=11,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        match validate_imported_hash(t_over) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-argon2-t-cost"),
                "t 超上限错误应含 import-hash-argon2-t-cost，实际: {}",
                msg
            ),
            other => panic!("t 超上限应返回 InvalidParam，实际: {:?}", other.map(|_| ())),
        }
        let p_over = "$argon2id$v=19$m=19456,t=2,p=5$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        match validate_imported_hash(p_over) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-argon2-p-cost"),
                "p 超上限错误应含 import-hash-argon2-p-cost，实际: {}",
                msg
            ),
            other => panic!("p 超上限应返回 InvalidParam，实际: {:?}", other.map(|_| ())),
        }
        // nosemgrep: generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash —— validate_imported_hash 超限测试的 bcrypt 形状夹具（非真实凭证）
        let bcrypt_over = "$2b$16$012345678901234567890123456789012345678901234567890123456";
        match validate_imported_hash(bcrypt_over) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-bcrypt-cost"),
                "bcrypt cost 超上限错误应含 import-hash-bcrypt-cost，实际: {}",
                msg
            ),
            other => panic!(
                "bcrypt cost 超上限应返回 InvalidParam，实际: {:?}",
                other.map(|_| ())
            ),
        }
    }

    /// 边界值：恰好等于上限 → Ok（不误杀合法迁移来源）。
    #[test]
    fn imported_hash_accepts_boundary_values() {
        let at_limit = "$argon2id$v=19$m=1048576,t=10,p=4$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        assert!(
            validate_imported_hash(at_limit).is_ok(),
            "m=1GiB/t=10/p=4 恰在边界应放行"
        );
        // nosemgrep: generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash —— validate_imported_hash 边界值测试的 bcrypt 形状夹具（非真实凭证）
        let bcrypt_at_limit = "$2b$15$012345678901234567890123456789012345678901234567890123456";
        assert!(
            validate_imported_hash(bcrypt_at_limit).is_ok(),
            "bcrypt cost=15 恰在边界应放行"
        );
    }

    /// 白名单外前缀：argon2i/argon2d、scrypt、空串、乱串 → Err（仅四个白名单
    /// 前缀可导入）。
    #[test]
    fn imported_hash_rejects_non_whitelisted_prefixes() {
        let rejected = [
            "$argon2i$v=19$m=19456,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
            "$argon2d$v=19$m=19456,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
            "$scrypt$ln=16,r=8,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
            "$argon2idX$v=19$m=19456,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg",
            "not-a-hash",
            "",
        ];
        for bad in rejected {
            assert!(
                matches!(
                    validate_imported_hash(bad),
                    Err(GarrisonError::InvalidParam(_))
                ),
                "白名单外 {:?} 应返回 InvalidParam",
                bad
            );
        }
    }

    /// 白名单内常见来源：默认档位 argon2id 与三种 bcrypt 前缀变体 → Ok。
    #[test]
    fn imported_hash_accepts_whitelisted_formats() {
        let argon2id = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        assert!(validate_imported_hash(argon2id).is_ok(), "默认档位应放行");
        for prefix in ["$2b$", "$2a$", "$2y$"] {
            let hash = format!(
                "{}12$012345678901234567890123456789012345678901234567890123456",
                prefix
            );
            assert!(
                validate_imported_hash(&hash).is_ok(),
                "{} 前缀 cost=12 应放行",
                prefix
            );
        }
    }

    /// 畸形参数段：argon2id 缺参数段 / 参数不全、bcrypt 缺 cost 段 → Err
    /// （无法确认参数上限即拒绝，fail-closed）。
    #[test]
    fn imported_hash_rejects_unparseable_params() {
        let missing_params = "$argon2id$v=19$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        match validate_imported_hash(missing_params) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-argon2-format"),
                "缺参数段错误应含 import-hash-argon2-format，实际: {}",
                msg
            ),
            other => panic!("缺参数段应返回 InvalidParam，实际: {:?}", other.map(|_| ())),
        }
        let partial_params = "$argon2id$m=19456,t=2$c2FsdDEyMzQ1Njc4$MDEyMzQ1Njc4OWFiY2RlZg";
        assert!(
            matches!(
                validate_imported_hash(partial_params),
                Err(GarrisonError::InvalidParam(_))
            ),
            "参数不全应返回 InvalidParam"
        );
        let bcrypt_no_cost = "$2b$rest-of-hash";
        match validate_imported_hash(bcrypt_no_cost) {
            Err(GarrisonError::InvalidParam(msg)) => assert!(
                msg.contains("import-hash-bcrypt-format"),
                "缺 cost 段错误应含 import-hash-bcrypt-format，实际: {}",
                msg
            ),
            other => panic!(
                "缺 cost 段应返回 InvalidParam，实际: {:?}",
                other.map(|_| ())
            ),
        }
        let bcrypt_bad_cost = "$2b$xx$012345678901234567890123456789012345678901234567890123456";
        assert!(
            matches!(
                validate_imported_hash(bcrypt_bad_cost),
                Err(GarrisonError::InvalidParam(_))
            ),
            "cost 段非数字应返回 InvalidParam"
        );
    }
}
