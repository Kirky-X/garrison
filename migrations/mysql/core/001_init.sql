-- Migration: 初始化 8 张核心表 + app_user_ext 扩展表（MySQL 版本）
-- 对应 spec: extensible-schema
-- 数据库: MySQL 8.0+（VARCHAR(36) 存储 UUID，BIGINT 0/1 存储 boolean，VARCHAR(30) 存时间戳）
-- 幂等性: CREATE TABLE 使用 IF NOT EXISTS；MySQL 不支持 CREATE INDEX IF NOT EXISTS，故省略
-- 偏离说明: 依据 tasks.md T028，参考 postgres/core/001_init.sql 转换为 MySQL 方言：
--   TEXT PRIMARY KEY → VARCHAR(36) PRIMARY KEY（MySQL 要求索引列有长度）
--   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP → VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP)
--   CREATE [UNIQUE] INDEX IF NOT EXISTS → CREATE [UNIQUE] INDEX（MySQL 不支持 IF NOT EXISTS）
--   DROP INDEX IF EXISTS → 移除（DROP TABLE 自动级联删除索引）

-- UP:

-- ============================================================================
-- 1. app_user: 用户主表
-- ============================================================================
CREATE TABLE IF NOT EXISTS app_user (
    id              VARCHAR(36) PRIMARY KEY,                                  -- UUID
    username        VARCHAR(255) NOT NULL,                                    -- 账户名
    password_hash   VARCHAR(255) NOT NULL,                                    -- 密码哈希（argon2/bcrypt）
    status          VARCHAR(20) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'active', 'suspended', 'inactive', 'deleted')),
    tenant_id       BIGINT  NOT NULL DEFAULT 0,                               -- 租户 ID（i64，0=默认租户）
    created_at      VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    updated_at      VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    last_login_at   VARCHAR(30)                                               -- 最后登录时间（可空）
);
-- 注意：仅保留复合唯一 UK(username, tenant_id)，不创建全局 UK(username)。
-- 原因：多租户场景下相同 username 应能在不同 tenant_id 下共存。
CREATE UNIQUE INDEX uk_app_user_username_tenant    ON app_user (username, tenant_id);
CREATE INDEX        idx_app_user_tenant             ON app_user (tenant_id);
CREATE INDEX        idx_app_user_status             ON app_user (status);

-- ============================================================================
-- 2. app_role: 角色表
-- ============================================================================
CREATE TABLE IF NOT EXISTS app_role (
    id          VARCHAR(36) PRIMARY KEY,                                      -- UUID
    code        VARCHAR(255) NOT NULL,                                        -- 角色编码（业务用）
    name        VARCHAR(255) NOT NULL,                                        -- 角色名（展示用）
    description TEXT,                                                         -- 描述
    tenant_id   BIGINT  NOT NULL DEFAULT 0,                                   -- 租户 ID（i64）
    is_system   BIGINT  NOT NULL DEFAULT 0,                                  -- 是否系统内置角色（0=false, 1=true）
    created_at  VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    updated_at  VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP)
);
CREATE UNIQUE INDEX uk_app_role_code_tenant  ON app_role (code, tenant_id);
CREATE INDEX        idx_app_role_tenant     ON app_role (tenant_id);

-- ============================================================================
-- 3. app_permission: 权限表（全局，无 tenant_id）
-- ============================================================================
CREATE TABLE IF NOT EXISTS app_permission (
    id              VARCHAR(36) PRIMARY KEY,                                  -- UUID
    code            VARCHAR(255) NOT NULL,                                    -- 权限编码（全局唯一）
    name            VARCHAR(255) NOT NULL,                                    -- 权限名
    resource_type   VARCHAR(100),                                             -- 资源类型（如 user/role/order）
    action          VARCHAR(100),                                             -- 动作（如 read/write/delete）
    created_at      VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    updated_at      VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP)
);
CREATE UNIQUE INDEX uk_app_permission_code  ON app_permission (code);

-- ============================================================================
-- 4. app_user_role: 用户-角色关联表（复合主键）
-- ============================================================================
CREATE TABLE IF NOT EXISTS app_user_role (
    user_id     VARCHAR(36) NOT NULL,
    role_id     VARCHAR(36) NOT NULL,
    scope       TEXT,                                                         -- 授权范围（如 data scope）
    grant_time  VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    tenant_id   BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES app_user (id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES app_role (id) ON DELETE CASCADE
);
CREATE INDEX idx_app_user_role_role_id  ON app_user_role (role_id);
CREATE INDEX idx_app_user_role_tenant   ON app_user_role (tenant_id);

-- ============================================================================
-- 5. app_role_permission: 角色-权限关联表（复合主键）
-- ============================================================================
CREATE TABLE IF NOT EXISTS app_role_permission (
    role_id         VARCHAR(36) NOT NULL,
    permission_id   VARCHAR(36) NOT NULL,
    tenant_id       BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id)         REFERENCES app_role       (id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id)   REFERENCES app_permission  (id) ON DELETE CASCADE
);
CREATE INDEX idx_app_role_permission_permission_id  ON app_role_permission (permission_id);
CREATE INDEX idx_app_role_permission_tenant          ON app_role_permission (tenant_id);

-- ============================================================================
-- 6. app_auth_method: 认证方式表
-- ============================================================================
CREATE TABLE IF NOT EXISTS app_auth_method (
    id           VARCHAR(36) PRIMARY KEY,                                     -- UUID
    user_id      VARCHAR(36) NOT NULL,
    method_type  VARCHAR(50) NOT NULL
                  CHECK (method_type IN ('passkey', 'password', 'oauth', 'did')),
    external_id  TEXT,                                                        -- 外部 ID（如 OAuth provider user id）
    metadata     TEXT,                                                        -- JSON 元数据
    create_time  VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    tenant_id    BIGINT  NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES app_user (id) ON DELETE CASCADE
);
CREATE INDEX idx_app_auth_method_user_id     ON app_auth_method (user_id);
CREATE INDEX idx_app_auth_method_external_id  ON app_auth_method (external_id(255));
CREATE INDEX idx_app_auth_method_tenant       ON app_auth_method (tenant_id);

-- ============================================================================
-- 7. app_session: 会话表（可选 DB 持久化，默认存 oxcache）
-- ============================================================================
CREATE TABLE IF NOT EXISTS app_session (
    session_id   VARCHAR(36) PRIMARY KEY,                                    -- 会话 ID（Token）
    user_id      VARCHAR(36) NOT NULL,
    device_id    VARCHAR(36),                                                 -- 设备 ID
    ip           TEXT,                                                        -- 登录 IP
    user_agent   TEXT,                                                        -- User-Agent
    login_time   VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    last_active  VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    expire_time  VARCHAR(30),                                                 -- 过期时间
    tenant_id    BIGINT  NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES app_user (id) ON DELETE CASCADE
);
CREATE INDEX idx_app_session_user_id     ON app_session (user_id);
CREATE INDEX idx_app_session_expire      ON app_session (expire_time);
CREATE INDEX idx_app_session_tenant      ON app_session (tenant_id);

-- ============================================================================
-- 8. app_login_log: 登录日志表
-- ============================================================================
CREATE TABLE IF NOT EXISTS app_login_log (
    id           VARCHAR(36) PRIMARY KEY,                                    -- UUID
    user_id      VARCHAR(36),                                                 -- 可空（登录失败时可能无 user）
    action       VARCHAR(50) NOT NULL
                  CHECK (action IN ('login', 'logout', 'refresh', 'kickout', 'kicked')),
    ip           TEXT,
    device_id    VARCHAR(36),
    success      BIGINT  NOT NULL DEFAULT 1,                                 -- 0=失败, 1=成功
    fail_reason  TEXT,
    create_time  VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    tenant_id    BIGINT  NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES app_user (id) ON DELETE SET NULL
);
CREATE INDEX idx_app_login_log_user_time    ON app_login_log (user_id, create_time);
CREATE INDEX idx_app_login_log_create_time   ON app_login_log (create_time);
CREATE INDEX idx_app_login_log_tenant        ON app_login_log (tenant_id);

-- ============================================================================
-- 9. app_user_ext: 用户扩展字段表（KV 设计，保持核心表稳定）
-- ============================================================================
CREATE TABLE IF NOT EXISTS app_user_ext (
    id           VARCHAR(36) PRIMARY KEY,                                    -- UUID
    user_id      VARCHAR(36) NOT NULL,
    field_key    VARCHAR(255) NOT NULL,                                       -- 扩展字段键（如 email/phone/avatar）
    field_value  TEXT,                                                        -- 扩展字段值
    field_type   VARCHAR(50) NOT NULL DEFAULT 'string'
                  CHECK (field_type IN ('string', 'number', 'boolean', 'json', 'datetime')),
    created_at   VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    updated_at   VARCHAR(30) NOT NULL DEFAULT (CURRENT_TIMESTAMP),
    tenant_id    BIGINT  NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES app_user (id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX uk_app_user_ext_user_key   ON app_user_ext (user_id, field_key);
CREATE INDEX        idx_app_user_ext_field_key  ON app_user_ext (field_key);
CREATE INDEX        idx_app_user_ext_tenant     ON app_user_ext (tenant_id);

-- DOWN:
-- MySQL 中 DROP TABLE 会自动级联删除关联索引，无需手动 DROP INDEX。
-- 回滚顺序：先关联表后主表（避免外键约束阻塞）。
DROP TABLE IF EXISTS app_user_ext;
DROP TABLE IF EXISTS app_login_log;
DROP TABLE IF EXISTS app_session;
DROP TABLE IF EXISTS app_auth_method;
DROP TABLE IF EXISTS app_role_permission;
DROP TABLE IF EXISTS app_user_role;
DROP TABLE IF EXISTS app_permission;
DROP TABLE IF EXISTS app_role;
DROP TABLE IF EXISTS app_user;
