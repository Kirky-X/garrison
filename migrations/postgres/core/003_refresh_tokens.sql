-- Migration: RefreshToken 轮换表（PostgreSQL 版本，v0.5.0 新增，依据 proposal H4）
-- 对应 spec: jwt-refresh-rotation（hash chain + reuse detection）
-- 数据库: PostgreSQL
-- 幂等性: CREATE TABLE 使用 IF NOT EXISTS
--
-- 用途：存储 RefreshToken 的 hash chain 记录，支持多租户隔离与密钥轮换。
-- RefreshTokenRotation.rotate() 读写此表：
--   1. 查 SHA-256(old_token) 验证未 revoked
--   2. INSERT 新 record（parent_token_hash 指向旧 token_hash）
--   3. UPDATE 旧 record revoked=1（防重放）
-- detect_reuse() 查 revoked=1 判断 token 是否被重用。
-- revoke_chain() 递归 UPDATE parent_token_hash 链吊销整条链。

-- UP:

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash         TEXT    PRIMARY KEY,             -- SHA-256(token)，主键
    parent_token_hash  TEXT,                             -- 旧 token 的 SHA-256（首次签发为 NULL）
    login_id           TEXT    NOT NULL,                 -- 关联用户 ID（String）
    tenant_id          BIGINT  NOT NULL DEFAULT 0,       -- 租户 ID（i64，0=默认租户）
    key_version        BIGINT  NOT NULL,                 -- 密钥轮换版本号
    expires_at         BIGINT  NOT NULL,                 -- 过期时间（Unix 秒）
    revoked            BIGINT  NOT NULL DEFAULT 0,       -- 是否已撤销（0=false, 1=true）
    created_at         BIGINT  NOT NULL                  -- 创建时间（Unix 秒）
);

-- 查询索引：按 login_id 查询用户的所有 refresh_token（rotate 时验证用户身份）
CREATE INDEX IF NOT EXISTS idx_refresh_login
    ON refresh_tokens (login_id);

-- 查询索引：按 parent_token_hash 查询子 token（revoke_chain 递归遍历用）
CREATE INDEX IF NOT EXISTS idx_refresh_parent
    ON refresh_tokens (parent_token_hash);

-- 查询索引：按 tenant_id 过滤（多租户隔离）
CREATE INDEX IF NOT EXISTS idx_refresh_tenant
    ON refresh_tokens (tenant_id);
