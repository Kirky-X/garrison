-- Migration: 新增登录标识唯一性表 app_user_identifier
-- 对应 spec: security-audit-remediation（T022，phone/email 数据库级原子防重）
-- 数据库: SQLite 3.35+
-- 幂等性: CREATE TABLE/INDEX 使用 IF NOT EXISTS

-- UP:

CREATE TABLE IF NOT EXISTS app_user_identifier (
    id_type TEXT NOT NULL,
    id_value TEXT NOT NULL,
    tenant_id BIGINT NOT NULL DEFAULT 0,
    user_id TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id_type, id_value)
);

CREATE INDEX IF NOT EXISTS idx_app_user_identifier_user ON app_user_identifier (user_id);

-- DOWN:
DROP INDEX IF EXISTS idx_app_user_identifier_user;
DROP TABLE IF EXISTS app_user_identifier;
