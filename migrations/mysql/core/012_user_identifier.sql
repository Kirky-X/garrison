-- Migration: 新增登录标识唯一性表 app_user_identifier
-- 对应 spec: security-audit-remediation（T022，phone/email 数据库级原子防重）
-- 数据库: MySQL 8.0+
-- 幂等性: dbnexus 迁移器按版本号一次性应用（dbnexus_migrations 历史表去重），
--         普通 DDL 即可——MySQL 8 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属，
--         011 同款教训：真实 MySQL E2E 曾因该语法炸 1064），故此处不带。

-- UP:

CREATE TABLE IF NOT EXISTS app_user_identifier (
    id_type VARCHAR(32) NOT NULL,
    id_value VARCHAR(255) NOT NULL,
    tenant_id BIGINT NOT NULL DEFAULT 0,
    user_id VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id_type, id_value)
);

CREATE INDEX idx_app_user_identifier_user ON app_user_identifier (user_id);

-- DOWN:
DROP INDEX idx_app_user_identifier_user ON app_user_identifier;
DROP TABLE IF EXISTS app_user_identifier;
