-- Copyright (c) 2026 Kirky.X🌠
-- SPDX-License-Identifier: Apache-2.0

-- Migration: 新增 WebAuthn/Passkey 凭据表 app_webauthn_credential
-- 对应 spec: webauthn（凭据模型与持久化）
-- 数据库: MySQL 8.0+
-- 幂等性: dbnexus 迁移器按版本号一次性应用（dbnexus_migrations 历史表去重），
--         普通 DDL 即可——MySQL 8 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属，
--         011 同款教训：真实 MySQL E2E 曾因该语法炸 1064），故此处不带。

-- UP:

CREATE TABLE IF NOT EXISTS app_webauthn_credential (
    tenant_id BIGINT NOT NULL DEFAULT 0,
    user_id VARCHAR(255) NOT NULL,
    -- WebAuthn credential ID 规范上限 1023 字节（base64url ≈ 1364 字符）；
-- utf8mb4 复合主键字节预算 3072 = tenant_id BIGINT(8) + credential_id → 上限 766 字符
-- （768×4=3072 未给 tenant_id 留位，真实 MySQL 8 触发 1071 Specified key was too long）
    credential_id VARCHAR(766) NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INT NOT NULL DEFAULT 0,
    backup_eligible TINYINT NOT NULL DEFAULT 0,
    backup_state TINYINT NOT NULL DEFAULT 0,
    attestation TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, credential_id)
);

CREATE INDEX idx_app_webauthn_credential_user
    ON app_webauthn_credential (tenant_id, user_id);

-- DOWN:
DROP INDEX idx_app_webauthn_credential_user ON app_webauthn_credential;
DROP TABLE IF EXISTS app_webauthn_credential;
