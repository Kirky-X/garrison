-- Copyright (c) 2026 Kirky.X🌠
-- SPDX-License-Identifier: Apache-2.0

-- Migration: 新增 WebAuthn/Passkey 凭据表 app_webauthn_credential
-- 对应 spec: webauthn（凭据模型与持久化）
-- 数据库: DuckDB
-- 幂等性: CREATE TABLE/INDEX 使用 IF NOT EXISTS

-- UP:

CREATE TABLE IF NOT EXISTS app_webauthn_credential (
    tenant_id BIGINT NOT NULL DEFAULT 0,
    user_id VARCHAR NOT NULL,
    credential_id VARCHAR NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state INTEGER NOT NULL DEFAULT 0,
    attestation TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, credential_id)
);

CREATE INDEX IF NOT EXISTS idx_app_webauthn_credential_user
    ON app_webauthn_credential (tenant_id, user_id);

-- DOWN:
DROP INDEX IF EXISTS idx_app_webauthn_credential_user;
DROP TABLE IF EXISTS app_webauthn_credential;
