-- Copyright (c) 2026 Kirky.X🌠
-- SPDX-License-Identifier: Apache-2.0

-- Migration: 密码历史表
-- 对应 spec: account/password-reset（重置成功追加历史，HistoryRule 复用检测）
-- 数据库: DuckDB
-- 幂等性: CREATE TABLE/INDEX 使用 IF NOT EXISTS
--
-- 用途：记录每个用户的历史密码 hash（Argon2id 等 PasswordHasher 产物），
-- 供 account-policy 的 HistoryRule 在密码修改/找回流程中拒绝重用最近 N 条。

-- UP:

CREATE TABLE IF NOT EXISTS app_password_history (
    id            VARCHAR     NOT NULL PRIMARY KEY,           -- UUID v4
    tenant_id     BIGINT      NOT NULL,                       -- 租户 ID（i64）
    user_id       VARCHAR     NOT NULL,                       -- 用户 ID（login_id）
    password_hash TEXT        NOT NULL,                       -- 历史 hash（PHC 字符串）
    created_at    BIGINT      NOT NULL                        -- 创建时间（epoch seconds）
);

CREATE INDEX IF NOT EXISTS idx_app_password_history_user
    ON app_password_history (tenant_id, user_id, created_at);

-- DOWN:
DROP INDEX IF EXISTS idx_app_password_history_user;
DROP TABLE IF EXISTS app_password_history;
