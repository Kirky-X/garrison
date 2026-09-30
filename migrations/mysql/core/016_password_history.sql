-- Copyright (c) 2026 Kirky.X🌠
-- SPDX-License-Identifier: Apache-2.0

-- Migration: 密码历史表
-- 对应 spec: account/password-reset（重置成功追加历史，HistoryRule 复用检测）
-- 数据库: MySQL 8.0+
-- 幂等性: dbnexus 迁移器按版本号一次性应用（dbnexus_migrations 历史表去重），
--         普通 DDL 即可——MySQL 8 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属，
--         011 同款教训：真实 MySQL E2E 曾因该语法炸 1064），故此处不带。
--
-- 用途：记录每个用户的历史密码 hash（Argon2id 等 PasswordHasher 产物），
-- 供 account-policy 的 HistoryRule 在密码修改/找回流程中拒绝重用最近 N 条。

-- UP:

CREATE TABLE IF NOT EXISTS app_password_history (
    id            VARCHAR(64)  NOT NULL PRIMARY KEY,          -- UUID v4
    tenant_id     BIGINT       NOT NULL,                      -- 租户 ID（i64）
    user_id       VARCHAR(255) NOT NULL,                      -- 用户 ID（login_id）
    password_hash TEXT         NOT NULL,                      -- 历史 hash（PHC 字符串）
    created_at    BIGINT       NOT NULL                       -- 创建时间（epoch seconds）
);

CREATE INDEX idx_app_password_history_user
    ON app_password_history (tenant_id, user_id, created_at);

-- DOWN:
DROP INDEX idx_app_password_history_user ON app_password_history;
DROP TABLE IF EXISTS app_password_history;
