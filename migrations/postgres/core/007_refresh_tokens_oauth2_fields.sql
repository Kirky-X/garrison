-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: refresh_tokens 表扩展 OAuth2 字段（PostgreSQL 版本，v0.7.1 字段补齐）
-- 对应 change: v0.7.1-refresh-token-unification
-- 数据库: PostgreSQL
-- 幂等性: ALTER TABLE ADD COLUMN IF NOT EXISTS + CREATE INDEX IF NOT EXISTS（PG 原生支持）
--
-- 用途：为已应用 003_refresh_tokens.sql 的旧 PostgreSQL 数据库添加 OAuth2 扩展字段。
-- 新安装的数据库由 003_refresh_tokens.sql 直接创建含新字段的表，跳过此迁移。
--
-- 新字段：
--   client_id TEXT    -- OAuth2 客户端 ID（JWT 模块不使用）
--   scopes    TEXT    -- OAuth2 scope 列表（空格分隔）
--   username  TEXT    -- OAuth2 password grant type 用户名
--   user_id   BIGINT  -- OAuth2 user_id（client_credentials 时为 NULL，与 tenant_id 同类型）
--
-- 方言说明：PostgreSQL 支持 ADD COLUMN IF NOT EXISTS 与 CREATE INDEX IF NOT EXISTS，
-- 重复执行幂等（不报错）。dbnexus_migrations 历史表额外保证只执行一次。

-- UP:

ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS client_id TEXT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS scopes TEXT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS user_id BIGINT;

-- v0.7.1 新增索引：按 client_id 查询（OAuth2 客户端维度审计）
CREATE INDEX IF NOT EXISTS idx_refresh_client
    ON refresh_tokens (client_id);

-- DOWN:
-- PostgreSQL 支持 DROP COLUMN IF EXISTS，可回滚（与 SQLite 不同）。
-- ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS client_id;
-- ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS scopes;
-- ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS username;
-- ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS user_id;
-- DROP INDEX IF EXISTS idx_refresh_client;
