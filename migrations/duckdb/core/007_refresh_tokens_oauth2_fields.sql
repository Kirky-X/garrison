-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: refresh_tokens 表扩展 OAuth2 字段（v0.7.1）
-- 对应 change: v0.7.1-refresh-token-unification
-- 数据库: DuckDB
-- 幂等性: DuckDB 支持 ALTER TABLE ADD COLUMN IF NOT EXISTS
--
-- 用途：为 refresh_tokens 表添加 OAuth2 扩展字段。
-- 注意：003_refresh_tokens.sql 创建的是不含 OAuth2 字段的基础表，新旧安装都
--       必须执行本迁移（007）补齐 client_id/scopes/username/user_id 字段。
--
-- 新字段：
--   client_id TEXT    -- OAuth2 客户端 ID（JWT 模块不使用）
--   scopes    TEXT    -- OAuth2 scope 列表（空格分隔）
--   username  TEXT    -- OAuth2 password grant type 用户名
--   user_id   BIGINT  -- OAuth2 user_id（client_credentials 时为 NULL）

-- UP:

ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS client_id TEXT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS scopes TEXT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS username TEXT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS user_id BIGINT;

-- v0.7.1 新增索引：按 client_id 查询（OAuth2 客户端维度审计）
CREATE INDEX IF NOT EXISTS idx_refresh_client
    ON refresh_tokens (client_id);

-- DOWN:
-- DuckDB 支持 ALTER TABLE DROP COLUMN，但 dbnexus 迁移历史表保证
-- UP 只执行一次，DOWN 仅在显式回滚时触发。
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS user_id;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS username;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS scopes;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS client_id;
