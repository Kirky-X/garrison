-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: refresh_tokens 表扩展 OAuth2 字段（v0.7.1）
-- 对应 change: v0.7.1-refresh-token-unification
-- 数据库: SQLite
-- 幂等性: SQLite 不支持 ADD COLUMN IF NOT EXISTS，通过 PRAGMA 检查后执行
--
-- 用途：为 refresh_tokens 表添加 OAuth2 扩展字段。
-- 注意：003_refresh_tokens.sql 创建的是不含 OAuth2 字段的基础表，新旧安装都
--       必须执行本迁移（007）补齐 client_id/scopes/username/user_id 字段。
--
-- 新字段：
--   client_id TEXT    -- OAuth2 客户端 ID（JWT 模块不使用）
--   scopes    TEXT    -- OAuth2 scope 列表（空格分隔）
--   username  TEXT    -- OAuth2 password grant type 用户名
--   user_id   INTEGER -- OAuth2 user_id（client_credentials 时为 NULL）
--
-- 注意：SQLite ALTER TABLE ADD COLUMN 不支持 IF NOT EXISTS，
-- 重复执行会报错。dbnexus 迁移历史表（dbnexus_migrations）保证只执行一次。

-- UP:

ALTER TABLE refresh_tokens ADD COLUMN client_id TEXT;
ALTER TABLE refresh_tokens ADD COLUMN scopes TEXT;
ALTER TABLE refresh_tokens ADD COLUMN username TEXT;
ALTER TABLE refresh_tokens ADD COLUMN user_id INTEGER;

-- v0.7.1 新增索引：按 client_id 查询（OAuth2 客户端维度审计）
CREATE INDEX IF NOT EXISTS idx_refresh_client
    ON refresh_tokens (client_id);

-- DOWN:
-- SQLite 不支持 DROP COLUMN（除非重建表），DOWN 留空。
-- 如需回滚，需手动重建 refresh_tokens 表（仅保留旧字段）。
