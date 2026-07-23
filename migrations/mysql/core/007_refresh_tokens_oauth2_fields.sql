-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: refresh_tokens 表扩展 OAuth2 字段（MySQL 版本，v0.7.1 字段补齐）
-- 对应 change: v0.7.1-refresh-token-unification
-- 数据库: MySQL 8.0+
-- 幂等性: MySQL 8.0 不支持 ALTER TABLE ADD COLUMN IF NOT EXISTS，
--         重复执行会报错。dbnexus_migrations 历史表保证只执行一次（与 003 一致）。
--
-- 用途：为 refresh_tokens 表添加 OAuth2 扩展字段。
-- 注意：003_refresh_tokens.sql 创建的是不含 OAuth2 字段的基础表，新旧安装都
--       必须执行本迁移（007）补齐 client_id/scopes/username/user_id 字段。
--
-- 新字段：
--   client_id VARCHAR(255) -- OAuth2 客户端 ID（JWT 模块不使用，与 login_id VARCHAR(36) 对齐但放宽长度）
--   scopes    TEXT         -- OAuth2 scope 列表（空格分隔，长度可变）
--   username  VARCHAR(255) -- OAuth2 password grant type 用户名
--   user_id   BIGINT       -- OAuth2 user_id（client_credentials 时为 NULL，与 tenant_id 同类型）
--
-- 方言说明：MySQL 8.0 的 CREATE INDEX 不支持 IF NOT EXISTS（与 003_refresh_tokens.sql 一致），
-- 重复执行会报错。dbnexus_migrations 历史表保证只执行一次。

-- UP:

ALTER TABLE refresh_tokens ADD COLUMN client_id VARCHAR(255);
ALTER TABLE refresh_tokens ADD COLUMN scopes TEXT;
ALTER TABLE refresh_tokens ADD COLUMN username VARCHAR(255);
ALTER TABLE refresh_tokens ADD COLUMN user_id BIGINT;

-- v0.7.1 新增索引：按 client_id 查询（OAuth2 客户端维度审计）
CREATE INDEX idx_refresh_client
    ON refresh_tokens (client_id);

-- DOWN:
-- MySQL 8.0 支持 DROP COLUMN（无需 IF EXISTS，靠 dbnexus_migrations 保证单次）。
-- ALTER TABLE refresh_tokens DROP COLUMN client_id;
-- ALTER TABLE refresh_tokens DROP COLUMN scopes;
-- ALTER TABLE refresh_tokens DROP COLUMN username;
-- ALTER TABLE refresh_tokens DROP COLUMN user_id;
-- DROP INDEX idx_refresh_client ON refresh_tokens;
