-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: refresh_tokens 过期索引（DuckDB 版本）
-- 对应 change: migration-schema-optimization
-- 数据库: DuckDB
-- 幂等性: CREATE INDEX IF NOT EXISTS
--
-- 用途：为 refresh_tokens.expires_at 添加索引，支持按过期时间范围查询
-- （cleanup_expired 批量删除已撤销且过期的 token 记录）。

-- UP:

CREATE INDEX IF NOT EXISTS idx_refresh_expires_at
    ON refresh_tokens (expires_at);

-- DOWN:

DROP INDEX IF EXISTS idx_refresh_expires_at;
