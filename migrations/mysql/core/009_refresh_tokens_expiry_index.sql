-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: refresh_tokens 过期索引（MySQL 版本）
-- 对应 change: migration-schema-optimization
-- 数据库: MySQL 8.0+
-- 幂等性: 依赖 dbnexus_migrations 历史表保证单次执行
--
-- 用途：为 refresh_tokens.expires_at 添加索引，支持按过期时间范围查询
-- （cleanup_expired 批量删除已撤销且过期的 token 记录）。

-- UP:

CREATE INDEX idx_refresh_expires_at
    ON refresh_tokens (expires_at);

-- DOWN:

DROP INDEX idx_refresh_expires_at ON refresh_tokens;
