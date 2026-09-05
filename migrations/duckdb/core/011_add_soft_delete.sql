-- Migration: 为 3 张核心表添加逻辑删除字段
-- 对应 spec: fix-codebase-review-violations (T009)
-- 数据库: DuckDB
-- 幂等性: DuckDB 支持 ALTER TABLE ADD COLUMN IF NOT EXISTS

-- UP:

-- 1. app_user: 添加 is_deleted 字段
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS is_deleted BIGINT NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
CREATE INDEX IF NOT EXISTS idx_app_user_is_deleted ON app_user (is_deleted);

-- 2. app_role: 添加 is_deleted 字段
ALTER TABLE app_role ADD COLUMN IF NOT EXISTS is_deleted BIGINT NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
CREATE INDEX IF NOT EXISTS idx_app_role_is_deleted ON app_role (is_deleted);

-- 3. app_permission: 添加 is_deleted 字段
ALTER TABLE app_permission ADD COLUMN IF NOT EXISTS is_deleted BIGINT NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
CREATE INDEX IF NOT EXISTS idx_app_permission_is_deleted ON app_permission (is_deleted);

-- DOWN:
DROP INDEX IF EXISTS idx_app_permission_is_deleted;
ALTER TABLE app_permission DROP COLUMN IF EXISTS is_deleted;

DROP INDEX IF EXISTS idx_app_role_is_deleted;
ALTER TABLE app_role DROP COLUMN IF EXISTS is_deleted;

DROP INDEX IF EXISTS idx_app_user_is_deleted;
ALTER TABLE app_user DROP COLUMN IF EXISTS is_deleted;
