-- Migration: 为 3 张核心表添加逻辑删除字段
-- 对应 spec: fix-codebase-review-violations (T009)
-- 数据库: SQLite 3.35+
-- 幂等性: SQLite 不支持 IF NOT EXISTS for ADD COLUMN，但重复添加会报错；
--         使用条件判断不适用 SQLite，依赖迁移框架保证只执行一次。

-- UP:

-- 1. app_user: 添加 is_deleted 字段
ALTER TABLE app_user ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
CREATE INDEX IF NOT EXISTS idx_app_user_is_deleted ON app_user (is_deleted);

-- 2. app_role: 添加 is_deleted 字段
ALTER TABLE app_role ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
CREATE INDEX IF NOT EXISTS idx_app_role_is_deleted ON app_role (is_deleted);

-- 3. app_permission: 添加 is_deleted 字段
ALTER TABLE app_permission ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
CREATE INDEX IF NOT EXISTS idx_app_permission_is_deleted ON app_permission (is_deleted);

-- DOWN:
-- SQLite 不支持 DROP COLUMN（3.35.0 以前），需要重建表。
-- 此处使用 3.35.0+ 的 ALTER TABLE DROP COLUMN。
DROP INDEX IF EXISTS idx_app_permission_is_deleted;
ALTER TABLE app_permission DROP COLUMN is_deleted;

DROP INDEX IF EXISTS idx_app_role_is_deleted;
ALTER TABLE app_role DROP COLUMN is_deleted;

DROP INDEX IF EXISTS idx_app_user_is_deleted;
ALTER TABLE app_user DROP COLUMN is_deleted;
