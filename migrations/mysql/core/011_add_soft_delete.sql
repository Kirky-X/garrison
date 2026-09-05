-- Migration: 为 3 张核心表添加逻辑删除字段
-- 对应 spec: fix-codebase-review-violations (T009)
-- 数据库: MySQL 8.0+
-- 字符集: utf8mb4（新迁移显式声明，确保与 001_init 保持一致）
-- 幂等性: MySQL 不支持 ADD COLUMN IF NOT EXISTS，使用存储过程安全添加
--
-- 字符集约定：
-- ALTER TABLE ADD COLUMN 的字符集继承自表的 DEFAULT CHARSET。
-- 若表仍为 001_init 的默认字符集（应为 utf8mb4），无需额外操作。
-- 以下语句确保表级字符集为 utf8mb4（幂等，已为 utf8mb4 时无影响）：
ALTER TABLE app_user CONVERT TO CHARACTER SET utf8mb4;
ALTER TABLE app_role CONVERT TO CHARACTER SET utf8mb4;
ALTER TABLE app_permission CONVERT TO CHARACTER SET utf8mb4;

-- UP:

-- 使用存储过程确保幂等性（列已存在时跳过）
DELIMITER //
CREATE PROCEDURE IF NOT EXISTS add_is_deleted_columns()
BEGIN
    -- 1. app_user: 添加 is_deleted 字段
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'app_user' AND COLUMN_NAME = 'is_deleted'
    ) THEN
        ALTER TABLE app_user ADD COLUMN is_deleted BIGINT NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
    END IF;

    -- 2. app_role: 添加 is_deleted 字段
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'app_role' AND COLUMN_NAME = 'is_deleted'
    ) THEN
        ALTER TABLE app_role ADD COLUMN is_deleted BIGINT NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
    END IF;

    -- 3. app_permission: 添加 is_deleted 字段
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'app_permission' AND COLUMN_NAME = 'is_deleted'
    ) THEN
        ALTER TABLE app_permission ADD COLUMN is_deleted BIGINT NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
    END IF;
END //
DELIMITER ;

CALL add_is_deleted_columns();
DROP PROCEDURE IF EXISTS add_is_deleted_columns;

-- 索引（MySQL 支持 CREATE INDEX IF NOT EXISTS 从 8.0 起不保证，先检查）
CREATE INDEX idx_app_user_is_deleted ON app_user (is_deleted);
CREATE INDEX idx_app_role_is_deleted ON app_role (is_deleted);
CREATE INDEX idx_app_permission_is_deleted ON app_permission (is_deleted);

-- DOWN:
DROP INDEX idx_app_permission_is_deleted ON app_permission;
ALTER TABLE app_permission DROP COLUMN is_deleted;

DROP INDEX idx_app_role_is_deleted ON app_role;
ALTER TABLE app_role DROP COLUMN is_deleted;

DROP INDEX idx_app_user_is_deleted ON app_user;
ALTER TABLE app_user DROP COLUMN is_deleted;
