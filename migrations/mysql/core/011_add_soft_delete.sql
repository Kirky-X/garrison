-- Migration: 为 3 张核心表添加逻辑删除字段
-- 对应 spec: fix-codebase-review-violations (T009)
-- 数据库: MySQL 8.0+
-- 字符集: utf8mb4（001_init 建表即继承 MySQL 8.0 服务器默认 utf8mb4，无需 CONVERT）
-- 幂等性: dbnexus 迁移器按版本号一次性应用（dbnexus_migrations 历史表去重），
--   普通 DDL 即可；**禁止使用 DELIMITER/存储过程**——迁移经 sqlx 多语句批量
--   执行（execute_unprepared），`DELIMITER` 是 mysql CLI 客户端指令而非 SQL，
--   服务端解析直接报 1064（2026-09-09 E2E 套件 acceptance_db_mysql 首次真实
--   执行暴露；历史 CLI-only 语义无法覆盖运行时迁移路径）。
--   注：本文件此前从未通过 dbnexus 成功应用，故直接原地修正内容（版本号不变）。

-- UP:
ALTER TABLE app_user ADD COLUMN is_deleted BIGINT NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
ALTER TABLE app_role ADD COLUMN is_deleted BIGINT NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));
ALTER TABLE app_permission ADD COLUMN is_deleted BIGINT NOT NULL DEFAULT 0 CHECK (is_deleted IN (0, 1));

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
