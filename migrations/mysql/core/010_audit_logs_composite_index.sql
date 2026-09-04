-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: 审计日志三列覆盖索引（MySQL 版本）
-- 对应 change: migration-schema-optimization
-- 数据库: MySQL 8.0+
-- 幂等性: 依赖 dbnexus_migrations 历史表保证单次执行
--
-- 用途：替换原有两个单列/双列索引为三列覆盖索引，
-- 优化 query_audit_logs 的常用查询模式：
-- WHERE tenant_id = ? AND event_type = ? AND created_at BETWEEN ? AND ?
--
-- 变更：
-- - 删除 idx_audit_tenant_time (tenant_id, created_at)
-- - 删除 idx_audit_event_type (event_type)
-- - 创建 idx_audit_tenant_event_time (tenant_id, event_type, created_at)

-- UP:

DROP INDEX idx_audit_tenant_time ON audit_logs;
DROP INDEX idx_audit_event_type ON audit_logs;

CREATE INDEX idx_audit_tenant_event_time
    ON audit_logs (tenant_id, event_type, created_at);

-- DOWN:

DROP INDEX idx_audit_tenant_event_time ON audit_logs;

CREATE INDEX idx_audit_tenant_time
    ON audit_logs (tenant_id, created_at);
CREATE INDEX idx_audit_event_type
    ON audit_logs (event_type);
