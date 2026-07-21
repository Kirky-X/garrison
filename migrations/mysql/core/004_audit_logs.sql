-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: 审计日志表（MySQL 版本，v0.5.0 新增，依据 proposal H3）
-- 对应 spec: audit-log（AuditLogListener 持久化事件）
-- 数据库: MySQL 8.0+
-- 幂等性: CREATE TABLE 使用 IF NOT EXISTS；MySQL 不支持 CREATE INDEX IF NOT EXISTS，故省略
--
-- 用途：存储 GarrisonEvent 持久化记录，支持字段掩码与按 tenant/event_type/时间范围查询。
-- AuditLogListener.on_event 将事件转换为 AuditEntry 并 INSERT 到此表。

-- UP:

CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id   BIGINT  NOT NULL DEFAULT 0,   -- 租户 ID（i64，0=默认租户）
    event_type  VARCHAR(100) NOT NULL,          -- 事件类型（如 "login"/"logout"/"kickout"）
    login_id    VARCHAR(36),                    -- 登录主体 ID（可为 NULL，如 TokenExpired 无 login_id）
    token       TEXT,                           -- 关联 token（可为 NULL）
    ip          TEXT,                           -- 客户端 IP（可为 NULL）
    user_agent  TEXT,                           -- 客户端 User-Agent（可为 NULL）
    metadata    TEXT,                           -- 事件元数据 JSON（已掩码敏感字段）
    success     BIGINT  NOT NULL,               -- 事件是否成功（0=失败，1=成功）
    created_at  BIGINT  NOT NULL                -- 创建时间（Unix 秒）
);

-- 查询索引：按租户 + 时间范围查询（审计日志常用查询模式）
CREATE INDEX idx_audit_tenant_time
    ON audit_logs (tenant_id, created_at);

-- 查询索引：按事件类型查询（如统计登录失败次数）
CREATE INDEX idx_audit_event_type
    ON audit_logs (event_type);

-- DOWN:

DROP TABLE IF EXISTS audit_logs;
