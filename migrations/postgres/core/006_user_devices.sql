-- Migration: 用户设备表（PostgreSQL 版本，v0.5.1 新增，依据 design.md D4 / M2 UserDevice）
-- 对应 spec: repository-layer（UserDeviceRepository trait）
-- 数据库: PostgreSQL
-- 幂等性: CREATE TABLE/INDEX 使用 IF NOT EXISTS
--
-- 用途：存储用户登录设备指纹与 UA 信息，支持设备阻断与多设备管理（MAX_DEVICES）。
-- register_device 读取此表实现"幂等注册 + 超限拒绝"语义。
-- UNIQUE(tenant_id, login_id, device_identifier) 保证同一用户下同一设备指纹仅一条记录。
--
-- 注意：时间字段用 BIGINT（epoch seconds），与 design.md D4 schema 一致，
-- 不同于 001_init.sql 中其他表使用的 TEXT（CURRENT_TIMESTAMP）。

-- UP:

CREATE TABLE IF NOT EXISTS app_user_device (
    id                TEXT    PRIMARY KEY,                                  -- UUID v4
    tenant_id         BIGINT  NOT NULL,                                    -- 租户 ID（i64）
    login_id          BIGINT  NOT NULL,                                    -- 登录 ID（i64）
    device_identifier TEXT    NOT NULL,                                    -- UA hash 或设备指纹
    device_name       TEXT,                                                -- 从 UA 解析的设备名
    user_agent        TEXT,                                                -- 原始 User-Agent
    is_blocked        BIGINT  NOT NULL DEFAULT 0,                         -- 0=未阻断, 1=已阻断
    last_seen_at      BIGINT,                                             -- 最后活跃时间（epoch seconds，可空）
    created_at        BIGINT  NOT NULL,                                    -- 创建时间（epoch seconds）
    UNIQUE(tenant_id, login_id, device_identifier)
);

CREATE INDEX IF NOT EXISTS idx_app_user_device_tenant_login
    ON app_user_device (tenant_id, login_id);

CREATE INDEX IF NOT EXISTS idx_app_user_device_tenant
    ON app_user_device (tenant_id);

-- DOWN:

DROP INDEX IF EXISTS idx_app_user_device_tenant;
DROP INDEX IF EXISTS idx_app_user_device_tenant_login;
DROP TABLE IF EXISTS app_user_device;
