-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: 用户设备表（MySQL 版本）
-- 对应 spec: repository-layer（UserDeviceRepository trait）
-- 数据库: MySQL 8.0+
-- 幂等性: CREATE TABLE/INDEX 使用 IF NOT EXISTS；MySQL 不支持 CREATE INDEX IF NOT EXISTS，故省略
--
-- 用途：存储用户登录设备指纹与 UA 信息，支持设备阻断与多设备管理（MAX_DEVICES）。
-- register_device 读取此表实现"幂等注册 + 超限拒绝"语义。
-- UNIQUE(tenant_id, login_id, device_identifier) 保证同一用户下同一设备指纹仅一条记录。
--
-- 注意：时间字段用 BIGINT（epoch seconds），
-- 不同于 001_init.sql 中其他表使用的 VARCHAR(30)（CURRENT_TIMESTAMP）。

-- UP:

CREATE TABLE IF NOT EXISTS app_user_device (
    id                VARCHAR(36) PRIMARY KEY,                                  -- UUID v4
    tenant_id         BIGINT  NOT NULL,                                    -- 租户 ID（i64）
    login_id          VARCHAR(36) NOT NULL,                                    -- 登录 ID（String）
    device_identifier VARCHAR(255) NOT NULL,                                    -- UA hash 或设备指纹
    device_name       TEXT,                                                -- 从 UA 解析的设备名
    user_agent        TEXT,                                                -- 原始 User-Agent
    is_blocked        BIGINT  NOT NULL DEFAULT 0,                         -- 0=未阻断, 1=已阻断
    last_seen_at      BIGINT,                                             -- 最后活跃时间（epoch seconds，可空）
    created_at        BIGINT  NOT NULL,                                    -- 创建时间（epoch seconds）
    UNIQUE(tenant_id, login_id, device_identifier)
);

CREATE INDEX idx_app_user_device_tenant_login
    ON app_user_device (tenant_id, login_id);

CREATE INDEX idx_app_user_device_tenant
    ON app_user_device (tenant_id);

-- DOWN:

DROP TABLE IF EXISTS app_user_device;
