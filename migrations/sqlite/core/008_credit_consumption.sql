-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: Credit 消费流水表（credit-metering feature）
-- 对应 spec: multi-tenant-credit-metering（多租户配额计量）
-- 数据库: SQLite
-- 幂等性: CREATE TABLE 使用 IF NOT EXISTS
--
-- 用途：记录每个租户的 credit 消费明细（冷数据，异步写入）。
-- CreditMeter::consume_credit() 在 KV 热路径完成后 tokio::spawn 写入此表。
-- CreditMeter::get_usage_history() 读取此表返回历史流水。

-- UP:

CREATE TABLE IF NOT EXISTS credit_consumption (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id        INTEGER NOT NULL DEFAULT 0,
    resource         TEXT    NOT NULL,
    cost             INTEGER NOT NULL,
    credits          INTEGER NOT NULL,
    total_consumed   INTEGER NOT NULL,
    cycle_start      INTEGER NOT NULL,
    created_at       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credit_consumption_tenant_cycle
    ON credit_consumption (tenant_id, cycle_start);

CREATE INDEX IF NOT EXISTS idx_credit_consumption_tenant_created
    ON credit_consumption (tenant_id, created_at);

-- DOWN:

DROP INDEX IF EXISTS idx_credit_consumption_tenant_created;
DROP INDEX IF EXISTS idx_credit_consumption_tenant_cycle;
DROP TABLE IF EXISTS credit_consumption;
