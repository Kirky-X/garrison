-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: Credit 消费流水表（MySQL 版本，credit-metering feature）
-- 对应 spec: multi-tenant-credit-metering（多租户配额计量）
-- 数据库: MySQL 8.0+
-- 幂等性: CREATE TABLE 使用 IF NOT EXISTS
--
-- 用途：记录每个租户的 credit 消费明细（冷数据，异步写入）。
-- CreditMeter::consume_credit() 在 KV 热路径完成后 tokio::spawn 写入此表。
-- CreditMeter::get_usage_history() 读取此表返回历史流水。

-- UP:

CREATE TABLE IF NOT EXISTS credit_consumption (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id        BIGINT  NOT NULL DEFAULT 0,
    resource         VARCHAR(100) NOT NULL,
    cost             BIGINT  NOT NULL,
    credits          BIGINT  NOT NULL,
    total_consumed   BIGINT  NOT NULL,
    cycle_start      BIGINT  NOT NULL,
    created_at       BIGINT  NOT NULL
);

CREATE INDEX idx_credit_consumption_tenant_cycle
    ON credit_consumption (tenant_id, cycle_start);

CREATE INDEX idx_credit_consumption_tenant_created
    ON credit_consumption (tenant_id, created_at);

-- DOWN:

DROP TABLE IF EXISTS credit_consumption;
