-- Copyright (c) 2026 Kirky.X. All rights reserved.
-- See LICENSE for full license text.

-- Migration: 社交账号绑定表（MySQL 版本，v0.5.0 新增，依据 proposal H2 / spec social-login R-social-login-004）
-- 对应 spec: social-login（社交登录账号绑定）
-- 数据库: MySQL 8.0+
-- 幂等性: CREATE TABLE 使用 IF NOT EXISTS；MySQL 不支持 CREATE INDEX IF NOT EXISTS，故省略
--
-- 用途：存储 login_id 与第三方社交账号（微信/支付宝）的绑定关系。
-- SocialBindingService.find_or_create() 读取此表实现"首次登录自动创建绑定"语义。
-- UNIQUE(tenant_id, provider, provider_user_id) 保证同一租户下同一社交账号仅绑定一个 login_id。

-- UP:

CREATE TABLE IF NOT EXISTS social_bindings (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id        BIGINT  NOT NULL DEFAULT 0,
    login_id         VARCHAR(36) NOT NULL,
    provider         VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    union_id         VARCHAR(255),
    created_at       BIGINT  NOT NULL,
    UNIQUE(tenant_id, provider, provider_user_id)
);

CREATE INDEX idx_social_bindings_tenant_provider
    ON social_bindings (tenant_id, provider);

CREATE INDEX idx_social_bindings_login_id
    ON social_bindings (login_id);

-- DOWN:

DROP TABLE IF EXISTS social_bindings;
