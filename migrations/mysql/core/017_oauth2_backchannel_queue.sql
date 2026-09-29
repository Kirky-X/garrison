-- Migration: OIDC Back-Channel Logout 持久化投递队列 oauth2_backchannel_queue
-- 对应 spec: p1p2-absorption（logout token 持久化投递/重试计数/超时退役）
-- 数据库: MySQL 8.0+
-- 幂等性: dbnexus 迁移器按版本号一次性应用（dbnexus_migrations 历史表去重），
--         普通 DDL 即可——MySQL 8 不支持 CREATE INDEX IF NOT EXISTS（MariaDB 专属，
--         011 同款教训：真实 MySQL E2E 曾因该语法炸 1064），故此处不带。

-- UP:

CREATE TABLE IF NOT EXISTS oauth2_backchannel_queue (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    logout_token TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    pending_retries BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    next_attempt_at BIGINT NOT NULL,
    max_ttl_at BIGINT NOT NULL
);

CREATE INDEX idx_oauth2_backchannel_queue_status
    ON oauth2_backchannel_queue (status, next_attempt_at);

-- DOWN:
DROP INDEX idx_oauth2_backchannel_queue_status ON oauth2_backchannel_queue;
DROP TABLE IF EXISTS oauth2_backchannel_queue;
