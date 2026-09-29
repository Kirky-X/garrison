-- Migration: OIDC Back-Channel Logout 持久化投递队列 oauth2_backchannel_queue
-- 对应 spec: p1p2-absorption（logout token 持久化投递/重试计数/超时退役）
-- 数据库: SQLite 3.35+
-- 幂等性: CREATE TABLE/INDEX 使用 IF NOT EXISTS

-- UP:

CREATE TABLE IF NOT EXISTS oauth2_backchannel_queue (
    id VARCHAR(64) NOT NULL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    logout_token TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    pending_retries INTEGER NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    next_attempt_at BIGINT NOT NULL,
    max_ttl_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth2_backchannel_queue_status
    ON oauth2_backchannel_queue (status, next_attempt_at);

-- DOWN:
DROP INDEX IF EXISTS idx_oauth2_backchannel_queue_status;
DROP TABLE IF EXISTS oauth2_backchannel_queue;
