-- Copyright (c) 2026 Kirky.X🌠
-- SPDX-License-Identifier: Apache-2.0

-- Migration: garrison_kv — SQL 持久化 KV（MySQL 版本）
-- 对应实现: src/dao/dbnexus_kv.rs（DbnexusKvDao）
-- 用途: garrison-cli change-key / check-key 的字段加密数据寻址（敏感命名空间密文行）
-- 语义: expire_at 为 UTC unix 秒（BIGINT），NULL = 永久；过期行由 DAO 读路径视为不存在并惰性清理
-- 说明: MySQL 的 TEXT 列不可作 PRIMARY KEY（无前缀长度），键列用 VARCHAR(255)
-- 幂等性: CREATE TABLE 使用 IF NOT EXISTS

-- UP:

CREATE TABLE IF NOT EXISTS garrison_kv (
    k         VARCHAR(255) NOT NULL PRIMARY KEY,
    v         TEXT         NOT NULL,
    expire_at BIGINT
);

-- DOWN:

DROP TABLE IF EXISTS garrison_kv;
