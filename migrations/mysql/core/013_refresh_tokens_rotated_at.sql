-- Copyright (c) 2026 Kirky.X🌠
-- SPDX-License-Identifier: Apache-2.0

-- Migration: refresh_tokens 表增 rotated_at 列（重用分级与宽限窗口）
-- 数据库: MySQL 8.0+
-- 幂等性: MySQL 8 不支持 ADD COLUMN IF NOT EXISTS，dbnexus_migrations 历史表保证只执行一次
--
-- 用途：记录 refresh token 被轮换消费（revoked 0→1）的 Unix 秒时刻。
-- RefreshTokenRotation 在原子消费（compare-and-swap）时写入：
--   - 重用三级分类与宽限窗口以 rotated_at 判定「是否处于宽限窗口内」；
--   - 旋转失败补偿将该列连同 revoked 一并回退（NULL / 0）；
--   - 首次签发（issue）与 rotate 产生的新记录该列为 NULL（从未被轮换消费）。
-- 存量行由 ALTER TABLE 填 NULL，语义即「迁移前未记录消费时刻」，不参与宽限判定。

-- UP:

ALTER TABLE refresh_tokens ADD COLUMN rotated_at BIGINT;

-- DOWN:
ALTER TABLE refresh_tokens DROP COLUMN rotated_at;
