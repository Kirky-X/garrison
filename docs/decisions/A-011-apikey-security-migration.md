# A-011: API Key 安全退化修复（nebulaid → garrison 迁移）

- **状态**：已采纳（v0.7.x 实现）
- **决策日期**：2026-07-23
- **相关变更**：apikey-security-migration
- **相关代码**：`src/protocol/apikey/handler.rs` / `src/protocol/apikey/mod.rs` / `src/dao/mod.rs`（inline `oxcache_impl`）/ `src/stp/context.rs` / `src/stp/default_impl.rs` / `src/strategy/firewall/brute_force.rs`

## 背景

nebulaid（PostgreSQL + Argon2）全量迁移到 garrison 的 KV 型 `ApiKeyHandler` 后，安全审计发现 7 项退化：明文存储（CWE-916）、持久化退化、多租户隔离退化（IDOR）、IP 级失败限速丢失（CWE-307）、凭证格式降级、权限控制退化、密钥管理能力丢失。本 ADR 记录修复决策与关键权衡。

## 决策

### 1. 哈希算法：SHA-256 而非 Argon2（Decision Matrix）

API Key 由两个 UUIDv4 拼接（244-bit 高熵随机值），采用**确定性 `sha256(key_secret)` + `subtle::ConstantTimeEq` 常量时间比较**存储，而非 nebulaid 的 Argon2id。

理由：

- Argon2 随机盐 → 输出非确定性 → 无法作 KV 查找 key → verify 退回 O(N) 全表扫描（重现被 E4 修复的 DoS）。
- Argon2 每次 verify ~10-50ms，每请求校验成性能瓶颈，而对高熵 token 无抗暴力增益。
- SHA-256 确定性 + 高熵，密码学上足够，保持 O(1) 查询。

**前提不变量**：`key_secret` 必须是生成期锁定的高熵随机值（当前为 UUIDv4 simple，128-bit）。若未来改为低熵/用户可选 secret，快速哈希将变得可暴力破解，届时必须改用 Argon2 并接受 O(N) 或额外维护 `key_id→salt` 映射。

### 2. 凭证格式：`key_id.key_secret` 双段

对外返回 `key_id.key_secret`（各 32 hex，`.` 分隔）。`key_id` 作存储 key 后缀（`garrison:apikey:<ns>:<key_id>`）与反向索引，可安全记录到日志；`key_secret` 仅生成时返回一次，存储侧只有其哈希。一次性同时修复 CWE-916（无明文 secret）与凭证格式降级（审计对等 nebulaid 的 `key_id:key_secret`）。

### 3. `keys()` 生产可用：`dao-key-index` feature

将 `GarrisonDaoOxcache` 的 key 索引机制从 `anomalous-detector-dual` gate 泛化为独立内部 feature `dao-key-index`，由 `protocol-apikey` 与 `anomalous-detector-dual` 共同传递启用。使 `ApiKeyHandler::list_by_namespace` / `get_keys_older_than` 在生产（启用 protocol-apikey）默认可用，不再返回 `NotImplemented`。

> 注意：真正编译的 oxcache 实现是 `src/dao/mod.rs` 内的 inline `mod oxcache_impl { ... }`（L538+），而非同名孤立文件 `src/dao/oxcache_impl.rs`（后者为历史"迁移"遗留、未被 `mod` 声明引用、不参与编译）。本次修复作用于 inline 实现。

### 4. IP 级失败限速：复用 `BruteForceStrategy` + `CURRENT_IP` task_local

新增 `CURRENT_IP` task_local（仿 `CURRENT_TOKEN`）由 Web middleware 用 `extract_client_ip`（已含 trusted_proxies 防 XFF 伪造）注入；为 `BruteForceStrategy` 增加 `is_blocked`（只读、不计数）与 `record_failure`（仅失败计数、超阈值封禁）两方法；`check_api_key` 校验前短路已封禁 IP，仅在校验失败时计数（成功零写入）。整段 `firewall-bruteforce` 门控，无 IP 上下文时 fail-open 兼容。

### 5. 多租户隔离（IDOR）

以既有 `verify_with_namespace` 的 namespace 归属校验为核心（namespace A 的 key 无法在 B 通过）+ `tenant-isolation` 的 DAO 层物理前缀隔离 + 新增 `owner_id` 归属元数据（默认等于 `login_id`）。

## 已拒绝/推迟的备选

- **Argon2 直哈希 token**：拒绝（见决策 1）。
- **立即引入 dbnexus `app_api_key` 表作 DB-of-record**：推迟。修复持久化退化最彻底，但需新增迁移 + store trait + 缓存 read-through，改动面大、回归风险高，超出"安全退化外科式修复"范围。**本轮先以文档 + `cache-redis` AOF 配置缓解**（见 `docs/SECURITY.md` §8）；如有 ACID/外键硬需求，后续按本 ADR 扩展为独立 feature，并遵守 A-009（Redis/网络后端须弃 `_sync` 改 async）。
- **保持单一 token 仅加 SHA-256**：拒绝，无法修复凭证格式降级（无 `key_id` 审计能力）。

## 后续跟进

- 孤立文件 `src/dao/oxcache_impl.rs` 与 inline 实现重复且已发散，建议后续单独清理（转为 `mod oxcache_impl;` 引用文件并删除 inline，或删除孤立文件），本次未在安全修复范围内处理。
- DB-of-record 持久化如落地，另立 ADR。
