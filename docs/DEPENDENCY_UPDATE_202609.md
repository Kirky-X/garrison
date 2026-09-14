# 依赖升级与自研库特性吸收方案（2026-09）

依据 `cargo outdated` 全量更新；自研库取最新 rc，第三方仅稳定版，全部经
crates.io（开发期缺陷修复使用 `[patch.crates-io]` 本地源码，见下文）。

## 一、版本更新

### 自研库（rc 允许）

| 库 | 旧 → 新 | rc.2→rc.4/rc.5 规模 | 与 garrison 相关的要点 |
| --- | --- | --- | --- |
| confers | 0.6.0-rc.2 → 0.6.0-rc.4 | 65 提交 | lazy 惰性解析、OpenFeature 评估器、金丝雀发布、Vault/KMS/keyring |
| oxcache | 0.5.0-rc.2 → 0.5.0-rc.4 | 57 提交 | invalidation 键空间失效、red-lock、versioning CAS、热路径零分配、bincode 2.0（RUSTSEC-2025-0141 处置） |
| dbnexus | 0.6.0-rc.2 → 0.6.0-rc.4 | 677 提交 | BanTarget::Cidr 网段封禁、UnifiedDbError、PermissionFacade、prepare 缓存、实体事件 Outbox |
| inklog | 0.3.0-rc.2 → 0.3.0-rc.4 | 74 提交 | 审计事件 HMAC 防篡改链、Sink 中间件链、net-sink、OTLP 导出、采样器 |
| limiteron | 0.3.0-rc.2 → 0.3.0-rc.4 | 59 提交 | **AIMD 自适应限流真实现**、ban-sync 跨实例封禁同步、HTB 分层令牌桶、舱壁隔离、Webhook HMAC |
| sdforge | 0.5.0-rc.2 → 0.5.0-rc.4 | 53 提交 | on_start/on_stop 生命周期钩子、gRPC 拦截器 + WS 握手认证、otel、统一错误契约 |
| trait-kit | 0.5.0-rc.2 → 0.5.0-rc.5 | 53 提交 | 能力版本协商（negotiate）、KeyProvider port、子 Kit 组合、健康历史采样 |

### 第三方（仅稳定版）

| 库 | 旧 → 新 | 说明 |
| --- | --- | --- |
| maxminddb | 0.30 → 0.32 | 跨 minor 兼容；firewall-maxminddb 全特性面编译通过 |
| uuid / toml / reqwest 等 | lockfile 内更新至最新兼容版 | `cargo update` 全量刷新（actix-web 3.13.5、hyper 1.11.1 等 100+ 传递依赖） |

## 二、破坏性变更与适配

| 变更 | 适配 |
| --- | --- |
| limiteron `BanTarget` 新增 `Cidr` 网段封禁变体 | `src/limiteron/ban.rs` `target_to_key_fragment` 补 `cidr:{cidr}` 分支 |
| limiteron rc.4 `event-system` 未启用 `webhook` 时编译失败（发送块未门控 + 存根签名不匹配） | **修复上游源码**（limiteron 仓库 commit `801c96e`，发送路径按 feature 门控），garrison 经本地 patch 使用，见下文 |
| generic-array 0.14.9 弃用 `GenericArray::as_slice` | `src/protocol/sso/saml.rs` 常量时间比较改经 Deref：`ct_ne(&computed)` |

## 三、开发期本地 patch

```toml
[patch.crates-io]
limiteron = { path = "../limiteron" }
```

- 适用场景：自研库缺陷已在上游仓库修复但尚未发版。
- 退出条件：limiteron 发布含 `801c96e` 的 rc.5 后，删除该 patch 段恢复纯
  crates.io 来源，garrison 版本 req 升至 rc.5。
- 约束：patch 仅限开发期；发布 garrison 前必须移除（crates.io 发布禁止 patch）。

## 四、新特性吸收方案（kueiku：ICE 粗筛 18 项 → RICE 精排 Top10）

### 本次已落地（零代码 feature 转发）

| RICE | 新特性 | 吸收内容 |
| --- | --- | --- |
| #1（41） | `cache-invalidation` | 转发 `oxcache/invalidation`：多实例部署下 L1 缓存经 Redis 键空间通知自动失效 |
| #2（23） | `ban-sync` | 转发 `limiteron/ban-sync`：封禁记录经 oxcache Pub/Sub 跨实例同步（依赖 cache-invalidation） |

两者已纳入 `full` 聚合并登记 check-cfg。

### 排期建议（需代码接线）

| RICE | 特性 | 接线点 | 预估 |
| --- | --- | --- | --- |
| #3（22） | limiteron AIMD 自适应限流（rc.4 真实现，替代 0.2.10 时代的 no-op 回退） | `src/strategy/firewall/rate_limit.rs` 限流器选择 + `firewall-ddos` 门控 | 3 人日 |
| #4（12） | oxcache 热路径零分配 `get_by_str/set_by_str` | `src/dao/oxcache_impl.rs` 调用点替换 | 3 人日 |
| #5（10） | limiteron 舱壁隔离（按资源组分池） | firewall 资源组配置 | 2 人日 |
| #7（7） | sdforge `lifecycle`/`hooks`（on_start/on_stop） | auth_server 启停钩子 | 4 人日 |
| #8（6） | inklog 审计 HMAC 防篡改链 | `audit-inklog` 消费方启用链式签名 | 5 人日 |
| #9（5） | trait-kit KeyProvider + confers cloud-kms/keyring | JWT secret KMS 托管 | 6 人日 |

### 明确不吸收

- **dbnexus PermissionFacade**：与 garrison 自身权限引擎职责重叠，吸收会造成
  双决策引擎（ICE 得分最低 48）。
- **sdforge otel**：garrison 已有独立 `otlp` feature（opentelemetry 栈直连），
  叠加 sdforge otel 会产生双导出通道。
