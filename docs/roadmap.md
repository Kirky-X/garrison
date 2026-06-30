# Bulwark 项目路线图

本文件描述 Bulwark（Rust 认证授权框架，借鉴 Sa-Token v1.45.0 设计哲学）的版本演进规划与设计原则。

> 仓库：https://github.com/Kirky-X/bulwark
> License：Apache-2.0
> 作者：Kirky.X
> 变更管理：通过 OpenSpec 工作流进行 proposal → design → tasks → archive

> 架构设计详见 [architecture.md](./architecture.md)；开发规范详见 [development.md](./development.md)。

---

## 版本总览

| 版本 | 状态 | 计划完成 | 主要内容 |
|------|------|---------|---------|
| 0.1.0 | ✅ 已完成 | 2026-06-30 | 核心基础设施 |
| 0.2.0 | 🚧 规划中 | 2026 Q3 | 协议与安全层 |
| 0.3.0 | 📋 待规划 | 2026 Q4 | 多后端与可观测 |
| 0.4.0 | 📋 待规划 | 2027 Q1 | 高级特性 |
| 1.0.0 | 📋 待规划 | 2027 Q2 | 稳定版 |

---

## 详细版本规划

### v0.1.0 核心基础设施（已完成）

发布日期：2026-06-30

- ✅ 错误类型体系（`BulwarkError`）
- ✅ 配置系统（三级配置源 + `tokio::sync::watch` 热更新）
- ✅ 上下文抽象（`BulwarkContext` + axum adapter + task_local）
- ✅ DAO 抽象（`BulwarkDao` trait + oxcache + dbnexus）
- ✅ 双模会话管理（Account-Session + Token-Session）
- ✅ 核心 API（`BulwarkLogic` + `BulwarkUtil`）
- ✅ 权限校验策略（`BulwarkFirewallStrategy`）
- ✅ 全局管理器（`BulwarkManager` + inventory 编译期注册）
- ✅ axum 集成（extractor + `BulwarkRouter` + Interceptor）

**里程碑意义**：完成"能跑起来"的最小闭环，支持基于 UUID/Random64 Token 的登录、会话、权限校验与 axum 集成。可作为评估框架设计哲学的基线版本。

#### 已知限制（0.1.0）

- oxcache 0.3 `Cache<K,V>::update` 无法保留 per-entry TTL
- dbnexus 0.2 仅支持 SQLite（PostgreSQL/MySQL 待 0.2.0+）
- `BulwarkRouter::route_protected` 仅支持 GET 方法

---

### v0.2.0 协议与安全层（规划中）

计划完成：2026 Q3

#### 0.2.0 特性域状态表

Bulwark 借鉴 Sa-Token 的 13 个特性域设计，0.2.0 的推进状态如下：

| # | 特性域 | 模块 | Feature | 0.1.0 状态 | 0.2.0 状态 |
|---|--------|------|---------|-----------|------------|
| 1 | 登录认证 | `core/auth` | - | ✅ 已完成 | 🚧 完善 |
| 2 | 权限认证 | `core/permission` | - | ✅ 已完成 | 🚧 完善 |
| 3 | Session 会话 | `session` | - | ✅ 已完成 | 🚧 完善 |
| 4 | OAuth2 | `protocol/oauth2` | `protocol-oauth2` | ❌ 未开始 | 🚧 规划中 |
| 5 | 单点登录 (SSO) | `protocol/sso` | `protocol-sso` | ❌ 未开始 | 🚧 规划中 |
| 6 | JWT | `protocol/jwt` | `protocol-jwt` | ❌ 未开始 | 🚧 规划中 |
| 7 | 微服务网关鉴权 | `protocol/sign` | `protocol-sign` | ❌ 未开始 | 🚧 规划中 |
| 8 | API 接口鉴权 | `protocol/apikey` | `protocol-apikey` | ❌ 未开始 | 🚧 规划中 |
| 9 | 临时凭证 | `protocol/temp` | `protocol-temp` | ❌ 未开始 | 🚧 规划中 |
| 10 | TOTP 动态验证码 | `secure/totp` | `secure-totp` | ❌ 未开始 | 🚧 规划中 |
| 11 | Basic 认证 | `secure/httpbasic` | `secure-httpbasic` | ❌ 未开始 | 🚧 规划中 |
| 12 | Digest 认证 | `secure/httpdigest` | `secure-httpdigest` | ❌ 未开始 | 🚧 规划中 |
| 13 | 路由拦截鉴权 | `router` | `web-axum` | ✅ 已完成 | 🚧 完善 |

#### 协议层（protocol-*）

- 🚧 JWT 签发与验证（`protocol-jwt`）
- 🚧 OAuth2 三种模式（`protocol-oauth2`，授权码 / 密码 / 客户端凭证）
- 🚧 SSO 单点登录 ticket（`protocol-sso`）
- 🚧 API 签名 + nonce 防重放（`protocol-sign`）
- 🚧 API Key 认证（`protocol-apikey`）
- 🚧 临时凭证（`protocol-temp`）

#### 安全层（secure-*）

- 🚧 TOTP 动态验证码（`secure-totp`，RFC 6238）
- 🚧 HMAC 签名工具（`secure-sign`）
- 🚧 HTTP Basic 认证（`secure-httpbasic`）
- 🚧 HTTP Digest 认证（`secure-httpdigest`）

#### 核心扩展

- 🚧 `core/auth` / `core/permission` / `core/token` 抽象完善
- 🚧 异常系统 + JSON 模板 + 插件系统 + 监听器
- 🚧 新增配置字段：`jwt_algorithm`、`sign_window_seconds`、`sso_ticket_ttl_seconds`

**里程碑意义**：覆盖 Sa-Token 13 个特性域中的大部分协议与安全子域，Bulwark 从"可用"走向"完整"。

---

### v0.3.0 多后端与可观测（待规划）

计划完成：2026 Q4

- 📋 PostgreSQL 后端（待 `dbnexus` 0.3+ 提供 PG 后端）
- 📋 MySQL 后端（待 `dbnexus` 0.3+ 提供 MySQL 后端）
- 📋 OpenTelemetry 集成
- 📋 分布式追踪
- 📋 Redis Cluster 支持
- 📋 actix-web / warp 适配完善

**里程碑意义**：完成多后端能力与生产级可观测性，覆盖企业级部署需求。

---

### v0.4.0 高级特性（待规划）

计划完成：2027 Q1

- 📋 Refresh Token 自动轮换
- 📋 RBAC 层级角色
- 📋 ABAC 属性访问控制
- 📋 多租户支持
- 📋 审计日志持久化

**里程碑意义**：补充高级安全特性，对标 Sa-Token 的高级场景能力。

---

### v1.0.0 稳定版（待规划）

计划完成：2027 Q2

- 📋 API 冻结（semver 稳定承诺）
- 📋 性能基准测试
- 📋 生产案例文档
- 📋 安全审计

**里程碑意义**：发布 1.0 稳定版，给出向后兼容承诺与生产可用性证据，进入长期维护期。

---

## 版本兼容性策略（SemVer）

Bulwark 遵循 [SemVer](https://semver.org/lang/zh-CN/) 语义化版本规范：

| 版本变更 | 允许的变更类型 | 示例 |
|---------|---------------|------|
| **patch**（0.1.0 → 0.1.1） | 仅 bug fix 与文档，**不破坏**任何 API | 修复会话续期 panic |
| **minor**（0.1 → 0.2） | 可新增 feature、新增 API，**不破坏**已有 API | 新增 `protocol-jwt` |
| **major**（0.x → 1.0） | 允许破坏性变更，仅在重大设计缺陷下 | API 冻结前的最后机会 |

### 破坏性变更过渡策略

破坏性变更优先以 deprecation 周期过渡：

1. 先标记 `#[deprecated]` + 文档警告
2. 至少经过一个 minor 版本的过渡期
3. 过渡期结束后在 major 版本中移除

> 在 0.x 阶段（1.0 之前），minor 版本理论上允许破坏性变更，但 Bulwark 承诺仅在不可避免时才这样做，并提前在 CHANGELOG 中标注。

### 向后兼容承诺

- **0.1.0 的核心 API** 在 1.0 之前不会发生破坏性变更（`BulwarkManager` / `BulwarkUtil` / `BulwarkConfig` 等核心接口稳定）。
- **协议/安全层 API** 在 0.2.0 阶段可能调整，建议在生产环境中锁定具体 patch 版本。

---

## 设计原则

Bulwark 在整个版本演进过程中遵循以下四条原则：

### 1. 借鉴而非照搬

学习 Sa-Token 的领域建模（13 特性域划分）、API 设计哲学（静态工具类 + 全局配置）与使用习惯，但用 Rust idiomatic 方式实现：

- 用 `trait` 替代 Java interface
- 用 `async fn` + `tokio` 替代线程池
- 用 `inventory` 替代 SPI 反射
- 用 `Feature` 门控替代 Maven profile

### 2. 抽象优先

所有核心组件均以 **trait + Default** 模式提供，任何组件都可被替换为自定义实现，框架默认实现仅在未被覆盖时生效。

### 3. Feature 门控

按需编译，减小二进制体积。每个特性域对应一个 cargo feature，通过聚合 feature 一键启用常用组合。保证 Bulwark 在 Edge、WASM、嵌入式等资源敏感场景下也能使用。

### 4. 向后兼容

遵循 semver 规范，破坏性变更优先以 deprecation 周期过渡。

---

## 变更管理

所有版本演进通过 **OpenSpec 工作流** 管理：

```
explore → propose → apply → archive
```

- `explore`：探索阶段，明确需求与可行性
- `propose`：提案阶段，输出 proposal / design / specs / tasks
- `apply`：实施阶段，按 tasks 推进实现
- `archive`：归档阶段，同步 delta spec 到主 spec 库

每个变更在合并前必须经过影响面分析，HIGH / CRITICAL 风险变更需要显式评估后才能推进。

---

> 本路线图为持续滚动更新文档，实际发布时间与内容可能随社区反馈调整。最新进展请关注 [GitHub Releases](https://github.com/Kirky-X/bulwark/releases)。
