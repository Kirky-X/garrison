# Design: v0.4.1 Gap Closure

## Context

Bulwark 0.4.0 发布后，探索性分析暴露 8 类遗留问题。本 change 作为 0.4.1 补丁版本，聚焦 gap 闭合
与代码加固，不引入新功能。

**当前状态**（基于 3 个并行 subagent 探索结果）：

- **幽灵代码**：`cargo build --features full --workspace` 零 dead_code 警告；5 个死字段被
  `#[allow(dead_code)]` 显式抑制（TotpHandler.step/digits、DigestResponse.username/realm/uri）
- **文档/代码不一致**：3 项（OidcHandler 算法支持、gRPC 拦截器、DefaultBulwarkInterceptor 注解）
- **覆盖率**：95.41%（2039/2137 行）达标，但被 1 个失败测试阻断；7 个模块 <95%
- **环境护栏**：配置文件完整（9 个），CI 4 workflow 完备，但 **pre-commit hooks 未安装**（critical）
- **examples**：29×29 完美 1:1，但 6 个 feature 无独立 example
- **阻断测试**：`tests/plugin_listener_integration.rs::auto_wire_logout_triggers_hooks` 失败

**约束**：

- 向后兼容 0.4.0 API（不引入 BREAKING CHANGE）
- patch 版本递增（0.4.0 → 0.4.1），不引入新功能
- 所有 0.5.0+ 范围功能明确排除（JWKS/JWT 三模式/多租户/PostgreSQL/HTTP API/proc-macro 等）
- 测试覆盖率维持 95%+，目标 95.5%+
- clippy + fmt + doc 零警告

## Goals / Non-Goals

**Goals:**

- 清理 0.4.0 遗留的死代码与文档不一致
- 修复阻断测试，恢复覆盖率工具链可用性
- 安装 pre-commit hooks，恢复本地门禁有效性
- 补全 6 个缺失的 examples
- 通过全维度代码审查并修复发现的问题
- 文档与代码完全一致

**Non-Goals:**

- 不实现 0.5.0+ 范围的新功能（JWKS 缓存、JWT 三模式、多租户隔离、PostgreSQL/MySQL 后端、
  HTTP API 端点、过程宏注解、kickoutByDevice、UserExtRepository、BulwarkStrategy 注册表、
  OAuth2 注解 gap #4、SSO 原子 get-and-delete）
- 不重构 0.4.0 既有模块结构
- 不修改 0.4.0 已归档的 openspec change
- 不升级主要依赖版本

## Decisions

### D1: 死字段清理 — 逐个评估，优先删除

**决策**：对 5 个 `#[allow(dead_code)]` 字段逐个评估：

1. **`TotpHandler.step` / `TotpHandler.digits`**（src/secure/totp/mod.rs:32,35）：
   - 当前：存储 TOTP 配置（步长/位数）但从不读取，TOTP 库内部处理
   - 决策：**保留**，补 doc 注释说明「元数据字段，供调试/日志使用，TOTP 验证由 totp-rs 库内部处理」
   - 理由：字段语义清晰，未来可能用于日志/监控，删除收益低

2. **`DigestResponse.username` / `.realm` / `.uri`**（src/secure/httpdigest/mod.rs:228,230,233）：
   - 当前：从 Authorization header 解析但从不使用
   - 决策：**删除**，仅在解析函数内用局部变量
   - 理由：解析后不使用属于 dead code，保留误导维护者以为会被使用

**替代方案**：全部保留 + doc 注释 → 拒绝，DigestResponse 三字段无未来用途规划

### D2: OidcHandler 算法支持 — 文档化限制，收窄 API

**决策**：`OidcHandler::with_algorithm` 的参数类型从 `Algorithm` 收窄为 `HmacAlgorithm`（或保持
`Algorithm` 但 doc 注释明确「仅支持 HMAC，非对称算法返回 Config 错误」）。

**理由**：当前 `require_hmac_algorithm()` 在入口拒绝非对称算法，API 表面与实际行为不一致。
JWKS 端点（支持非对称算法）是 0.5.0+ 范围，0.4.1 仅文档化限制。

**替代方案**：实现 JWKS 端点支持非对称算法 → 拒绝，超 0.4.1 范围（0.5.0+）

### D3: gRPC 拦截器 — doc 注释强化，不改行为

**决策**：`BulwarkGrpcInterceptor` doc 注释强化：

- 明确标注「仅提取 token，不执行 async 鉴权」
- 明确标注「tonic::Interceptor 是同步 trait，无法调用 async check_login」
- 推荐替代方案：`tonic tower::Layer + BulwarkContext` 实现完整 async 鉴权
- 在 `troubleshooting.md` 新增「gRPC 鉴权方案选择」段落

**理由**：行为正确（tonic 限制），问题是文档不足导致用户误用

### D4: DefaultBulwarkInterceptor — doc 注释强化

**决策**：`DefaultBulwarkInterceptor::pre_handle` doc 注释强化：

- 明确标注 7 个注解的处理方式（NotImplemented / 直接放行）
- 引导用户使用 axum extractor 模式（`CheckLogin` / `CheckRole` / `CheckPermission`）
- 在 `faq.md` 新增「extractor vs annotation 模式选择」段落

**理由**：行为正确（无 HTTP 上下文），问题是文档不足

### D5: pre-commit hooks 安装 — 立即修复

**决策**：执行 `pre-commit install` 安装 hooks，验证 hook 触发（故意引入格式错误确认拦截）。

**理由**：`.pre-commit-config.yaml` 已配置 11 个 hook（fmt/clippy/cargo-deny/codespell 等），
但从未安装，本地提交完全绕过门禁。这是 critical 缺陷。

**补充**：CI 补 Miri job（评估项目 unsafe 代码：仅 chrono/reqwest 等 deps 有 unsafe，
项目自身代码无 unsafe → Miri job 可选，优先级低）

### D6: 阻断测试修复 — 优先排查

**决策**：优先修复 `auto_wire_logout_triggers_hooks` 测试失败：

1. 读取测试代码与被测代码
2. 分析失败原因（可能是 0.4.0 auto-wire 逻辑变更导致 mock 期望不匹配）
3. 修复测试或被测代码
4. 验证 `cargo llvm-cov --features full --workspace` 可生成新鲜报告

**理由**：该测试阻断覆盖率工具链，必须最先修复

### D7: 覆盖率提升策略 — 逐模块补测试

**决策**：按严重程度逐模块补测试：

1. **`context/mod.rs`（0%）**：补 `set_cookie` 默认方法测试
2. **`observability/mod.rs`（65.6%）**：
   - `BulwarkMetrics::new` / `Default` / `Debug`：补单元测试
   - `init_otlp_tracing`：用 mock endpoint 或 `#[cfg(test)]` 条件编译跳过
   - `From<ExporterBuildError>`：补错误转换测试
3. **`manager/mod.rs`（86.9%）**：补 factory_selector 返回 None 的兜底路径测试
4. **`error.rs`（88.4%）**：补 `to_json_body` 完整路径测试
5. **`web_actix/mod.rs`（92.9%）**：补 `with_interceptor` 测试
6. **`config/mod.rs`（93.4%）**：补 env var 加载路径测试
7. **其余 <95% 模块**：补边界路径测试

**目标**：所有模块 ≥95%，整体 ≥95.5%

### D8: Examples 补全 — 6 个新 example

**决策**：新增 6 个 example，每个配套 bin + test + feature 转发：

1. **`web_actix_example`**：演示 BulwarkRouter + middleware + CheckLogin/CheckRole/CheckPermission extractor
2. **`web_warp_example`**：演示 BulwarkRouter + rejection + check_login/check_role/check_permission
3. **`grpc_interceptor`**：演示 BulwarkGrpcInterceptor 使用（token 提取 + 手动 check_login）
4. **`i18n_usage`**：演示 BulwarkLocale + set_locale + translate_error（中英文切换）
5. **`observability_setup`**：演示 BulwarkMetrics 注册 + init_otlp_tracing（mock endpoint）
6. **`cache_redis`**（可选）：演示 Redis L2 后端配置（需 Redis 实例，test 标记 `#[ignore]`）

**理由**：6 个 feature 缺独立 example，用户无法快速上手

### D9: 代码审查 — 6 维度 subagent 并行

**决策**：派遣 6 个 subagent 逐维度审查，每个维度独立：

1. **架构与设计**：模块边界、依赖方向、抽象层次、feature flag 一致性
2. **正确性与逻辑**：边界条件、错误处理、并发安全、TOCTOU
3. **性能与资源**：内存分配、clone 频率、异步效率、锁粒度
4. **安全与健壮性**：输入校验、密钥处理、constant_time_eq、unsafe 代码
5. **代码简化与可维护性**：重复代码、过度工程、命名、注释
6. **API 一致性与文档**：公共 API 契约、doc 注释、示例一致性

发现问题使用 kueiku 分析最优解决方案（结构化决策：问题定义 → 选项枚举 → 权衡分析 → 最优方案）

### D10: 文档同步 — 代码优先，文档跟随

**决策**：所有代码修改完成后，逐文档同步：

1. `CHANGELOG.md`：新增 0.4.1 段落（Keep a Changelog 格式）
2. `docs/architecture.md`：补 0.4.0 新增模块 + 0.4.1 修复项
3. `docs/configuration.md`：补新 feature flag 配置说明
4. `docs/troubleshooting.md`：补已知限制（OIDC 仅 HMAC、gRPC 同步、注解 NotImplemented）
5. `docs/faq.md`：补 extractor vs annotation、gRPC 鉴权方案选择
6. `README.md`：更新 feature 列表与示例链接
7. `mdbook/`：文档站同步

**理由**：避免文档与代码再次漂移
