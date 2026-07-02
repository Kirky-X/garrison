# Proposal: v0.4.1 Gap Closure

## Why

Bulwark 0.4.0 已发布（2026-07-02），补齐了 0.2.0 协议层 8 项遗留 gap 中的 7 项。但代码审查与
探索性分析暴露出 0.4.0 存在 **8 类遗留问题**：幽灵字段未清理、行为与文档不一致、测试覆盖率瓶颈、
环境护栏失效、examples 覆盖不全、缺乏全维度代码审查、回归测试未通过、文档与代码漂移。

本 change 作为 **0.4.1 补丁版本**（patch 递增，非新功能引入），聚焦 gap 闭合与代码加固，确保
0.4.0 已发布功能的**质量、一致性、可维护性**达标。所有 0.5.0+ 范围的新功能（JWKS 缓存、JWT 三模式、
多租户、PostgreSQL/MySQL、HTTP API 端点、过程宏注解等）明确排除在本 change 范围外。

## What Changes

### 1. 幽灵代码清理（deep analysis 驱动）

- **分析结论**：`cargo build --features full --workspace` 零 dead_code 警告，无真正幽灵函数
- **5 个死字段清理**（`#[allow(dead_code)]` 显式抑制）：
  - `src/secure/totp/mod.rs`：`TotpHandler.step` / `TotpHandler.digits`（存储从不读取）
  - `src/secure/httpdigest/mod.rs`：`DigestResponse.username` / `.realm` / `.uri`（解析从不使用）
- **清理策略**：评估每个字段的未来用途，无明确规划则删除；保留则补 doc 注释说明用途

### 2. 文档与代码行为不一致修复（3 项 gap）

- **Gap A**：`OidcHandler` 算法支持不一致 — `with_algorithm` 接受非对称算法但 `require_hmac_algorithm()`
  在入口拒绝。修复：API 表面移除非对称算法参数，或文档明确标注「仅支持 HMAC」
- **Gap B**：`BulwarkGrpcInterceptor` 仅提取 token 不执行鉴权 — tonic `Interceptor` 同步 trait 限制。
  修复：doc 注释强化使用指引，推荐 `tower::Layer + BulwarkContext` 方案
- **Gap C**：`DefaultBulwarkInterceptor::pre_handle` 对 7 个注解返回 NotImplemented/直接放行 —
  缺 HTTP 上下文。修复：doc 注释明确引导使用 extractor 模式

### 3. 环境护栏修复（pangu 检查）

- **🔴 Critical**：`.pre-commit-config.yaml` 存在但 `pre-commit install` 从未执行 — 本地提交完全绕过门禁
- **修复**：执行 `pre-commit install` + 验证 hook 触发
- **可选改进**：CI 补 Miri job（项目含 unsafe 代码）、补 `lefthook.yml` 双产出

### 4. 测试覆盖率提升至 95%+ 稳态

- **当前**：95.41%（2039/2137 行）— 达标但被 1 个失败测试阻断无法生成新鲜报告
- **🔴 阻断测试**：`tests/plugin_listener_integration.rs::auto_wire_logout_triggers_hooks` 失败
- **低覆盖率模块修复**（按严重程度）：
  - `src/context/mod.rs`：0.0%（2 行未覆盖，`set_cookie` 默认方法）
  - `src/observability/mod.rs`：65.6%（`init_otlp_tracing` / `BulwarkMetrics::new` / `Default` / `Debug`）
  - `src/manager/mod.rs`：86.9%（factory_selector 兜底路径）
  - `src/error.rs`：88.4%（`to_json_body` 部分路径）
  - `src/secure/httpbasic/mod.rs`：92.0%
  - `src/web_actix/mod.rs`：92.9%（`with_interceptor`）
  - `src/config/mod.rs`：93.4%（env var 加载路径）
- **目标**：所有模块 ≥95%，整体 ≥95.5%

### 5. 全维度代码审查（diting + subagents）

派遣独立 subagent 逐维度审查，每个维度一个 subagent：

- **维度 1**：架构与设计（模块边界、依赖方向、抽象层次）
- **维度 2**：正确性与逻辑（边界条件、错误处理、并发安全）
- **维度 3**：性能与资源（内存、分配、异步效率）
- **维度 4**：安全与健壮性（输入校验、密钥处理、unsafe 代码）
- **维度 5**：代码简化与可维护性（重复代码、过度工程、命名）
- **维度 6**：API 一致性与文档（公共 API 契约、doc 注释、示例一致性）
- 发现问题使用 kueiku 分析最优解决方案后优化

### 6. Examples 覆盖补全（6 个缺失）

- **当前**：29 examples × 29 tests（1:1 完美映射），但 6 个 feature 无独立 example：
  - `web-actix`：BulwarkRouter / middleware / extractor（高优先级）
  - `web-warp`：BulwarkRouter / rejection / check 函数（高优先级）
  - `grpc`：BulwarkGrpcInterceptor 使用示例（中优先级）
  - `i18n`：BulwarkLocale / set_locale / translate_error（中优先级）
  - `metrics-prometheus` + `observability-otlp`：metrics 注册 + OTLP 初始化（中优先级）
  - `cache-redis`：Redis L2 后端演示（低优先级，可选）
- 每个新 example 配套 `examples/tests/<name>.rs` 测试 + `examples/src/bin/<name>.rs` 入口

### 7. 回归测试

- 修复后运行完整测试矩阵：
  - `cargo test --workspace --features full`（全部通过）
  - `cargo test --workspace --no-default-features`（default=[] 通过）
  - `cargo clippy --workspace --features full -- -D warnings`（零警告）
  - `cargo fmt --all -- --check`（零差异）
  - `cargo doc --workspace --features full --no-deps`（零警告）
  - examples 测试全绿

### 8. 文档同步

- 更新 `docs/` 下文档与代码实现一致：
  - `docs/architecture.md`：补 0.4.0 新增模块、标注 0.4.1 修复项
  - `docs/configuration.md`：补新 feature flag 配置说明
  - `docs/troubleshooting.md`：补已知限制（OIDC 仅 HMAC、gRPC 同步限制等）
  - `docs/faq.md`：补常见问题（extractor vs annotation 模式选择）
  - `CHANGELOG.md`：新增 0.4.1 版本段落
  - `README.md`：更新 feature 列表与示例链接
- `mdbook/` 文档站同步更新

## Capabilities

### Modified Capabilities

- `secure-totp`：清理死字段（step/digits），doc 注释强化
- `secure-httpdigest`：清理死字段（DigestResponse.username/realm/uri），doc 注释强化
- `protocol-oidc`：API 表面与实际行为对齐（算法支持文档化）
- `grpc-integration`：使用限制文档化，推荐替代方案
- `annotation-system`：NotImplemented 行为文档化，引导 extractor 模式
- `observability-stack`：覆盖率提升，init_otlp_tracing 测试覆盖
- `context-abstraction`：set_cookie 默认方法测试覆盖
- `web-actix`：新增独立 example，with_interceptor 测试覆盖
- `web-warp`：新增独立 example
- `version-roadmap`：新增 0.4.1 版本段落

### New Capabilities

无（0.4.1 是补丁版本，不引入新 capability）

## Impact

### 代码影响

- `src/secure/totp/mod.rs` — 死字段清理或文档化
- `src/secure/httpdigest/mod.rs` — 死字段清理或文档化
- `src/protocol/oauth2/oidc.rs` — API 文档强化或参数收窄
- `src/grpc/mod.rs` — doc 注释强化
- `src/router/mod.rs` — doc 注释强化
- `src/observability/mod.rs` — 补测试
- `src/context/mod.rs` — 补测试
- `src/manager/mod.rs` — 补测试
- `src/error.rs` — 补测试
- `src/web_actix/mod.rs` — 补测试 + with_interceptor 覆盖
- `src/config/mod.rs` — 补测试
- `examples/src/*.rs` — 新增 6 个 example
- `examples/tests/*.rs` — 新增 6 个 test
- `examples/Cargo.toml` — 新增 6 个 bin + feature 转发
- `Cargo.toml` — version 0.4.0 → 0.4.1
- `tests/plugin_listener_integration.rs` — 修复失败测试
- 多个 src/ 文件 — code review 后按 kueiku 方案优化

### 依赖与兼容性

- 无新增外部依赖
- 向后兼容：所有修改均为 bugfix/doc/test/清理，不引入 BREAKING CHANGE
- 死字段清理仅影响 `#[allow(dead_code)]` 字段，不影响公共 API

### 测试与覆盖率

- 修复 1 个阻断测试（`auto_wire_logout_triggers_hooks`）
- 新增 ~30-50 个单元测试（覆盖低覆盖率模块）
- 新增 6 个 example + 6 个 example test
- 目标：整体覆盖率 ≥95.5%，所有模块 ≥95%
- clippy + fmt + doc 零警告

### 文档影响

- `CHANGELOG.md` 新增 0.4.1 段落
- `docs/architecture.md` / `configuration.md` / `troubleshooting.md` / `faq.md` 同步更新
- `README.md` feature 列表更新
- `mdbook/` 文档站同步

## NEEDS CLARIFICATION

无 — 所有 8 项任务的范围与验收标准已通过探索性分析明确。
