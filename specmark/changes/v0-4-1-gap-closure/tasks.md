# Tasks: v0.4.1 Gap Closure

## Phase 1: 环境护栏修复与阻断测试修复（前置）

- [x] 1.1 执行 `pre-commit install` 安装本地 hooks（pip3 install --break-system-packages pre-commit + pre-commit install）
- [x] 1.2 验证 hook 触发：确认 pre-commit 拦截（修复 .pre-commit-config.yaml line 44 YAML 语法错误，block scalar 替代内联 colon）
- [x] 1.3 读取 `tests/plugin_listener_integration.rs` 中 `auto_wire_logout_triggers_hooks` 测试代码
- [x] 1.4 测试实际通过（false alarm）— `cargo test --workspace --features full` 全绿
- [x] 1.5 无需修复 — 测试已通过
- [x] 1.6 验证 `cargo test --test plugin_listener_integration --features full auto_wire_logout_triggers_hooks` 通过
- [x] 1.7 覆盖率工具链可用（cargo-llvm-cov 已安装）
- [ ] 1.8 commit: "fix(ci): 修复 .pre-commit-config.yaml YAML 语法 + 安装 pre-commit hooks"

## Phase 2: 幽灵代码清理（deep analysis 驱动）

- [x] 2.1 读取 `src/secure/totp/mod.rs` 分析 `TotpHandler.step` / `TotpHandler.digits` 字段用途
- [x] 2.2 保留 step/digits 字段，补 doc 注释「元数据字段，供调试/日志使用，TOTP 验证由 totp-rs 库内部处理」
- [x] 2.3 读取 `src/secure/httpdigest/mod.rs` 分析 `DigestResponse.username` / `.realm` / `.uri` 字段用途
- [x] 2.4 删除 DigestResponse 三字段（parse_authorization 改为忽略 username/realm/uri，不再要求存在）
- [x] 2.5 修改 `src/secure/httpdigest/mod.rs`：删除 3 个字段 + 修改 `parse_authorization` 忽略三字段
- [x] 2.6 运行 `cargo test --features "secure-totp secure-httpdigest" --lib secure` — 33 passed, 0 failed
- [x] 2.7 更新 `src/secure/totp/mod.rs` doc 注释 + 恢复 `#[allow(dead_code)]` 属性
- [x] 2.8 clippy 零警告 — `cargo clippy --features "secure-totp secure-httpdigest" --lib -- -D warnings` 通过

## Phase 3: 文档与代码行为不一致修复

- [x] 3.1 读取 `src/protocol/oauth2/oidc.rs` 分析 `with_algorithm` API 与 `require_hmac_algorithm` 逻辑
- [x] 3.2 强化 `OidcHandler::with_algorithm` doc 注释：明确「仅支持 HMAC（HS256/HS384/HS512），非对称算法返回 Config 错误；JWKS + 非对称算法待 0.5.0+」（with_algorithm 已有 doc，强化 sign/verify 即可）
- [x] 3.3 强化 `sign_id_token` / `verify_id_token` doc 注释：标注算法限制 + 错误返回
- [x] 3.4 读取 `src/grpc/mod.rs` 分析 `BulwarkGrpcInterceptor` 行为
- [x] 3.5 强化 `BulwarkGrpcInterceptor` doc 注释：明确「仅提取 token，不执行 async 鉴权；推荐 tonic tower::Layer + BulwarkContext 实现完整鉴权」
- [x] 3.6 读取 `src/router/mod.rs` 分析 `DefaultBulwarkInterceptor::pre_handle` 注解处理
- [x] 3.7 强化 `pre_handle` doc 注释：明确 11 个注解的处理方式（直接鉴权 5 个 / NotImplemented 3 个 / 直接放行 3 个）+ 引导 extractor 模式
- [x] 3.8 运行 `cargo doc --workspace --features full --no-deps` 确认零警告 + `cargo clippy --workspace --features full --all-targets -- -D warnings` 零警告
- [ ] 3.9 commit: "docs: 强化 OIDC/gRPC/Interceptor 行为限制文档（Phase 3, gap A/B/C）"

## Phase 4: 测试覆盖率提升至 95%+ 稳态

- [ ] 4.1 读取 `src/context/mod.rs` 分析 `set_cookie` 默认方法未覆盖原因
- [ ] 4.2 补 `set_cookie` 默认方法测试（或确认已有测试间接覆盖）
- [ ] 4.3 读取 `src/observability/mod.rs` 分析 7 个未测试函数
- [ ] 4.4 补 `BulwarkMetrics::new` / `Default` / `Debug` / `From<ExporterBuildError>` 测试
- [ ] 4.5 补 `init_otlp_tracing` 测试（mock endpoint 或条件编译跳过真实 gRPC）
- [ ] 4.6 读取 `src/manager/mod.rs` 分析 factory_selector 兜底路径
- [ ] 4.7 补 factory_selector 返回 None 的兜底路径测试
- [ ] 4.8 读取 `src/error.rs` 分析 `to_json_body` 未覆盖路径
- [ ] 4.9 补 `to_json_body` 完整路径测试
- [ ] 4.10 读取 `src/web_actix/mod.rs` 分析 `with_interceptor` 未覆盖原因
- [ ] 4.11 补 `with_interceptor` 测试
- [ ] 4.12 读取 `src/config/mod.rs` 分析 env var 加载路径
- [ ] 4.13 补 `COOKIE_SECURE` / `COOKIE_SAME_SITE` env var 加载测试
- [ ] 4.14 补 `src/secure/httpbasic/mod.rs` 边界路径测试（92% → 95%+）
- [ ] 4.15 补 `src/strategy/hooks.rs` 钩子路径测试（94.4% → 95%+）
- [ ] 4.16 补 `src/secure/httpdigest/mod.rs` parse_authorization 路径测试（94.7% → 95%+）
- [ ] 4.17 补 `src/strategy/mod.rs` 权限缓存写入失败 warn 路径测试（94.9% → 95%+）
- [ ] 4.18 运行 `cargo llvm-cov --features full --workspace --html` 确认整体 ≥95.5%，所有模块 ≥95%
- [ ] 4.19 commit: "test: 覆盖率提升至 95.5%+（context/observability/manager/error/web_actix/config）"

## Phase 5: Examples 覆盖补全（6 个缺失）

- [ ] 5.1 读取 `examples/Cargo.toml` 了解 feature 转发与 bin 配置模式
- [ ] 5.2 新增 `examples/src/web_actix_example.rs`：演示 BulwarkRouter + middleware + CheckLogin/CheckRole/CheckPermission extractor
- [ ] 5.3 新增 `examples/src/bin/web_actix_example.rs` + `examples/tests/web_actix_example.rs`
- [ ] 5.4 新增 `examples/src/web_warp_example.rs`：演示 BulwarkRouter + rejection + check 函数
- [ ] 5.5 新增 `examples/src/bin/web_warp_example.rs` + `examples/tests/web_warp_example.rs`
- [ ] 5.6 新增 `examples/src/grpc_interceptor.rs`：演示 BulwarkGrpcInterceptor token 提取 + 手动 check_login
- [ ] 5.7 新增 `examples/src/bin/grpc_interceptor.rs` + `examples/tests/grpc_interceptor.rs`
- [ ] 5.8 新增 `examples/src/i18n_usage.rs`：演示 BulwarkLocale + set_locale + translate_error
- [ ] 5.9 新增 `examples/src/bin/i18n_usage.rs` + `examples/tests/i18n_usage.rs`
- [ ] 5.10 新增 `examples/src/observability_setup.rs`：演示 BulwarkMetrics 注册 + init_otlp_tracing（mock endpoint）
- [ ] 5.11 新增 `examples/src/bin/observability_setup.rs` + `examples/tests/observability_setup.rs`
- [ ] 5.12 新增 `examples/src/cache_redis.rs`（可选）：演示 Redis L2 后端配置（test 标记 `#[ignore]` 需真实 Redis）
- [ ] 5.13 新增 `examples/src/bin/cache_redis.rs` + `examples/tests/cache_redis.rs`
- [ ] 5.14 更新 `examples/Cargo.toml`：新增 6 个 `[[bin]]` 段 + feature 转发 + `full` 聚合更新
- [ ] 5.15 运行 `cargo test -p bulwark-examples --features full` 确认全部通过
- [ ] 5.16 commit: "feat(examples): 补全 6 个缺失 example（web_actix/web_warp/grpc/i18n/observability/cache_redis）"

## Phase 6: 全维度代码审查（diting + subagents）

- [ ] 6.1 派遣 subagent 1：架构与设计维度审查（模块边界/依赖方向/抽象层次/feature flag 一致性）
- [ ] 6.2 派遣 subagent 2：正确性与逻辑维度审查（边界条件/错误处理/并发安全/TOCTOU）
- [ ] 6.3 派遣 subagent 3：性能与资源维度审查（内存分配/clone 频率/异步效率/锁粒度）
- [ ] 6.4 派遣 subagent 4：安全与健壮性维度审查（输入校验/密钥处理/constant_time_eq/unsafe）
- [ ] 6.5 派遣 subagent 5：代码简化与可维护性维度审查（重复代码/过度工程/命名/注释）
- [ ] 6.6 派遣 subagent 6：API 一致性与文档维度审查（公共 API 契约/doc 注释/示例一致性）
- [ ] 6.7 汇总 6 个维度审查报告，按严重程度排序（CRITICAL/HIGH/MEDIUM/LOW）
- [ ] 6.8 对每个 HIGH+ 问题使用 kueiku 分析最优解决方案（问题定义 → 选项枚举 → 权衡 → 最优方案）
- [ ] 6.9 按 kueiku 方案实施修复（逐个 commit）
- [ ] 6.10 运行 `cargo test --workspace --features full` + `cargo clippy --workspace --features full -- -D warnings` 确认全绿
- [ ] 6.11 commit: "refactor: 全维度代码审查修复（架构/正确性/性能/安全/简化/API 一致性）"

## Phase 7: 回归测试

- [ ] 7.1 运行 `cargo test --workspace --features full`（全部通过）
- [ ] 7.2 运行 `cargo test --workspace --no-default-features`（default=[] 通过）
- [ ] 7.3 运行 `cargo test --workspace --features all-defaults`（all-defaults 通过）
- [ ] 7.4 运行 `cargo test --workspace --features production`（production 通过）
- [ ] 7.5 运行 `cargo clippy --workspace --features full -- -D warnings`（零警告）
- [ ] 7.6 运行 `cargo fmt --all -- --check`（零差异）
- [ ] 7.7 运行 `cargo doc --workspace --features full --no-deps`（零警告）
- [ ] 7.8 运行 `cargo test -p bulwark-examples --features full`（examples 全绿）
- [ ] 7.9 运行 `cargo llvm-cov --features full --workspace --html` 确认覆盖率 ≥95.5%
- [ ] 7.10 运行 `pre-commit run --all-files` 确认所有 hook 通过
- [ ] 7.11 如有失败，修复后回到 7.1 重新运行

## Phase 8: 文档同步

- [ ] 8.1 更新 `CHANGELOG.md`：新增 0.4.1 版本段落（Keep a Changelog 格式，含 8 类修复）
- [ ] 8.2 更新 `Cargo.toml`：version 0.4.0 → 0.4.1
- [ ] 8.3 更新 `docs/architecture.md`：补 0.4.0 新增模块 + 0.4.1 修复项
- [ ] 8.4 更新 `docs/configuration.md`：补新 feature flag 配置说明（0.4.0 引入的 5 个 + 0.4.1 examples）
- [ ] 8.5 更新 `docs/troubleshooting.md`：补已知限制（OIDC 仅 HMAC / gRPC 同步限制 / 注解 NotImplemented / SSO TOCTOU）
- [ ] 8.6 更新 `docs/faq.md`：补 extractor vs annotation 模式选择 + gRPC 鉴权方案选择
- [ ] 8.7 更新 `README.md`：更新 feature 列表 + 示例链接 + 版本号
- [ ] 8.8 更新 `mdbook/` 文档站内容同步
- [ ] 8.9 运行 `cargo doc --workspace --features full --no-deps` 确认文档零警告
- [ ] 8.10 commit: "docs: 0.4.1 文档同步（CHANGELOG/architecture/configuration/troubleshooting/faq/README）"

## Phase 9: 收尾

- [ ] 9.1 运行 `git log --oneline -20` 确认 commit 历史清晰
- [ ] 9.2 运行 `cargo test --workspace --features full` 最终确认全绿
- [ ] 9.3 运行 `cargo llvm-cov --features full --workspace --html` 最终确认覆盖率
- [ ] 9.4 更新 `specmark/changes/v0-4-1-gap-closure/tasks.md` 所有任务勾选完成
- [ ] 9.5 提示运行 `/specmark converge` 对比代码与 spec，append 缺漏任务
- [ ] 9.6 converge 完成后提示运行 `/specmark archive` 归档
