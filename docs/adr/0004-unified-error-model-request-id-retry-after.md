# ADR-0004: 统一错误模型——request id 回传、Retry-After 头与模块前缀错误码（R04）

- 状态：Accepted

- 日期：2026-09-28

- 关联代码：`src/error.rs`（六元组 / `prefixed_code` / `retry_after_secs` / `RateLimited`）、`src/context/request_id.rs`（task-local）、`src/web/request_id.rs`、`src/web_actix/request_id.rs`、`src/web_warp/request_id.rs`（三框架中间件）、`src/server/middleware.rs`（429 接线）、`src/server/oauth2_routes.rs`（OIDC Retry-After 头）

## Context

R04 吸收项落地前，`GarrisonError` 的 HTTP 错误响应只有 `error_code`（旧码 `UPPER_SNAKE_CASE`）+ `message`，存在三个缺口：

1. **错误与请求无法关联**：客户端报障时无法把一个错误响应对应到服务端日志中的具体请求（无 request id 回传）。
2. **限流无退避指引**：429 响应不携带 `Retry-After`，客户端只能盲目重试（`server` 限流中间件自建 `{"error": "rate_limited"}` 信封，与统一错误体形状漂移）。
3. **错误码缺模块维度**：旧码是扁平字符串，跨模块检索与告警聚合（按 `auth.*` / `sms.*` 分组）无法表达。

吸收时存在五个必须预先裁决的兼容性决策（新旧并存、头名、秒数格式、错误体注入机制、公开 API 面）。

## Decision

### 决策一：错误码新旧并存（不 deprecate 旧码）

- 旧 `error_code`（`NOT_LOGIN` 等）**冻结原值**继续输出，所有既有消费方零破坏。
- 新字段 `error_id` 携带模块前缀码，格式 `<module>.<snake>`（如 `auth.not_login` / `sms.rate_limit_exceeded` / `ratelimit.rate_limited`），命名风格与既有 miette dotted 码 `garrison.not_login` 先例一致。
- `OAuth2` 变体的模块段为 `oauth`（非 `oauth2`）：`<module>` 段格式约束 `^[a-z]+(_[a-z]+)*$` 不含数字，故取协议域词根 `oauth`（`error_id` 为 `oauth.error`）。
- **单一事实来源**：`parts_and_msg_key` 私有函数五元组扩为六元组（追加 `error_id: &'static str`），全部 arm **人工逐一显式静态书写**（不自动派生——派生规则会为 `EXCEPTION` 这类条件复用码产出歧义映射，且派生逻辑本身成为第二事实来源）。
- `Exception` 变体的三个子 arm（业务 code -1 / -2 / 其他）的 `error_id` 分别为 `exception.not_login` / `exception.not_permission` / `exception.default`——不复用 `auth.*`（保证 `prefixed_code()` 全变体两两唯一，与 `code()` 固定 `EXCEPTION` 的既有先例同构）。
- 旧 → 新对照表写入 [API_REFERENCE.md](../API_REFERENCE.md) 错误模型章节。
- 公开 API：`pub fn prefixed_code() -> &'static str`；`code()` 与 `response_parts` / `response_parts_i18n` 公开签名不变。

### 决策二：body 字段名 `request_id`，无 id 时省略（omitempty）

字段名对齐 pocket-id `ErrorDto` 惯例。当前请求存在 request id（task-local）时统一错误体携带 `request_id` 字段；无（非 HTTP 路径、测试直调）时**字段整体省略**，不输出空串或 null。

### 决策三：`Retry-After` 统一 delta-seconds（整数秒，下限 1）

不做 HTTP-date 双格式——limiteron `RateLimitSnapshot.reset_secs` 上游值本身即秒数，双格式徒增解析分叉。`GarrisonError::retry_after_secs()` 返回 `Some(max(1, secs))`，0 值强制抬到 1（0 秒会误导客户端立即重试打满限流窗口）。仅 `RateLimited` 变体返回 `Some`，其余变体 `None`（`SmsRateLimitExceeded` / `EmailRateLimitExceeded` 是发送窗口限速，非网关限流语义，不携带该头）。

`Retry-After` 为 **advisory 头**：`server` 限流中间件的 allow 判定与随后二次快照（`remaining()`）之间存在 refill 窗口，OIDC `/oauth2/token` 桥接路径只能取限流器配置窗口上界作保守提示——两处头值均**允许陈旧**（提示性质，非精确承诺）。OIDC 限流错误（token handler 的 `OAuth2("rate_limited: ...")` 消息前缀契约）在 `server::oauth2_routes` 桥接为 `RateLimited` 后经统一 `with_retry_after` 输出头。

### 决策四：头名为常量非配置

`X-Request-ID` / `Retry-After` 为编译期常量（`REQUEST_ID_HEADER` / `RETRY_AFTER_HEADER`），**不加配置项**：头名一旦可配置，反向代理规则、监控埋点、客户端解析都会随部署漂移；入站 `X-Request-ID` 校验（非空、长度 ≤ 128、全部可见 ASCII `0x21..=0x7E`）同样内置。入站 id 是**不可信输入**：非法即丢弃重新生成 UUID v4（防 CRLF / header / 日志注入），绝不转义保留。

### 决策五：`GarrisonError` 扩展方式与公开 API 面

新增 `RateLimited { retry_after_secs: u64 }` 变体（核心变体，无 feature 门控；`u64` 单字段不膨胀枚举，`size_of::<GarrisonError>() ≤ 64B` 锚点保持）。不给既有变体加字段（会破坏全部构造点），公开签名 `code()` / `response_parts()` / `response_parts_i18n()` 不动（六元组为私有内部函数）。

### 三框架注入机制差异（warp 后置回填）

request id 经 tokio `task_local!`（`REQUEST_ID: Arc<str>`，与 `stp` 的 `CURRENT_TOKEN` 同机制）传播，三框架中间件在请求入口设置：

- **axum**：`middleware::from_fn` 内 `REQUEST_ID.scope` 包住 `next.run(req)`——handler 与统一错误体渲染（`to_json_body`）都在 scope 内，**前置渲染**直接读 task-local。
- **actix-web**：Transform/Service 包住 `inner.call`。注意 actix 在 dispatch 层（scope 外）渲染 `Err(Error)`——中间件在 scope 内自行调用 `error_response()` 渲染为 `Ok(ServiceResponse)`，保证错误体 `request_id` 与头一致；`HttpRequest` 的留存 clone 使用 actix-web 4 官方廉价 Arc 语义（历史 BUG #8 的 Rc/match_info_mut panic 属 actix 3.x 时代，4.12 不适用）。
- **warp**：`wrap_fn` 只能组合 Filter，**无法用自有 future 包住内层 filter 的执行**——handler（错误体渲染）必然在 scope 之外。采用**后置回填**：`and_then` 内生成 id、`scope` 包住后置处理，对 4xx/5xx 且 `content-type: application/json` 的响应收集 body 解析 JSON 后经共享函数 `inject_request_id_into_error_body` 注入 `request_id` 再重组（成功与非 JSON 错误响应零缓冲透传）。三框架终态输出形状一致。防御路径显性化且不吞语义：body 收集失败（流错误）时保留**原状态码与响应头**（含 `Retry-After` / `X-Request-ID`），仅替换 body 为统一错误体；body 超过 4KB（与 axum IntoResponse 截断阈值一致）或解析出非 JSON 时跳过注入、原样透传。

## Consequences

**正面：**

- 客户端报障可凭 `request_id` 精确关联服务端日志（中间件 span + 事件均携带该字段）。
- 429 自带退避指引，`server` 限流中间件与统一错误体形状收敛（移除自建信封）。
- `error_id` 使日志/监控可按模块维度聚合；新旧码并存零迁移成本。

**负面 / 代价：**

- 新增变体时 `parts_and_msg_key` 需人工补 `error_id`（哨兵测试 `prefixed_code_covers_all_variants_unique_and_well_formed` 强制覆盖 + 格式校验）。
- warp 路径错误响应有一次 body 缓冲 + 重序列化开销（仅 4xx/5xx JSON；成功响应零缓冲）。
- OIDC 端点自建错误体（RFC 6749 信封）保持 body 键不动，`/oauth2/token` 限流 429 经 `rate_limited` 前缀桥接为 `RateLimited` 后补 `Retry-After` 头（其余 4 个端点——`/oauth2/authorize`、`/oauth2/authorize/resume`、`/oauth2/revoke`、`/oauth2/introspect`——均套 `with_retry_after` 但无限流来源，头为防御性 no-op）——两套错误体形状（OAuth2 `error` vs 统一 `error_code`）并存是既有契约，非本次引入。

**测试锚点：** 哨兵计数 29/33/30/34（四组 cfg 组合）、旧码冻结全量对照表（`legacy_error_codes_frozen_at_original_values` 覆盖全部 arm 的状态码 / error_code / `code()`，行数与 `all_variant_samples()` 对齐）、`prefixed_code` 全变体唯一 + 格式、`retry_after_secs` 下限、体积 ≤64B、三框架 X-Request-ID / request_id / Retry-After 对等断言集、OIDC 429 Retry-After 头断言、限流日志降级 warn 断言。
