// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 请求标识（request id）task-local 上下文。
//!
//! 机制与 [`crate::stp`] 的 `CURRENT_TOKEN` task-local 同源：tokio
//! `task_local!`，由各 Web 框架中间件（axum / actix-web / warp）在请求入口
//! 设置，请求结束自动清除；统一错误响应体（[`crate::error::GarrisonError::to_json_body`]）
//! 从 [`current`] 读取并携带 `request_id` 字段，实现错误与请求的关联回传。
//!
//! # 入站校验（不可信输入）
//!
//! 入站 `X-Request-ID` 仅在满足「非空、长度 ≤ [`MAX_INBOUND_LEN`]、全部为
//! 可见 ASCII（`0x21..=0x7E`）」时原样传播；否则丢弃并重新生成 UUID v4。
//! 可见 ASCII 边界同时排除空格与 DEL，可阻断 CRLF / header 注入与日志注入
//! （`\r` / `\n` / `\t` 均落在 `0x21..=0x7E` 之外）。

use std::future::Future;
use std::sync::Arc;

/// `X-Request-ID` 请求/响应头名（固定常量，非配置项）。
pub const REQUEST_ID_HEADER: &str = "X-Request-ID";

/// `Retry-After` 响应头名（固定常量，非配置项）。
///
/// 值统一为 delta-seconds（整数秒，下限 1），不做 HTTP-date 双格式
/// （limiteron 快照的 `reset_secs` 本身即秒数）。
pub const RETRY_AFTER_HEADER: &str = "Retry-After";

/// 统一错误响应体中携带 request id 的字段名。
pub const REQUEST_ID_BODY_FIELD: &str = "request_id";

/// 入站 request id 长度上限（字节）。
pub const MAX_INBOUND_LEN: usize = 128;

/// request id 传播载体。
///
/// axum 中间件将其注入 `request.extensions()`（handler 经
/// `Extension<RequestId>` 读取），actix-web 中间件注入
/// `req.extensions_mut()`。warp 无 request extensions 机制，经 task-local
/// 传播。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub Arc<str>);

tokio::task_local! {
    static REQUEST_ID: Arc<str>;
}

/// 读取当前请求的 request id。
///
/// 未在 [`scope`] 内（非 HTTP 请求路径、测试直接调用）返回 `None`。
pub fn current() -> Option<Arc<str>> {
    REQUEST_ID.try_with(Arc::clone).ok()
}

/// 在 `REQUEST_ID` scope 内执行 `f`。
pub async fn scope<R, F>(id: Arc<str>, f: F) -> R
where
    F: Future<Output = R>,
{
    REQUEST_ID.scope(id, f).await
}

/// 生成新的 request id（UUID v4）。
pub fn generate() -> Arc<str> {
    Arc::from(uuid::Uuid::new_v4().to_string().as_str())
}

/// 校验入站 request id 是否可原样传播。
///
/// 规则：非空、长度 ≤ [`MAX_INBOUND_LEN`]、全部字节为可见 ASCII
/// （`0x21..=0x7E`）。入站 id 是不可信输入，非法即拒绝（由
/// [`propagate_or_generate`] 重新生成），绝不做转义后保留。
pub fn is_valid_inbound_request_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_INBOUND_LEN && id.bytes().all(|b| (0x21..=0x7E).contains(&b))
}

/// 入站 request id 合法则原样传播，否则丢弃并重新生成 UUID v4。
///
/// 判定为确定性逻辑（显式代码），模型不参与决策。
pub fn propagate_or_generate(inbound: Option<&str>) -> Arc<str> {
    match inbound {
        Some(id) if is_valid_inbound_request_id(id) => Arc::from(id),
        _ => generate(),
    }
}

/// 将当前 request id 注入统一错误响应体（`{"request_id": "..."}`）。
///
/// 未在 [`scope`] 内时 no-op（响应体省略 `request_id` 字段，omitempty 语义）。
/// 供 warp 后置回填与测试共用；axum / actix 的错误体在前置渲染路径
/// （[`crate::error::GarrisonError::to_json_body`]）内读取 task-local，
/// 三框架终态输出形状一致。
pub fn inject_request_id_into_error_body(body: &mut serde_json::Value) {
    if let Some(id) = current() {
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                REQUEST_ID_BODY_FIELD.to_string(),
                serde_json::Value::String(id.to_string()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 合法入站 id 原样传播（不重新生成）。
    #[test]
    fn propagate_or_generate_valid_inbound_passthrough() {
        let id = propagate_or_generate(Some("550e8400-e29b-41d4-a716-446655440000"));
        assert_eq!(id.as_ref(), "550e8400-e29b-41d4-a716-446655440000");

        let custom = propagate_or_generate(Some("req-abc_123"));
        assert_eq!(custom.as_ref(), "req-abc_123");
    }

    /// 含 CRLF 的入站 id 必须被丢弃并重新生成（防 header/日志注入）。
    #[test]
    fn propagate_or_generate_crlf_inbound_regenerated() {
        let inbound = "id\r\nEvil: 1";
        let id = propagate_or_generate(Some(inbound));
        assert_ne!(id.as_ref(), inbound);
        assert!(
            uuid::Uuid::parse_str(&id).is_ok(),
            "重新生成的 id 应为合法 UUID，实际: {id}"
        );
    }

    /// 超长（> 128 字节）与非 ASCII 的入站 id 必须被丢弃并重新生成。
    #[test]
    fn propagate_or_generate_oversized_and_non_ascii_regenerated() {
        let oversized = "a".repeat(MAX_INBOUND_LEN + 1);
        let id = propagate_or_generate(Some(&oversized));
        assert_ne!(id.as_ref(), oversized);
        assert!(uuid::Uuid::parse_str(&id).is_ok());

        let non_ascii = "请求标识";
        let id = propagate_or_generate(Some(non_ascii));
        assert_ne!(id.as_ref(), non_ascii);
        assert!(uuid::Uuid::parse_str(&id).is_ok());

        // 控制字符与 DEL 同样被拒
        for bad in ["a\u{0}b", "a\u{7f}b", "a b"] {
            let id = propagate_or_generate(Some(bad));
            assert_ne!(id.as_ref(), bad, "非法 id {bad:?} 不应被传播");
            assert!(uuid::Uuid::parse_str(&id).is_ok());
        }
    }

    /// 入站为 None 时生成 UUID v4。
    #[test]
    fn propagate_or_generate_none_generates_uuid_v4() {
        let id = propagate_or_generate(None);
        let parsed = uuid::Uuid::parse_str(&id).expect("None 入站应生成合法 UUID");
        assert_eq!(parsed.get_version_num(), 4, "应为 UUID v4");
    }

    /// current() 在 scope 内返回 Some(同值)，scope 外返回 None。
    #[tokio::test]
    async fn current_visible_only_within_scope() {
        assert_eq!(current(), None, "scope 外 current() 应为 None");

        let id: Arc<str> = Arc::from("scope-test-id");
        let observed = scope(id.clone(), async { current() }).await;
        assert_eq!(observed.as_deref(), Some(id.as_ref()));

        assert_eq!(current(), None, "scope 结束后 current() 应恢复 None");
    }

    /// 连续 1e4 次生成无重复（UUID v4 碰撞概率可忽略）。
    #[test]
    fn generate_10k_times_no_duplicates() {
        let mut seen = std::collections::HashSet::with_capacity(10_000);
        for _ in 0..10_000 {
            assert!(seen.insert(generate()), "生成出重复 request id");
        }
        assert_eq!(seen.len(), 10_000);
    }

    /// is_valid_inbound_request_id 边界：127/128 合法，129 与空串非法。
    #[test]
    fn is_valid_inbound_request_id_boundaries() {
        assert!(!is_valid_inbound_request_id(""), "空串非法");
        assert!(is_valid_inbound_request_id(&"a".repeat(127)));
        assert!(is_valid_inbound_request_id(&"a".repeat(128)));
        assert!(!is_valid_inbound_request_id(&"a".repeat(129)), "超长非法");
        assert!(is_valid_inbound_request_id(
            "!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
        ));
    }

    /// inject_request_id_into_error_body：scope 内注入 request_id 字段。
    #[tokio::test]
    async fn inject_into_error_body_inside_scope() {
        let mut body = serde_json::json!({"error_code": "NOT_LOGIN"});
        let id: Arc<str> = Arc::from("inject-test-id");
        scope(id.clone(), async {
            inject_request_id_into_error_body(&mut body);
        })
        .await;
        assert_eq!(body["request_id"], "inject-test-id");
        assert_eq!(body["error_code"], "NOT_LOGIN", "既有字段不被覆盖");
    }

    /// inject_request_id_into_error_body：scope 外 no-op（字段省略）。
    #[test]
    fn inject_into_error_body_outside_scope_is_noop() {
        let mut body = serde_json::json!({"error_code": "NOT_LOGIN"});
        inject_request_id_into_error_body(&mut body);
        assert!(body.get(REQUEST_ID_BODY_FIELD).is_none());
    }

    /// RequestId 载体可比较且调试输出不 panic（供 Extension 注入使用）。
    #[test]
    fn request_id_wrapper_eq_and_debug() {
        let a = RequestId(Arc::from("x"));
        let b = a.clone();
        assert_eq!(a, b);
        assert!(format!("{a:?}").contains("x"));
    }
}
