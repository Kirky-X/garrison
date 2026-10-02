// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 回环传输层抗抖动发送扩展（仅验收测试使用；产品代码禁止依赖）。
//!
//! 部分虚拟化环境（Docker Desktop 的 WSL2 回环中继）会以低概率截断回环
//! HTTP 连接——客户端侧表现为 `IncompleteMessage` / send error，与负载、
//! 连接复用方式无关（裸 TCP 300 连发与本仓库同栈复现实验均无法稳定复现，
//! 仅长程验收套件中偶发）。CI（GitHub runner）与裸机环境不受影响。
//!
//! [`SendRelayRetry::send_relay_retry`] 对传输层错误做有界重试（≤3 次，
//! 100ms 退避）；任何已收到的响应（含 4xx/5xx）原样返回——业务状态码
//! 断言语义完全不变，重试路径仅在传输抖动时触发。

/// 回环中继抗抖动发送。
pub(crate) trait SendRelayRetry {
    /// 有界重试地发送请求。
    fn send_relay_retry(
        self,
    ) -> impl std::future::Future<Output = reqwest::Result<reqwest::Response>> + Send;
}

impl SendRelayRetry for reqwest::RequestBuilder {
    fn send_relay_retry(
        self,
    ) -> impl std::future::Future<Output = reqwest::Result<reqwest::Response>> + Send {
        Box::pin(async move {
            const MAX_ATTEMPTS: u32 = 3;
            for attempt in 1..=MAX_ATTEMPTS {
                match self
                    .try_clone()
                    .expect("验收请求体应为内存缓冲（JSON/文本），可克隆")
                    .send()
                    .await
                {
                    Ok(resp) => return Ok(resp),
                    Err(e)
                        if attempt < MAX_ATTEMPTS
                            && (e.is_request() || e.is_connect() || e.is_timeout()) =>
                    {
                        eprintln!(
                            "[relay-retry] 回环传输抖动（第 {attempt} 次），100ms 后重试: {e}"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    },
                    Err(e) => return Err(e),
                }
            }
            unreachable!("重试循环恒在 MAX_ATTEMPTS 内返回")
        })
    }
}
