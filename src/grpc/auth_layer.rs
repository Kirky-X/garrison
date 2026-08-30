//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! gRPC async 鉴权层（`GarrisonGrpcAuthLayer`）。
//!
//! 消除 [`super::GarrisonGrpcInterceptor`]「仅提取 token 不鉴权」的 footgun：
//! tower `Layer`/`Service` 形态支持 async `GarrisonUtil::check_login()`，
//! 失败以 `tonic::Status::UNAUTHENTICATED`（trailers-only 响应，经
//! `Status::into_http` 构造）拒绝，成功则把 token 注入 task_local
//! （`with_current_token`）后放行，handler 内可直接调用 `GarrisonUtil` API。

use crate::stp::{with_current_token, GarrisonUtil};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tonic::Status;
use tower::{Layer, Service};

/// gRPC async 鉴权层（`grpc` feature）。
///
/// 对每个请求：
/// 1. 从 `Authorization: Bearer <token>` 提取 token（复用拦截器的严格 Bearer 校验）；
/// 2. 缺失/格式错误/未登录/伪造 → `Status::unauthenticated` 拒绝（不再进入 handler）；
/// 3. 已登录 → 在 `with_current_token` 作用域内调用内层 service，
///    handler 内 `GarrisonUtil::check_login()` 等静态 API 可直接使用。
///
/// # 用法
/// ```ignore
/// use garrison::grpc::GarrisonGrpcAuthLayer;
/// let (mut health, health_sink) = tonic_health::pb::health_service();
/// let svc = GarrisonGrpcAuthLayer.layer(my_service);
/// Server::builder().add_service(svc).serve(addr).await?;
/// ```
///
/// # 已知限制（安全审查 S4）
///
/// 本层不注入客户端 IP（`with_current_ip`）：`firewall-bruteforce` 的 IP 级
/// 撞库计数/封禁在 gRPC 路径不生效（IP 由 HTTP 框架 middleware 注入）。
/// gRPC token 为高熵随机串，在线猜测不可行；如需 IP 级防护，请在 transport
/// 层提取对端地址后以 `garrison::stp::with_current_ip(ip, fut)` 包裹调用。
#[derive(Debug, Clone, Copy, Default)]
pub struct GarrisonGrpcAuthLayer;

impl<S> Layer<S> for GarrisonGrpcAuthLayer {
    type Service = GarrisonGrpcAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GarrisonGrpcAuthService { inner }
    }
}

/// [`GarrisonGrpcAuthLayer`] 产出的内层 service 包装。
#[derive(Debug, Clone)]
pub struct GarrisonGrpcAuthService<S> {
    inner: S,
}

impl<S> Service<http::Request<tonic::body::Body>> for GarrisonGrpcAuthService<S>
where
    S: Service<http::Request<tonic::body::Body>, Response = http::Response<tonic::body::Body>>
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        // 1. 提取 token（零克隆直读 HTTP 头，与拦截器共享 parse_bearer 单点逻辑；
        //    失败即拒绝，不进入 handler）
        let token =
            super::GarrisonGrpcInterceptor::extract_token_from_headers(request.headers()).ok();

        let Some(token) = token else {
            return Box::pin(async {
                Ok(Status::unauthenticated(
                    "garrison-auth-layer::missing-or-malformed-authorization",
                )
                .into_http())
            });
        };

        // 2. 内层 future 先创建（tower 惯例：call() 内即发起；tonic 内置
        //    Routes/Grpc 为 level-based ready 协议，无许可滞留问题。若在
        //    本层之外叠加容量型中间件如 ConcurrencyLimit，其 poll_ready
        //    预取的许可在拒绝路径会滞留至 service drop——性能审查 P1/A5 结论），
        //    鉴权与内层调用同处 `with_current_token` 作用域——handler 经
        //    task_local 看到当前 token，`GarrisonUtil` 静态 API 可直接使用。
        let response_fut = self.inner.call(request);
        Box::pin(with_current_token(token, async move {
            match GarrisonUtil::check_login().await {
                Ok(true) => response_fut.await,
                _ => Ok(
                    Status::unauthenticated("garrison-auth-layer::invalid-or-expired-token")
                        .into_http(),
                ),
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::GarrisonDao;
    use crate::manager::GarrisonManager;
    use crate::stp::mock::{MockDao, MockInterface};
    use http::Request;
    use serial_test::serial;
    use std::sync::Arc;
    use tower::{Service, ServiceExt};

    async fn init_global_manager() {
        GarrisonManager::reset_for_test();
        let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
        let mut config = crate::config::GarrisonConfig::default_config();
        config.throw_on_not_login = false;
        let interface: Arc<dyn crate::stp::GarrisonInterface> = Arc::new(MockInterface);
        GarrisonManager::builder()
            .dao(dao)
            .config(Arc::new(config))
            .interface(interface)
            .build()
            .await
            .unwrap();
    }

    /// handler 桩：回显当前作用域内 `check_login` 结果（验证 token 经 Layer 传播）。
    #[derive(Clone)]
    struct EchoLoginService;

    impl Service<http::Request<tonic::body::Body>> for EchoLoginService {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<tonic::body::Body>) -> Self::Future {
            Box::pin(async {
                let logged_in = GarrisonUtil::check_login().await.unwrap_or(false);
                let mut resp = http::Response::new(tonic::body::Body::empty());
                resp.extensions_mut().insert(logged_in);
                Ok(resp)
            })
        }
    }

    fn grpc_request(token: Option<&str>) -> http::Request<tonic::body::Body> {
        let mut builder = Request::builder()
            .method(http::Method::POST)
            .uri("/svc/method");
        if let Some(t) = token {
            builder = builder.header("authorization", format!("Bearer {t}"));
        }
        builder.body(tonic::body::Body::empty()).unwrap()
    }

    /// 断言响应为 UNAUTHENTICATED（grpc-status=16）。
    async fn assert_unauthenticated(resp: http::Response<tonic::body::Body>) {
        assert_eq!(
            resp.headers()
                .get(tonic::Status::GRPC_STATUS)
                .and_then(|v| v.to_str().ok()),
            Some("16"),
            "应返回 gRPC UNAUTHENTICATED（16），实际 headers: {:?}",
            resp.headers()
        );
    }

    /// ACC-GRPC-AUTH-001（异常）：无 Authorization metadata → UNAUTHENTICATED。
    #[tokio::test]
    #[serial]
    async fn auth_layer_missing_token_rejected() {
        init_global_manager().await;
        let mut svc = GarrisonGrpcAuthLayer.layer(EchoLoginService);
        let resp = svc
            .ready()
            .await
            .unwrap()
            .call(grpc_request(None))
            .await
            .unwrap();
        assert_unauthenticated(resp).await;
    }

    /// ACC-GRPC-AUTH-002（异常）：伪造（未登录）token → UNAUTHENTICATED。
    #[tokio::test]
    #[serial]
    async fn auth_layer_forged_token_rejected() {
        init_global_manager().await;
        let mut svc = GarrisonGrpcAuthLayer.layer(EchoLoginService);
        let resp = svc
            .ready()
            .await
            .unwrap()
            .call(grpc_request(Some("forged-token-not-in-session")))
            .await
            .unwrap();
        assert_unauthenticated(resp).await;
    }

    /// ACC-GRPC-AUTH-003（正常）：有效 token 放行，handler 内 check_login 为 true。
    #[tokio::test]
    #[serial]
    async fn auth_layer_valid_token_passes_and_propagates_token() {
        init_global_manager().await;
        let token = GarrisonUtil::login_simple("1001").await.unwrap();
        let mut svc = GarrisonGrpcAuthLayer.layer(EchoLoginService);
        let resp = svc
            .ready()
            .await
            .unwrap()
            .call(grpc_request(Some(&token)))
            .await
            .unwrap();
        assert!(
            resp.extensions().get::<bool>().copied().unwrap_or(false),
            "handler 应在 with_current_token 作用域内看到已登录 token"
        );
    }
}
