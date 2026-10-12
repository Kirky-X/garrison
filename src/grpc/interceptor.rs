// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! gRPC 鉴权拦截器实现：`GarrisonGrpcInterceptor` 的构造、token 提取与 `tonic::Interceptor` trait 实现。
//!
//! `tonic::Interceptor::call` 是**同步** trait，无法调用异步 `check_login()`：`new()` 仅做 token
//! 提取与格式校验（RFC 7235 大小写不敏感 Bearer、非空、≤4KB）并注入 `GarrisonGrpcToken`；
//! `with_token_validator()` 注入同步校验器后可完成真实鉴权，async 全量鉴权请用
//! `GarrisonGrpcAuthLayer`（tower Layer，async `check_login` + task_local 注入）。

use tonic::service::Interceptor;
use tonic::Status;

use super::{GarrisonGrpcInterceptor, GarrisonGrpcToken, GarrisonGrpcTokenValidator};

/// Bearer token 最大长度（字节）：超长 `Authorization` 头会产生无界堆分配并放大查找开销，4KB 对合法 token 余量充足。
pub const MAX_TOKEN_LEN: usize = 4096;

impl GarrisonGrpcInterceptor {
    /// 创建仅做 Bearer 格式校验（无真实鉴权）的拦截器，可在多个 tonic Server 间共享（`Clone`）。
    /// 同步真实鉴权见 [`Self::with_token_validator`]；async 全量鉴权用 [`GarrisonGrpcAuthLayer`](super::GarrisonGrpcAuthLayer)。
    pub fn new() -> Self {
        Self { validator: None }
    }

    /// 创建带**同步 token 校验器**的拦截器：每请求调用 `validator.validate(&token)`，失败即以对应 `Status` 拒绝。
    pub fn with_token_validator(validator: std::sync::Arc<dyn GarrisonGrpcTokenValidator>) -> Self {
        Self {
            validator: Some(validator),
        }
    }

    /// 从 tonic 请求 metadata 提取 Authorization Bearer token（RFC 7235）。
    ///
    /// 仅接受 `Bearer <token>`（scheme 大小写不敏感，token 长度 ≤ [`MAX_TOKEN_LEN`]，裸 token 一律
    /// 拒绝避免将 Basic/Digest 凭证误认为 Bearer）；缺失 header 或格式不正确返回 `Status::UNAUTHENTICATED`。
    #[allow(clippy::result_large_err)]
    pub fn extract_token(metadata: &tonic::metadata::MetadataMap) -> Result<String, Status> {
        // tonic metadata key 全小写
        let auth_header = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing Authorization metadata"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Authorization metadata is not valid UTF-8"))?;

        Self::parse_bearer(auth_header)
    }

    /// [`Self::extract_token`] 的零克隆 HTTP 头版本：gRPC metadata 即 HTTP/2 headers（头名已小写），
    /// 直读 `http::HeaderMap` 避免 auth layer 热路径整体克隆。
    #[allow(clippy::result_large_err)]
    pub fn extract_token_from_headers(headers: &http::HeaderMap) -> Result<String, Status> {
        let auth_header = headers
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing Authorization metadata"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Authorization metadata is not valid UTF-8"))?;

        Self::parse_bearer(auth_header)
    }

    /// 严格 Bearer 前缀校验核心（RFC 7235）：scheme 按前 7 字节做 ASCII 大小写不敏感比较
    /// （`Bearer` / `bEaReR` 等均可），第 8 字节必须为空格；拒绝裸 token（防 Basic/Digest 误认），
    /// 超过 [`MAX_TOKEN_LEN`] 直接拒绝（防无界分配）。
    #[allow(clippy::result_large_err)]
    fn parse_bearer(auth_header: &str) -> Result<String, Status> {
        // RFC 7235 §2：scheme 大小写不敏感，前 7 字节（"Bearer " 含空格）ASCII 不敏感比较
        let token = auth_header
            .get(..7)
            .filter(|prefix| prefix.eq_ignore_ascii_case("Bearer "))
            .map(|_| &auth_header[7..])
            .ok_or_else(|| Status::unauthenticated("Authorization scheme must be Bearer"))?;

        if token.is_empty() {
            return Err(Status::unauthenticated("empty token after Bearer prefix"));
        }
        if token.len() > MAX_TOKEN_LEN {
            return Err(Status::unauthenticated("token exceeds maximum length"));
        }
        Ok(token.to_string())
    }
}

impl Interceptor for GarrisonGrpcInterceptor {
    #[allow(clippy::result_large_err)]
    fn call(&mut self, mut request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        let token = Self::extract_token(request.metadata())?;

        // token 存入 extensions 供 handler 经 `request.extensions().get::<GarrisonGrpcToken>()` 读取
        request
            .extensions_mut()
            .insert(GarrisonGrpcToken(token.clone()));

        // 同步 trait 无法 await check_login()：配置校验器时在此真实鉴权（失败即拒绝），async 校验用 [`GarrisonGrpcAuthLayer`]。
        if let Some(validator) = &self.validator {
            validator.validate(&token)?;
        } else {
            tracing::debug!(
                "garrison grpc interceptor: no token validator configured; \
                 only Bearer format is enforced here"
            );
        }
        Ok(request)
    }
}
