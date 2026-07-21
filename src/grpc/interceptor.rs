//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! gRPC 鉴权拦截器实现。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 包含 `GarrisonGrpcInterceptor` 的构造、token 提取方法
//! 与 `tonic::Interceptor` trait 实现。
//!
//! ## 重要限制：仅校验 token 格式，不执行 async 鉴权
//!
//! `tonic::Interceptor::call` 是**同步** trait，无法直接调用异步的 `GarrisonUtil::check_login()`。
//! 本拦截器仅完成 token 提取与基本格式校验（非空、`Bearer ` 前缀正确），
//! **不**执行实际的登录态/权限校验。
//!
//! 实际的 async 鉴权应在 tonic service handler 内通过 `GarrisonContext`
//! 显式调用 `GarrisonUtil::check_login()` 完成，或使用 `tower::Layer` middleware。

use tonic::service::Interceptor;
use tonic::Status;

use super::GarrisonGrpcInterceptor;

impl GarrisonGrpcInterceptor {
    /// 创建新的 gRPC 鉴权拦截器实例。
    ///
    /// 拦截器无状态，可在多个 tonic Server 间共享（实现 `Clone`）。
    pub fn new() -> Self {
        Self
    }

    /// 从 tonic 请求 metadata 提取 Authorization Bearer token。
    ///
    /// # 参数
    /// - `metadata`: tonic 请求 metadata map
    ///
    /// # 返回
    /// - `Ok(token)`: 成功提取的 token 字符串（去除 `Bearer ` 前缀）
    /// - `Err(Status::UNAUTHENTICATED)`: 缺失 Authorization header 或格式不正确
    ///
    /// # 严格 Bearer 校验（RFC 7235）
    ///
    /// 仅接受 `Bearer <token>` 格式，scheme 大小写不敏感（`Bearer` / `bearer` / `BEARER`）。
    /// 不带 Bearer 前缀的裸 token 一律拒绝（避免将 Basic/Digest 凭证误认为 Bearer token）。
    #[allow(clippy::result_large_err)]
    pub fn extract_token(metadata: &tonic::metadata::MetadataMap) -> Result<String, Status> {
        // 从 metadata 提取 Authorization header（tonic metadata key 全小写）
        let auth_header = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing Authorization metadata"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Authorization metadata is not valid UTF-8"))?;

        // 严格 Bearer 前缀校验（RFC 7235: scheme 大小写不敏感）
        // 不接受裸 token：避免将 Basic/Digest 凭证误认为 Bearer token
        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .or_else(|| auth_header.strip_prefix("BEARER "))
            .ok_or_else(|| Status::unauthenticated("Authorization scheme must be Bearer"))?;

        if token.is_empty() {
            return Err(Status::unauthenticated("empty token after Bearer prefix"));
        }
        Ok(token.to_string())
    }
}

impl Interceptor for GarrisonGrpcInterceptor {
    #[allow(clippy::result_large_err)]
    fn call(&mut self, request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        // 仅校验 Authorization metadata 格式（Bearer 前缀 + 非空 token）
        // 实际登录态/权限校验须在 tonic service handler 内通过 GarrisonContext 异步完成
        let _token = Self::extract_token(request.metadata())?;
        Ok(request)
    }
}
