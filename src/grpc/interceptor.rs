//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! gRPC 鉴权拦截器实现。
//!
//! 从 `mod.rs` 迁移而出（mod.rs 接口隔离）。
//! 包含 `GarrisonGrpcInterceptor` 的构造、token 提取方法
//! 与 `tonic::Interceptor` trait 实现。
//!
//! ## 鉴权语义
//!
//! `tonic::Interceptor::call` 是**同步** trait，无法直接调用异步的
//! `GarrisonUtil::check_login()`。默认构造（`new()`）仅完成 token 提取与
//! 格式校验（RFC 7235 大小写不敏感 Bearer 前缀、非空、≤4KB），并把 token
//! 注入 request extensions（`GarrisonGrpcToken`）；
//! 通过 `with_token_validator()` 注入同步校验器后可在拦截器内完成真实鉴权。
//!
//! 实际的 async 鉴权应在 tonic service handler 内通过 `GarrisonContext`
//! 显式调用 `GarrisonUtil::check_login()` 完成，或使用 `GarrisonGrpcAuthLayer`
//! （tower Layer middleware，async `check_login` + task_local 注入）。

use tonic::service::Interceptor;
use tonic::Status;

use super::{GarrisonGrpcInterceptor, GarrisonGrpcToken, GarrisonGrpcTokenValidator};

/// Bearer token 最大长度（字节）。
///
/// 超长 `Authorization` 头会在提取后产生无界堆分配并放大后续查找开销
/// ，4KB 对合法 access token 而言余量充足。
pub const MAX_TOKEN_LEN: usize = 4096;

impl GarrisonGrpcInterceptor {
    /// 创建新的 gRPC 鉴权拦截器实例（仅 Bearer 格式校验，无真实鉴权）。
    ///
    /// 拦截器可在多个 tonic Server 间共享（实现 `Clone`）。
    /// 需要同步真实鉴权请改用 [`Self::with_token_validator`]；
    /// 需要 async 全量鉴权请使用 [`GarrisonGrpcAuthLayer`](super::GarrisonGrpcAuthLayer)。
    pub fn new() -> Self {
        Self { validator: None }
    }

    /// 创建带**同步 token 校验器**的拦截器（真实鉴权扩展点）。
    ///
    /// 每个请求提取 token 后调用 `validator.validate(&token)`，
    /// 失败即以对应 `Status` 拒绝（不进入 handler）。
    pub fn with_token_validator(validator: std::sync::Arc<dyn GarrisonGrpcTokenValidator>) -> Self {
        Self {
            validator: Some(validator),
        }
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
    /// 仅接受 `Bearer <token>` 格式，scheme 大小写不敏感（任意大小写组合均可），
    /// token 长度 ≤ [`MAX_TOKEN_LEN`]。
    /// 不带 Bearer 前缀的裸 token 一律拒绝（避免将 Basic/Digest 凭证误认为 Bearer token）。
    #[allow(clippy::result_large_err)]
    pub fn extract_token(metadata: &tonic::metadata::MetadataMap) -> Result<String, Status> {
        // 从 metadata 提取 Authorization header（tonic metadata key 全小写）
        let auth_header = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing Authorization metadata"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Authorization metadata is not valid UTF-8"))?;

        Self::parse_bearer(auth_header)
    }

    /// [`Self::extract_token`] 的零克隆 HTTP 头版本（性能审查 P1）。
    ///
    /// gRPC metadata 即 HTTP/2 headers（头名已小写），从 `http::HeaderMap`
    /// 直接提取可避免 auth layer 热路径上的 `HeaderMap` 整体克隆。
    /// Bearer 解析逻辑与本方法共享 `parse_bearer` 单点实现（私有助手）。
    #[allow(clippy::result_large_err)]
    pub fn extract_token_from_headers(headers: &http::HeaderMap) -> Result<String, Status> {
        let auth_header = headers
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing Authorization metadata"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Authorization metadata is not valid UTF-8"))?;

        Self::parse_bearer(auth_header)
    }

    /// 严格 Bearer 前缀校验核心（RFC 7235: scheme 大小写不敏感）。
    ///
    /// scheme 按前 7 字节做 ASCII 大小写不敏感比较（`Bearer` / `bearer` /
    /// `bEaReR` 等任意大小写组合均接受），第 8 字节必须为空格。
    /// 不接受裸 token：避免将 Basic/Digest 凭证误认为 Bearer token。
    /// 超过 [`MAX_TOKEN_LEN`] 的 token 直接拒绝（防无界分配）。
    #[allow(clippy::result_large_err)]
    fn parse_bearer(auth_header: &str) -> Result<String, Status> {
        // RFC 7235 §2: scheme 大小写不敏感——对前 7 字节（"Bearer " 含空格）做
        // ASCII 不敏感比较，不再枚举三种硬编码大小写
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
        // 提取并校验 Authorization metadata（Bearer 前缀 + 非空 + 长度上限）
        let token = Self::extract_token(request.metadata())?;

        // 认证上下文注入：token 存入 request extensions，
        // handler 可通过 `request.extensions().get::<GarrisonGrpcToken>()` 读取，
        // 不再"提取即弃"。
        request
            .extensions_mut()
            .insert(GarrisonGrpcToken(token.clone()));

        // 真实鉴权扩展点：`Interceptor::call` 为同步 trait，
        // 无法 await `GarrisonUtil::check_login()`。配置了同步校验器时在此完成
        // 真实鉴权（失败 → UNAUTHENTICATED，不进入 handler）；需要 async 校验
        // 请使用 [`GarrisonGrpcAuthLayer`]（tower Layer，内部执行 check_login）。
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
