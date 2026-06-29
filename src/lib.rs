//! # Bulwark
//!
//! Bulwark 是一个面向 Rust 生态的身份认证鉴权框架，借鉴 Sa-Token v1.45.0 的设计理念。
//!
//! ## 特性域
//!
//! Bulwark 借鉴 Sa-Token 的 13 个特性域设计：
//!
//! - **登录认证** - 基于 Token 的会话管理
//! - **权限认证** - RBAC 权限模型
//! - **Session 会话** - 会话生命周期管理
//! - **OAuth2** - 第三方授权
//! - **单点登录 (SSO)** - 跨系统统一登录
//! - **JWT** - JSON Web Token 支持
//! - **微服务网关鉴权** - 网关层签名认证
//! - **API 接口鉴权** - API Key 认证
//! - **TOTP 动态验证码** - 时间一次性密码
//! - **Basic 认证** - HTTP Basic Auth
//! - **Digest 认证** - HTTP Digest Auth
//! - **路由拦截鉴权** - Web 框架适配
//! - **插件化扩展** - 编译期插件注册
//!
//! ## 双抽象层
//!
//! - **dbnexus** - 数据库抽象层（SQLite / PostgreSQL / MySQL）
//! - **oxcache** - 缓存抽象层（Memory / Redis Cluster / Caffeine）
//!
//! ## 使用示例
//!
//! ```toml
//! [dependencies]
//! bulwark = { version = "0.1", features = ["web-axum", "protocol-jwt"] }
//! ```
//!
//! ```rust
//! use bulwark::prelude::*;
//!
//! // 通过 prelude 引入核心类型
//! // let _config: BulwarkConfig = BulwarkConfig::default();
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

// ====================================================================
// 核心模块（always on，无 feature flag）
// ====================================================================

/// 核心模块，包含认证、权限、Token 的核心抽象。
pub mod core;

/// Stp 模块，提供 BulwarkLogic / BulwarkInterface / BulwarkUtil。
pub mod stp;

/// 注解模块，定义鉴权注解枚举。
pub mod annotation;

/// 路由模块，提供路由器与拦截器抽象。
pub mod router;

/// DAO 模块，定义持久化数据访问抽象层。
pub mod dao;

/// 策略模块，提供鉴权策略与防火墙策略。
pub mod strategy;

/// 会话模块，提供 BulwarkSession 会话模型。
pub mod session;

/// 配置模块，提供 BulwarkConfig 全局配置。
pub mod config;

/// 上下文模块，提供请求/响应/存储上下文抽象。
pub mod context;

/// JSON 模块，提供 JSON 模板与序列化抽象。
pub mod json;

/// 异常模块，定义框架异常类型。
pub mod exception;

/// 管理器模块，提供全局管理器单例。
pub mod manager;

/// 插件模块，定义插件 trait 与编译期注册。
pub mod plugin;

// ====================================================================
// 可选模块（特性门控）
// ====================================================================

/// 监听器模块，提供事件监听抽象。
#[cfg(feature = "listener")]
pub mod listener;

/// 安全模块，提供 TOTP / 签名 / Basic / Digest 验证。
#[cfg(feature = "secure-totp")]
pub mod secure;

/// 协议层模块，包含各协议插件子模块。
#[cfg(any(
    feature = "protocol-oauth2",
    feature = "protocol-sso",
    feature = "protocol-jwt",
    feature = "protocol-sign",
    feature = "protocol-apikey",
    feature = "protocol-temp",
))]
pub mod protocol;

// ====================================================================
// 公共入口
// ====================================================================

/// 预导出模块，包含最常用的类型与 trait。
pub mod prelude;

/// 错误类型定义模块。
pub mod error;

// Re-export prelude 以便 `use bulwark::prelude::*;` 可用
pub use prelude::*;
