//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 预导出模块，包含最常用的类型与 trait。
//!
//! 通过 `use bulwark::prelude::*;` 快速引入框架核心类型。

/// 全局配置结构体（[BulwarkConfig]）。
pub use crate::config::BulwarkConfig;
/// 上下文类型：请求/响应/存储抽象（[BulwarkContext]、[BulwarkRequest]、[BulwarkResponse]、[BulwarkStorage]）。
pub use crate::context::{BulwarkContext, BulwarkRequest, BulwarkResponse, BulwarkStorage};
/// 鉴权决策与请求模型（[Decision]、[DecisionReason]、[AuthRequest]，）。
pub use crate::core::permission::{AuthRequest, Decision, DecisionReason};
/// DAO trait，持久化数据访问抽象（[BulwarkDao]）。
pub use crate::dao::BulwarkDao;
/// 错误类型与 Result 别名（[BulwarkError]、[BulwarkResult]）。
pub use crate::error::{BulwarkError, BulwarkResult};
/// 全局管理器单例（[BulwarkManager]）。
pub use crate::manager::BulwarkManager;
/// 插件 trait，编译期注册扩展点（[BulwarkPlugin]）。
pub use crate::plugin::BulwarkPlugin;
/// 路由器与拦截器抽象（[BulwarkRouter]、[BulwarkInterceptor]）。
pub use crate::router::{BulwarkInterceptor, BulwarkRouter};
/// 会话模型（[BulwarkSession]）。
pub use crate::session::BulwarkSession;
/// 逻辑层抽象与静态入口（[BulwarkInterface]、[BulwarkLogicDefault]、[BulwarkUtil] + 5 个子 trait）。
pub use crate::stp::{
    BulwarkCore, BulwarkInterface, BulwarkLogicDefault, BulwarkUtil, MfaLogic, PasswordLogic,
    PermissionLogic, SessionLogic, TokenLogic,
};
/// 防火墙策略（[BulwarkPermissionStrategy]、[BulwarkPermissionStrategyDefault]）。
pub use crate::strategy::{BulwarkPermissionStrategy, BulwarkPermissionStrategyDefault};
