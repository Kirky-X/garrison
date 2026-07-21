//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 预导出模块，包含最常用的类型与 trait。
//!
//! 通过 `use garrison::prelude::*;` 快速引入框架核心类型。

/// 全局配置结构体（[GarrisonConfig]）。
pub use crate::config::GarrisonConfig;
/// 上下文类型：请求/响应/存储抽象（[GarrisonContext]、[GarrisonRequest]、[GarrisonResponse]、[GarrisonStorage]）。
pub use crate::context::{GarrisonContext, GarrisonRequest, GarrisonResponse, GarrisonStorage};
/// 鉴权决策与请求模型（[Decision]、[DecisionReason]、[AuthRequest]，）。
pub use crate::core::permission::{AuthRequest, Decision, DecisionReason};
/// DAO trait，持久化数据访问抽象（[GarrisonDao]）。
pub use crate::dao::GarrisonDao;
/// 错误类型与 Result 别名（[GarrisonError]、[GarrisonResult]）。
pub use crate::error::{GarrisonError, GarrisonResult};
/// 全局管理器单例（[GarrisonManager]）。
pub use crate::manager::GarrisonManager;
/// 插件 trait，编译期注册扩展点（[GarrisonPlugin]）。
pub use crate::plugin::GarrisonPlugin;
/// 路由器与拦截器抽象（[GarrisonRouter]、[GarrisonInterceptor]）。
pub use crate::router::{GarrisonInterceptor, GarrisonRouter};
/// 会话模型（[GarrisonSession]）。
pub use crate::session::GarrisonSession;
/// 逻辑层抽象与静态入口（[GarrisonInterface]、[GarrisonLogicDefault]、[GarrisonUtil] + 5 个子 trait）。
pub use crate::stp::{
    GarrisonCore, GarrisonInterface, GarrisonLogicDefault, GarrisonUtil, MfaLogic, PasswordLogic,
    PermissionLogic, SessionLogic, TokenLogic,
};
/// 防火墙策略（[GarrisonPermissionStrategy]、[GarrisonPermissionStrategyDefault]）。
pub use crate::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};
