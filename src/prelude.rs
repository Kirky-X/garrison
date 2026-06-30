//! 预导出模块，包含最常用的类型与 trait。
//!
//! 通过 `use bulwark::prelude::*;` 快速引入框架核心类型。

/// 全局配置结构体（[BulwarkConfig]）。
pub use crate::config::BulwarkConfig;
/// 上下文类型：请求/响应/存储抽象（[BulwarkContext]、[BulwarkRequest]、[BulwarkResponse]、[BulwarkStorage]）。
pub use crate::context::{BulwarkContext, BulwarkRequest, BulwarkResponse, BulwarkStorage};
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
/// 逻辑层抽象与静态入口（[BulwarkInterface]、[BulwarkLogic]、[BulwarkUtil]）。
pub use crate::stp::{BulwarkInterface, BulwarkLogic, BulwarkUtil};
/// 鉴权策略与防火墙策略（[BulwarkStrategy]、[BulwarkFirewallStrategy]、[BulwarkFirewallStrategyDefault]）。
pub use crate::strategy::{
    BulwarkFirewallStrategy, BulwarkFirewallStrategyDefault, BulwarkStrategy,
};
