//! 预导出模块，包含最常用的类型与 trait。
//!
//! 通过 `use bulwark::prelude::*;` 快速引入框架核心类型。

pub use crate::config::BulwarkConfig;
pub use crate::context::{BulwarkContext, BulwarkRequest, BulwarkResponse, BulwarkStorage};
pub use crate::dao::BulwarkDao;
pub use crate::error::{BulwarkError, BulwarkResult};
pub use crate::manager::BulwarkManager;
pub use crate::plugin::BulwarkPlugin;
pub use crate::router::{BulwarkInterceptor, BulwarkRouter};
pub use crate::session::BulwarkSession;
pub use crate::stp::{BulwarkInterface, BulwarkLogic, BulwarkUtil};
pub use crate::strategy::{BulwarkFirewallStrategy, BulwarkStrategy};
