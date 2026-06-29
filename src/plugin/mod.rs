//! 插件模块，定义插件 trait 与编译期注册。
//!
//! [借鉴 Sa-Token] 通过 `inventory` crate 实现编译期插件注册（替代 Java SPI），
//! 插件在编译期通过 `inventory::submit!` 注册，运行期通过 `inventory::iter!` 收集。

use crate::error::BulwarkResult;

/// Bulwark 插件 trait，所有插件需实现此接口。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的插件机制，
/// 通过 `inventory` crate 在编译期自动注册，无需手动初始化。
pub trait BulwarkPlugin: Send + Sync {
    /// 插件名称，用于唯一标识。
    fn name(&self) -> &str {
        todo!()
    }

    /// 插件初始化，在框架启动时调用。
    fn init(&self) -> BulwarkResult<()> {
        todo!()
    }

    /// 插件销毁，在框架关闭时调用。
    fn destroy(&self) -> BulwarkResult<()> {
        todo!()
    }
}

/// 插件注册条目，用于 `inventory` 收集。
///
/// 通过 `inventory::submit!(PluginEntry { plugin: &MY_PLUGIN })` 注册插件，
/// 运行期通过 `inventory::iter::<PluginEntry>()` 遍历。
pub struct PluginEntry {
    /// 插件实例的静态引用。
    pub plugin: &'static (dyn BulwarkPlugin + Send + Sync),
}

// 编译期插件注册收集点
inventory::collect!(PluginEntry);
