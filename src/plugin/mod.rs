//! 插件模块，定义插件 trait 与编译期注册。
//!
//! [借鉴 Sa-Token] 通过 `inventory` crate 实现编译期插件注册（替代 Java SPI），
//! 插件在编译期通过 `inventory::submit!` 注册，运行期通过 `inventory::iter!` 收集。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

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

#[cfg(test)]
mod tests {
    use super::*;

    /// 占位实现结构体，仅用于触发 trait 默认方法的 todo!() panic。
    ///
    /// 空结构体自动实现 `Send + Sync`，满足 `BulwarkPlugin: Send + Sync` 约束。
    struct DummyPlugin;

    impl BulwarkPlugin for DummyPlugin {}

    /// 验证 `BulwarkPlugin::name` 默认实现调用 `todo!()` 必 panic。
    /// Rust `todo!()` panic 消息为 "not yet implemented: ..."。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn plugin_name_panics_with_todo() {
        let plugin = DummyPlugin;
        let _ = plugin.name();
    }

    /// 验证 `BulwarkPlugin::init` 默认实现调用 `todo!()` 必 panic。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn plugin_init_panics_with_todo() {
        let plugin = DummyPlugin;
        let _ = plugin.init();
    }

    /// 验证 `BulwarkPlugin::destroy` 默认实现调用 `todo!()` 必 panic。
    #[test]
    #[should_panic(expected = "not yet implemented")]
    fn plugin_destroy_panics_with_todo() {
        let plugin = DummyPlugin;
        let _ = plugin.destroy();
    }
}
