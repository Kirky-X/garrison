//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! GarrisonCore base trait — 所有子 trait 的基础。
use super::GarrisonLogicDefault;
use crate::config::GarrisonConfig;
use std::sync::Arc;

/// 核心 base trait，提供配置访问能力。
///
/// 所有子 trait（SessionLogic/PermissionLogic/TokenLogic/MfaLogic/PasswordLogic）
/// 均以此为 super-trait（直接或间接），共享 `config()` 方法。
///
/// # 对象安全
///
/// 本 trait 仅含同步方法 `config()`，对象安全，可作为 `dyn GarrisonCore` 使用。
pub trait GarrisonCore: Send + Sync {
    /// 获取当前 `GarrisonConfig` 引用（用于 token 提取、Cookie 配置等需要配置的场景）。
    ///
    /// # 返回
    /// 全局配置的 `Arc` 引用。
    fn config(&self) -> Arc<GarrisonConfig>;
}

// ============================================================================
// GarrisonLogicDefault impl
// ============================================================================

impl GarrisonCore for GarrisonLogicDefault {
    fn config(&self) -> Arc<GarrisonConfig> {
        Arc::clone(&self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCore {
        config: Arc<GarrisonConfig>,
    }

    impl GarrisonCore for MockCore {
        fn config(&self) -> Arc<GarrisonConfig> {
            Arc::clone(&self.config)
        }
    }

    #[test]
    fn garrison_core_can_be_implemented() {
        let config = Arc::new(GarrisonConfig::default());
        let mock = MockCore {
            config: Arc::clone(&config),
        };
        let retrieved = mock.config();
        assert!(Arc::ptr_eq(&retrieved, &config));
    }
}
