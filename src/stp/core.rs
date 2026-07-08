//! BulwarkCore base trait — 所有子 trait 的基础。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use super::BulwarkLogicDefault;
use crate::config::BulwarkConfig;
use std::sync::Arc;

/// 核心 base trait，提供配置访问能力。
///
/// 所有子 trait（SessionLogic/PermissionLogic/TokenLogic/MfaLogic/PasswordLogic）
/// 均以此为 super-trait（直接或间接），共享 `config()` 方法。
///
/// # 对象安全
///
/// 本 trait 仅含同步方法 `config()`，对象安全，可作为 `dyn BulwarkCore` 使用。
pub trait BulwarkCore: Send + Sync {
    /// 获取当前 `BulwarkConfig` 引用（用于 token 提取、Cookie 配置等需要配置的场景）。
    ///
    /// # 返回
    /// 全局配置的 `Arc` 引用。
    fn config(&self) -> Arc<BulwarkConfig>;
}

// ============================================================================
// BulwarkLogicDefault impl
// ============================================================================

impl BulwarkCore for BulwarkLogicDefault {
    fn config(&self) -> Arc<BulwarkConfig> {
        Arc::clone(&self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCore {
        config: Arc<BulwarkConfig>,
    }

    impl BulwarkCore for MockCore {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[test]
    fn bulwark_core_can_be_implemented() {
        let config = Arc::new(BulwarkConfig::default());
        let mock = MockCore {
            config: Arc::clone(&config),
        };
        let retrieved = mock.config();
        assert!(Arc::ptr_eq(&retrieved, &config));
    }
}
