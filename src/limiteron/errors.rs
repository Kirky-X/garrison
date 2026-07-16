//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! limiteron 适配器的错误映射工具。
//!
//! 将 `BulwarkError` 桥接到 limiteron 的 `StorageError` / `LimiteronError`，
//! 供 storage / quota / distributed / ban 子模块共用。

use crate::error::BulwarkError;
use limiteron::error::{LimiteronError, StorageError};

/// 将 `BulwarkError` 映射为 `StorageError`。
pub(super) fn map_to_storage_err(e: BulwarkError) -> StorageError {
    StorageError::QueryError(format!("{}", e))
}

/// 将 `BulwarkError` 映射为 `LimiteronError`。
pub(super) fn map_to_limiter_err(e: BulwarkError) -> LimiteronError {
    LimiteronError::StorageError(StorageError::QueryError(format!("{}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// map_to_storage_err 和 map_to_limiter_err 正确映射错误。
    #[test]
    fn error_mapping_functions_correct() {
        let err1 = BulwarkError::Dao("test error".to_string());
        let storage_err = map_to_storage_err(err1);
        let storage_msg = format!("{}", storage_err);
        assert!(storage_msg.contains("test error"));

        let err2 = BulwarkError::Dao("test error".to_string());
        let limiter_err = map_to_limiter_err(err2);
        let limiter_msg = format!("{}", limiter_err);
        assert!(limiter_msg.contains("test error"));
    }
}
