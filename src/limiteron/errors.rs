// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! limiteron 适配器的错误映射工具。
//!
//! 将 `GarrisonError` 桥接到 limiteron 的 `StorageError` / `LimiteronError`，
//! 供 storage / quota / distributed / ban 子模块共用。

use crate::error::GarrisonError;
use limiteron::error::{LimiteronError, StorageError};

/// 将 `GarrisonError` 映射为 `StorageError`。
///
/// # 错误链保留
///
/// `StorageError::QueryError` 仅携带 `String`（无 source 字段），无法结构化
/// 包装原错误。为弥补直接 `format!("{}", e)` 丢失类型信息的问题（调用方无法
/// 按变体匹配/调试困难），消息前缀附上原错误的 `Debug` 表示（含变体名与负载），
/// 后接 `Display` 文本（i18n 翻译），错误源类型与内容均可从消息恢复。
pub(super) fn map_to_storage_err(e: GarrisonError) -> StorageError {
    StorageError::QueryError(format!("garrison-error[{:?}]::{}", e, e))
}

/// 将 `GarrisonError` 映射为 `LimiteronError`。
///
/// 错误链保留策略见 [`map_to_storage_err`]。
pub(super) fn map_to_limiter_err(e: GarrisonError) -> LimiteronError {
    LimiteronError::StorageError(StorageError::QueryError(format!(
        "garrison-error[{:?}]::{}",
        e, e
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// map_to_storage_err 和 map_to_limiter_err 正确映射错误。
    #[test]
    fn error_mapping_functions_correct() {
        let err1 = GarrisonError::Dao("test error".to_string());
        let storage_err = map_to_storage_err(err1);
        let storage_msg = format!("{}", storage_err);
        assert!(storage_msg.contains("test error"));

        let err2 = GarrisonError::Dao("test error".to_string());
        let limiter_err = map_to_limiter_err(err2);
        let limiter_msg = format!("{}", limiter_err);
        assert!(limiter_msg.contains("test error"));
    }

    /// 映射保留错误源信息：消息含原错误变体的 Debug 表示（可恢复变体类型）。
    #[test]
    fn error_mapping_preserves_source_variant() {
        let storage_msg = format!("{}", map_to_storage_err(GarrisonError::Dao("x".into())));
        assert!(
            storage_msg.contains("garrison-error[Dao("),
            "消息应含 Debug 变体名前缀，实际: {}",
            storage_msg
        );

        let limiter_msg = format!(
            "{}",
            map_to_limiter_err(GarrisonError::NotImplemented("y".into()))
        );
        assert!(
            limiter_msg.contains("garrison-error[NotImplemented("),
            "消息应含 Debug 变体名前缀，实际: {}",
            limiter_msg
        );
    }
}
