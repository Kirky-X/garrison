//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 自定义配置源（从已读取的 TOML 内容注入配置值）。
//!
//! 独立模块原因（规则 25 mod/crate 接口隔离）：`TomlContentSource` 是配置源实现，
//! 与 `GarrisonConfig` 的 impl 块关注点不同，拆分到独立文件便于未来扩展更多自定义 Source。

use confers::config::{Source, SourceKind};
use confers::loader::{parse_content, Format};
use confers::types::{AnnotatedValue, SourceId};
use std::path::PathBuf;

/// 从 path 的 `file_name()` 提取名称，失败时返回 None（DRY 重构，规则 9）。
///
/// 用于 `TomlContentSource::new` 和 `name()`，避免重复 `path.as_ref().and_then(...)` 链。
fn path_name(path: &Option<PathBuf>) -> Option<&str> {
    path.as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
}

/// 从已读取的 TOML 内容注入配置值的自定义 Source。
///
/// **设计原因**：confers 0.4.1 的 `FileSource` 在 `check_path_components()` 中
/// 无条件拒绝 `Component::Prefix`（Windows 驱动器号 `C:`），而 `allow_absolute_paths()`
/// 仅放行 `Component::RootDir`，无法放行带驱动器号的 Windows 绝对路径。此 Source
/// 直接接收已读取的 TOML 内容，绕过路径验证，使 Windows 上 `C:\path\to\config.toml`
/// 等绝对路径可正常加载（跨平台一致行为）。
///
/// 使用 confers 公共 API（`parse_content` + `Source` trait），不依赖内部实现。
///
/// # Security
///
/// `path` 字段仅用于错误定位和 source_id 生成，不再触发文件 I/O。
/// 文件读取与安全校验（路径遍历、大小限制、特殊文件拒绝）由 `GarrisonConfig::load` 负责。
#[derive(Debug)]
pub(super) struct TomlContentSource {
    /// 已读取的 TOML 文件内容。
    content: String,
    /// 优先级（与 FileSource::with_priority 语义一致）。
    priority: u8,
    /// 源 ID（用于追踪配置来源，从 path.file_name() 生成）。
    source_id: SourceId,
    /// 缓存的 name（从 path.file_name() 生成，避免 name() 重复计算）。
    name: String,
    /// 原始文件路径（用于错误定位和调试，可选）。
    path: Option<PathBuf>,
}

impl TomlContentSource {
    /// 创建新的 TomlContentSource。
    ///
    /// # 参数
    /// - `content`: 已读取的 TOML 文件内容
    /// - `path`: 原始文件路径（可选，用于 source_id 生成和错误定位）
    pub(super) fn new(content: String, path: Option<PathBuf>) -> Self {
        let name = path_name(&path).unwrap_or("toml-content").to_string();
        let source_id = SourceId::new(name.as_str());
        Self {
            content,
            priority: 0,
            source_id,
            name,
            path,
        }
    }

    /// 设置优先级（与 FileSource::with_priority 语义一致）。
    pub(super) fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }
}

impl Source for TomlContentSource {
    fn collect(&self) -> confers::ConfigResult<AnnotatedValue> {
        parse_content(
            &self.content,
            Format::Toml,
            self.source_id.clone(),
            self.path.as_deref(),
        )
        .map(|v| v.with_priority(self.priority))
    }

    fn priority(&self) -> u8 {
        self.priority
    }

    fn name(&self) -> &str {
        &self.name
    }

    /// 返回 `SourceKind::Memory`（非 `File`），因为此 Source 从内存字符串注入，
    /// 不再触发文件 I/O（文件已在 `GarrisonConfig::load` 中读取）。
    fn source_kind(&self) -> SourceKind {
        SourceKind::Memory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 collect() 对合法 TOML 返回正确的 AnnotatedValue（含 priority）。
    #[test]
    fn collect_parses_valid_toml() {
        let source = TomlContentSource::new(
            r#"token_style = "jwt"
timeout = 1800"#
                .to_string(),
            None,
        )
        .with_priority(10);
        let result = source.collect().expect("合法 TOML 应解析成功");
        assert_eq!(result.priority, 10);
        assert!(result.is_map(), "TOML 顶层应为 map");
    }

    /// 验证 with_priority() 与 priority() 一致。
    #[test]
    fn with_priority_sets_priority() {
        let source = TomlContentSource::new(String::new(), None);
        assert_eq!(source.priority(), 0);
        let source = source.with_priority(42);
        assert_eq!(source.priority(), 42);
    }

    /// 验证 collect() 对非法 TOML 错误正确传播（不吞错，规则 12）。
    #[test]
    fn collect_propagates_parse_error() {
        let source = TomlContentSource::new("this is not = valid = toml".to_string(), None);
        let result = source.collect();
        assert!(result.is_err(), "非法 TOML 应返回 Err");
    }

    /// 验证 source_kind() 返回 Memory（非 File），因为内容已在内存中。
    #[test]
    fn source_kind_is_memory() {
        let source = TomlContentSource::new(String::new(), None);
        assert_eq!(source.source_kind(), SourceKind::Memory);
    }

    /// 验证 name() 和 source_id 从 path.file_name() 生成（多实例可区分）。
    #[test]
    fn name_and_source_id_derived_from_path() {
        let path = PathBuf::from("/some/dir/my-config.toml");
        let source = TomlContentSource::new(String::new(), Some(path));
        assert_eq!(source.name(), "my-config.toml");
        assert_eq!(source.source_id.as_str(), "my-config.toml");
    }

    /// 验证 path=None 时 name() 和 source_id 回退到 "toml-content"。
    #[test]
    fn name_fallback_when_path_none() {
        let source = TomlContentSource::new(String::new(), None);
        assert_eq!(source.name(), "toml-content");
        assert_eq!(source.source_id.as_str(), "toml-content");
    }
}
