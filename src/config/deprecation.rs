// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 弃用配置键注册表：0.x → 1.0 平滑升级，配置键改名/移除经加载期显性化（不依赖 serde 静默忽略未知键）。
//!
//! 可自动映射键（`auto_map`/`map_fn`）：`< 1.0.0` 时迁移旧值到新键并 warn（含 since 版本与新键名）；不可映射键：`< 1.0.0` warn 迁移指引后放行（显性降级），`>= 1.0.0` 返回 [`GarrisonError::Config`](crate::error::GarrisonError::Config) 强制迁移。
//! 挂点：[`GarrisonConfig::load`](super::GarrisonConfig::load) 经 confers `ConfigBuilder::map_json`，在合并树反序列化前、`validate()` 前执行（不修改 confers 加载机制）。
//! 键格式：点号分隔逻辑路径（扁平键与嵌套段键统一表示）；env 经 `GARRISON_` 前缀 + `__` 分隔折叠后等价。

use serde_json::Value;

/// 旧值 → 新值转换函数类型（`map_fn` 字段的签名；转换失败以 `Err` 拒绝迁移）。
pub type DeprecationMapper = fn(&Value) -> Result<Value, String>;

/// 单条弃用键注册项：`since_version` 仅用于日志/错误指引，不参与 1.0 门判定（门只看当前版本）；`new_key` 为迁移目标（彻底移除填空串）。
///
/// `auto_map` 与 `map_fn` 组合语义：`map_fn = Some(f)` 存在即可迁移（等价 auto_map=true，注册建议直接写 `auto_map = true` 避免歧义）；`auto_map = true, map_fn = None` 旧值原样搬迁；两者皆无则不可自动映射；`map_fn` 返回 `Err` 表示值无法迁移（加载失败，错误显性化）。
#[derive(Debug, Clone, Copy)]
pub struct Deprecation {
    /// 弃用键（点号分隔逻辑路径）。
    pub key: &'static str,
    /// 弃用起始版本（SemVer 字符串）。
    pub since_version: &'static str,
    /// 迁移目标键（彻底移除的键填空串）。
    pub new_key: &'static str,
    /// 是否允许加载期自动迁移。
    pub auto_map: bool,
    /// 旧值 → 新值转换函数。
    pub map_fn: Option<DeprecationMapper>,
}

impl Deprecation {
    /// 该键是否可自动迁移（`auto_map` 或存在 `map_fn` 任一成立即可）。
    pub fn is_mappable(&self) -> bool {
        self.auto_map || self.map_fn.is_some()
    }
}

/// 生产弃用键注册表。
///
/// 唯一条目 `waf_config`：web-waf 门控的 `waf_config: WafConfig` 字段于 0.9.0 feature 重组中移除（CHANGELOG 只记录引入未记录移除），存量 toml 的 `[waf_config]` 升级后会被 serde 静默忽略、WAF 防护无提示消失——登记以显性化该失效模式。
/// 无单一继任键：防护配置由 `firewall-waf` 的 `waf_*` 平铺键按新语义重建，故 `new_key = ""` 且不可自动映射。
///
/// 后续配置键级弃用登记于此，并同步 `docs/CONFIGURATION.md` 弃用键表、CHANGELOG Breaking 段与本文件测试的逐键断言。
pub const fn deprecations() -> &'static [Deprecation] {
    &[Deprecation {
        key: "waf_config",
        since_version: "0.9.0",
        new_key: "",
        auto_map: false,
        map_fn: None,
    }]
}

/// 对合并后的配置树执行弃用键迁移/报错。
///
/// 可映射键：迁移（`map_fn` 或原样）并 warn；新键仅在树中缺失、或其值仍等于 `new_key_defaults` 默认值（默认值填充不算显式配置）时写入，用户显式配置的新键保留、旧键移除并告警。
/// 不可映射键：`< 1.0.0` warn 迁移指引后放行（树不变）；`>= 1.0.0` 命中任何注册键一律计入错误（宽限窗口关闭，可映射键也不再代迁）。`map_fn` 返回 `Err` 或版本无法解析且存在命中时 fail-closed 计入错误；`Err(消息列表)` 由调用方聚合为 [`GarrisonError::Config`](crate::error::GarrisonError::Config)；无命中不解析版本、不改树（热路径零开销）。
pub fn apply_deprecations(
    tree: &mut Value,
    registry: &[Deprecation],
    current_version: &str,
    new_key_defaults: &Value,
) -> Result<(), Vec<String>> {
    if registry.is_empty() {
        return Ok(());
    }
    let mut errors: Vec<String> = Vec::new();
    for dep in registry {
        let segments: Vec<&str> = dep.key.split('.').collect();
        // 先 peek 再按需移除：不可映射分支保持树不变
        let Some(old_value) = value_at_path(tree, &segments).cloned() else {
            continue;
        };
        match parsed_version(current_version) {
            Err(reason) => {
                errors.push(format!(
                    "config key \"{}\" deprecated since {}: cannot determine current version \"{}\" ({}); \
                     migrate the key manually before retrying",
                    dep.key, dep.since_version, current_version, reason
                ));
            },
            Ok(version) if is_at_least_1_0_0(&version) => {
                errors.push(unmigrated_error_message(dep));
            },
            Ok(_) if dep.is_mappable() => {
                let mapped = match dep.map_fn {
                    Some(map_fn) => map_fn(&old_value),
                    None => Ok(old_value.clone()),
                };
                match mapped {
                    Ok(new_value) => {
                        remove_value_at_path(tree, &segments);
                        if dep.new_key.is_empty() {
                            warn_migrated(dep, "removed without replacement");
                            continue;
                        }
                        let new_segments: Vec<&str> = dep.new_key.split('.').collect();
                        if new_key_is_explicit(&new_segments, tree, new_key_defaults) {
                            warn_migrated(
                                dep,
                                "new key already explicitly configured; legacy value discarded",
                            );
                            continue;
                        }
                        insert_value_at_path(tree, &new_segments, new_value);
                        warn_migrated(dep, "value migrated");
                    },
                    Err(reason) => {
                        errors.push(format!(
                            "config key \"{}\" deprecated since {}: value cannot be auto-migrated: {}",
                            dep.key, dep.since_version, reason
                        ));
                    },
                }
            },
            // < 1.0.0 且不可自动映射：warn 指引后放行（树不变，旧键随 serde 忽略、新键取默认值）
            Ok(_) => warn_unmigrated(dep),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// 新键是否为用户显式配置：树中不存在或等于默认对照 → 非显式（可写入）；无默认对照信息（`Value::Null` 或对照树缺该键）保守视为显式（不覆盖）。
fn new_key_is_explicit(new_segments: &[&str], tree: &Value, defaults: &Value) -> bool {
    let Some(current) = value_at_path(tree, new_segments) else {
        return false;
    };
    match value_at_path(defaults, new_segments) {
        Some(default_value) => current != default_value,
        None => true,
    }
}

/// 1.0 门命中的统一报错消息（含键名与迁移指引）。
fn unmigrated_error_message(dep: &Deprecation) -> String {
    let guidance = if dep.new_key.is_empty() {
        "this key has been removed; delete it from your configuration".to_string()
    } else {
        format!("rename it to \"{}\" in your configuration", dep.new_key)
    };
    format!(
        "config key \"{}\" deprecated since {}: support ended at 1.0.0; {}",
        dep.key, dep.since_version, guidance
    )
}

/// 自动迁移告警（含弃用键名、since 版本与新键名，`outcome` 说明值去向）。
fn warn_migrated(dep: &Deprecation, outcome: &str) {
    tracing::warn!(
        deprecated_key = dep.key,
        since = dep.since_version,
        new_key = dep.new_key,
        "{}",
        crate::i18n::translate_detail(
            "logs-config-deprecated-key-migrated",
            &[
                ("key", dep.key),
                ("since", dep.since_version),
                ("outcome", outcome),
            ]
        )
    );
}

/// 不可自动迁移键的告警（< 1.0.0 放行前输出迁移指引）。
fn warn_unmigrated(dep: &Deprecation) {
    let guidance = if dep.new_key.is_empty() {
        crate::i18n::translate_detail("config-deprecation-guidance-delete", &[])
    } else {
        crate::i18n::translate_detail("config-deprecation-guidance-rename", &[])
    };
    tracing::warn!(
        deprecated_key = dep.key,
        since = dep.since_version,
        new_key = dep.new_key,
        "{}",
        crate::i18n::translate_detail(
            "logs-config-deprecated-key-unmigratable",
            &[
                ("key", dep.key),
                ("since", dep.since_version),
                ("guidance", guidance.as_str()),
            ]
        )
    );
}

/// 解析后的 SemVer（major, minor, patch + 可选 pre-release 标识）。
type SemVer = ((u64, u64, u64), Option<String>);

/// 解析 `major[.minor[.patch]][-pre]` 版本号；pre-release 不参与门判定比较，仅区分 `1.0.0-rc.1 < 1.0.0`。
fn parsed_version(version: &str) -> Result<SemVer, String> {
    let (core, pre) = match version.split_once('-') {
        Some((core, pre)) => (core, Some(pre.to_string())),
        None => (version, None),
    };
    let mut numbers = [0u64; 3];
    for (idx, part) in core.split('.').enumerate() {
        if idx >= 3 {
            return Err(format!("too many components in version \"{}\"", version));
        }
        numbers[idx] = part
            .parse()
            .map_err(|_| format!("invalid version component \"{}\"", part))?;
    }
    Ok(((numbers[0], numbers[1], numbers[2]), pre))
}

/// 当前版本是否已到 1.0.0（含 1.0.0 本体；1.0.0 的 pre-release 未到）。
fn is_at_least_1_0_0(version: &SemVer) -> bool {
    let ((major, minor, patch), pre) = version;
    match (*major, *minor, *patch).cmp(&(1, 0, 0)) {
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Equal => pre.is_none(),
    }
}

/// 按点号路径读取树中值（中间节点非对象或叶子缺失返回 `None`）。
fn value_at_path<'a>(tree: &'a Value, segments: &[&str]) -> Option<&'a Value> {
    let (head, tail) = segments.split_first()?;
    if tail.is_empty() {
        return tree.get(*head);
    }
    value_at_path(tree.get(*head)?, tail)
}

/// 按点号路径从树中移除值并返回（路径不存在返回 `None`，树不变）。
fn remove_value_at_path(tree: &mut Value, segments: &[&str]) -> Option<Value> {
    let (head, tail) = segments.split_first()?;
    let object = tree.as_object_mut()?;
    if tail.is_empty() {
        return object.remove(*head);
    }
    remove_value_at_path(object.get_mut(*head)?, tail)
}

/// 按点号路径写入值（中间对象缺失时逐级创建）。
fn insert_value_at_path(tree: &mut Value, segments: &[&str], value: Value) {
    let Some((head, tail)) = segments.split_first() else {
        return;
    };
    if !tree.is_object() {
        *tree = serde_json::Map::new().into();
    }
    let object = tree.as_object_mut().expect("上一步已确保为对象");
    if tail.is_empty() {
        object.insert((*head).to_string(), value);
        return;
    }
    let child = object
        .entry((*head).to_string())
        .or_insert_with(|| serde_json::Map::new().into());
    insert_value_at_path(child, tail, value);
}
