// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 弃用配置键注册表：0.x → 1.0 的平滑升级路径。
//!
//! 配置键的改名/移除不再依赖“静默忽略未知键”（serde 默认行为，旧配置失效
//! 无任何提示），而是在加载期显性化：
//!
//! - **可自动映射**的键（`auto_map` / `map_fn`）：`< 1.0.0` 时旧值迁移到新键
//!   （可选经 `map_fn` 转换）并输出 `tracing::warn!`（含弃用起始版本与新键名）；
//! - **不可自动映射**的键：`< 1.0.0` 时 warn 迁移指引后放行（旧键随 serde
//!   忽略，新键取默认值——显性降级，不静默）；`≥ 1.0.0` 时返回
//!   [`GarrisonError::Config`](crate::error::GarrisonError::Config)（含弃用键名
//!   与迁移指引），强制配置文件在 1.0 前完成迁移。
//!
//! 挂点：[`GarrisonConfig::load`](super::GarrisonConfig::load) 借助 confers
//! `ConfigBuilder::map_json`，在 env/toml 合并树反序列化**前**、`validate()`
//! **前**执行（保证迁移后的值能通过校验）；不修改 confers 加载机制本身。
//!
//! 键格式：点号分隔的逻辑路径，与合并后 JSON 树的嵌套结构一致——扁平键
//! （如 `timeout_seconds`）与嵌套段键（如 `password_hasher.bcrypt_cost`）
//! 统一表示；env 变量经 `GARRISON_` 前缀 + `__` 分隔折叠后等价。

use serde_json::Value;

/// 旧值 → 新值转换函数类型（`map_fn` 字段的签名；转换失败以 `Err` 拒绝迁移）。
pub type DeprecationMapper = fn(&Value) -> Result<Value, String>;

/// 单条弃用键注册项。
///
/// # 字段
///
/// - `key`：弃用键（点号分隔逻辑路径，见模块文档）
/// - `since_version`：弃用起始版本（SemVer 字符串，仅用于日志与错误指引，
///   不参与 1.0 门判定——门只看当前版本）
/// - `new_key`：迁移目标键；键被彻底移除且无对应物时填 `""`（指引文案相应
///   退化为“直接移除该键”）
/// - `auto_map`：是否允许加载期自动迁移；与 `map_fn` 组合语义：
///   - `auto_map = true, map_fn = None`：旧值原样搬到新键（同类型改名）
///   - `auto_map = true, map_fn = Some(f)`：旧值经 `f` 转换后写入新键
///   - `auto_map = false, map_fn = None`：不可自动映射（`is_mappable` 为 false）
///   - `auto_map = false, map_fn = Some(f)`：等价于 `auto_map = true`（映射函数
///     存在即可迁移）；注册时建议直接写 `auto_map = true` 避免歧义
/// - `map_fn`：旧值 → 新值转换函数；返回 `Err` 表示该值无法迁移（加载失败，
///   错误显性化）
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
/// 首批唯一条目 `waf_config`——GarrisonConfig 全历史（63 个提交触及
/// `src/config/mod.rs`）字段集逐对 diff 的唯一删除项：web-waf feature 门控的
/// `waf_config: WafConfig` 字段于 v0.9.0 feature 重组中移除（含
/// enabled/path_whitelist/path_blacklist/check_dangerous_chars/
/// check_directory_traversal/allowed_methods 五个子键），随 0.9.0-rc.1 发布。
/// `docs/CHANGELOG.md` 只记录了其引入（0.6.4），**未记录移除**——存量 toml
/// 的 `[waf_config] enabled = true` 升级后会被 serde 静默忽略、WAF 防护无
/// 提示消失，正是本模块要显性化的失效模式；该键因 CHANGELOG 漏记而无法满足
/// “Breaking 段可溯源”的字面验收，经复审裁定仍须登记（不登记即保留静默
/// 失效）。无单一继任键：防护配置由 `firewall-waf` feature 的 `waf_*` 平铺键
/// （`waf_enabled_hooks` / `waf_white_paths` / `waf_black_paths` 等）按新语义
/// 重建，故 `new_key = ""`、不可自动映射。
///
/// 其余 Breaking 段条目（QRLogin poll `bind_token` 请求字段、
/// `ApiKeyHandler::verify` 默认禁用、`firewall-quota` feature 移除等）均为
/// 协议/代码 API/feature 面，不在配置键注册范围。
///
/// 后续任何配置键级弃用登记于此，并同步 `docs/CONFIGURATION.md` 弃用键表、
/// CHANGELOG Breaking 段与本文件测试模块的逐键断言。
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
/// - 命中可自动映射的键：迁移（`map_fn` 或原样）+ `tracing::warn!`（含
///   `since` 版本与新键名）。新键写入条件：树中缺失，**或**当前值仍等于
///   `new_key_defaults` 中该键的默认值（默认值填充不算显式配置）；用户显式
///   设置过新键（非默认值）时保留用户值，旧键仍移除并告警。
/// - 命中不可自动映射的键：`current_version < 1.0.0` 时 warn 迁移指引后
///   放行（树不变）；`≥ 1.0.0` 时计入错误。
/// - `current_version ≥ 1.0.0`：弃用宽限窗口关闭，命中任何注册键一律计入
///   错误（含可自动映射的键——1.0 起不再代迁）。
/// - `map_fn` 返回 `Err`：计入错误（值无法迁移，静默丢弃即静默失效）。
/// - `current_version` 无法解析且存在命中：fail-closed 计入错误。
///
/// `new_key_defaults`：新键默认值对照树（生产路径传序列化的
/// `GarrisonConfig::default_config()`；无对照信息传 `Value::Null`，此时新键
/// 已存在即视为显式配置不覆盖）。
///
/// 返回 `Err(消息列表)` 时消息已含弃用键名与迁移指引，由调用方聚合为
/// [`GarrisonError::Config`](crate::error::GarrisonError::Config)。
///
/// 无命中时不解析版本、不修改树（热路径零开销）。
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
            // < 1.0.0 且不可自动映射：warn 迁移指引后放行（树不变，旧键随
            // serde 忽略，新键取默认值——显性降级）
            Ok(_) => warn_unmigrated(dep),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// 新键是否为用户显式配置（存在且不等于默认对照值）。
///
/// 树中不存在 → 非显式（可写入）；存在但与默认对照相等 → 默认值填充，
/// 非显式（可写入）；无默认对照信息（`Value::Null` 或对照树缺该键）→
/// 保守视为显式（不覆盖）。
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
        "deprecated config key \"{}\" (since {}) processed: {}; update your configuration before 1.0.0",
        dep.key,
        dep.since_version,
        outcome
    );
}

/// 不可自动迁移键的告警（< 1.0.0 放行前输出迁移指引）。
fn warn_unmigrated(dep: &Deprecation) {
    tracing::warn!(
        deprecated_key = dep.key,
        since = dep.since_version,
        new_key = dep.new_key,
        "deprecated config key \"{}\" (since {}) is no longer auto-mappable and will be rejected at 1.0.0; {}",
        dep.key,
        dep.since_version,
        if dep.new_key.is_empty() {
            "delete it from your configuration"
        } else {
            "rename it manually"
        }
    );
}

/// 解析后的 SemVer（major, minor, patch + 可选 pre-release 标识）。
type SemVer = ((u64, u64, u64), Option<String>);

/// 解析 `major[.minor[.patch]][-pre]` 形式的版本号（整段 pre-release 不参与
/// 门判定比较，仅区分 `1.0.0-rc.1 < 1.0.0`）。
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
