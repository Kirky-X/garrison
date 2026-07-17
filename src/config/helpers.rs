//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! config 模块辅助函数（从 mod.rs 迁移，Rule 25 合规）。

use super::*;

/// 构造默认 JwtSecret（空字符串），避免 `Default` 实现中重复 cfg 分支。
pub(crate) fn default_jwt_secret() -> JwtSecret {
    #[cfg(feature = "protocol-zeroize")]
    {
        String::new().into()
    }
    #[cfg(not(feature = "protocol-zeroize"))]
    {
        String::new()
    }
}

/// 收集 `BULWARK_` 前缀的环境变量，转换为 confers MemorySource 所需的 `HashMap`。
///
/// Key 映射规则（与 confers `EnvSource::with_prefix(prefix).separator("__")` 一致）：
/// 1. 剥离前缀（如 `BULWARK_`）
/// 2. 转小写
/// 3. `__` → `.`（支持嵌套路径，如 `tenant_isolation.enabled`）
///
/// 使用 `MemorySource` 代替 `EnvSource` 的原因：confers 0.4.1 的 `EnvSource::collect()`
/// 未在顶层 `AnnotatedValue` 上调用 `.with_priority()`，导致优先级默认为 0，被
/// `DefaultSource`（同为 priority 0）覆盖。`MemorySource::collect()` 正确设置了 priority。
pub(crate) fn collect_env_vars(prefix: &str) -> HashMap<String, ConfigValue> {
    let mut values = HashMap::new();
    for (key, value) in std::env::vars() {
        if let Some(stripped) = key.strip_prefix(prefix) {
            let config_key = stripped.to_lowercase().replace("__", ".");
            values.insert(config_key, infer_config_value(&value));
        }
    }
    values
}

/// 从字符串推断 `ConfigValue` 类型（与 confers `EnvSource::infer_config_value` 逻辑一致）。
fn infer_config_value(s: &str) -> ConfigValue {
    if s.eq_ignore_ascii_case("true") {
        return ConfigValue::Bool(true);
    }
    if s.eq_ignore_ascii_case("false") {
        return ConfigValue::Bool(false);
    }
    if let Ok(v) = s.parse::<i64>() {
        return ConfigValue::I64(v);
    }
    if let Ok(v) = s.parse::<u64>() {
        return ConfigValue::U64(v);
    }
    if s.contains('.') || s.contains('e') || s.contains('E') {
        if let Ok(v) = s.parse::<f64>() {
            return ConfigValue::F64(v);
        }
    }
    ConfigValue::String(s.to_string())
}
