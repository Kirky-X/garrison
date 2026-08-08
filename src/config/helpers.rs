//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! config 模块辅助函数（从 mod.rs 迁移，Rule 25 合规）。

use super::*;

/// 构造默认 JwtSecret（空字符串），避免 `Default` 实现中重复 cfg 分支。
///
/// # ⚠️ 安全警告
///
/// 返回的 JWT secret 为**空字符串**，仅用于开发/测试环境的默认配置。
/// **生产环境必须通过配置文件或环境变量设置非空 secret**，否则攻击者可伪造任意 token。
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

/// 收集 `GARRISON_` 前缀的环境变量，转换为 confers MemorySource 所需的 `HashMap`。
///
/// Key 映射规则：
/// 1. 剥离前缀（如 `GARRISON_`）
/// 2. 转小写
/// 3. `__` → `.`（支持嵌套路径，如 `tenant_isolation.enabled`）
///
/// **不使用 confers `EnvSource` 的原因**（非 bug workaround，架构决策）：
/// Garrison 的 `ConfigBuilder` 使用**扁平 key** 注册默认值（如 `.default("token_name", ...)`），
/// 而 `EnvSource` 将 `GARRISON_TOKEN_NAME` 转为嵌套路径 `token.name`（`_` 作为分隔符 → `.`）。
/// 扁平 key 与嵌套路径不兼容，ConfigBuilder 无法反序列化嵌套路径到扁平字段。
/// 此函数是 ConfigBuilder 扁平 key 模型的**必要适配层**。
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
