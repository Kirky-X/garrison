#![no_main]
// Fuzz target：OIDC Discovery 配置反序列化。
// 覆盖 serde_json 对不受信任 discovery 响应的解析（未知字段、类型混淆、超深嵌套）。
// 注意：validate_id_token 需要 JWKS 网络拉取，不在无网络 fuzz 范围内。

use libfuzzer_sys::fuzz_target;
use garrison::protocol::sso::OidcDiscoveryConfig;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = serde_json::from_str::<OidcDiscoveryConfig>(s);
});
