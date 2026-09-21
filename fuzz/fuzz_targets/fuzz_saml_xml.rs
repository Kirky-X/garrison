#![no_main]
// Fuzz target：SAML Response XML 解析（攻击面最大的解析入口，quick-xml 手写解析链）。
// 覆盖 DefaultSamlProvider::parse_response 全链路：XML 结构提取、签名算法提取、
// 状态校验、base64 解码。崩溃 = 解析器存在 panic 路径。

use libfuzzer_sys::fuzz_target;
use garrison::protocol::sso::saml::{DefaultSamlProvider, SamlProvider};

fuzz_target!(|data: &[u8]| {
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(provider) = DefaultSamlProvider::new() else {
        return;
    };
    // parse_response 为 async trait 方法；fuzz 单线程 block_on 足够
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fuzz tokio runtime");
    let _ = rt.block_on(provider.parse_response(xml));
});
