#![no_main]
// Fuzz target：HTTP 认证头解析（Basic base64 解码 + Digest 参数解析与验证）。
// 覆盖 RFC 7617 / RFC 7616 Authorization header 的畸形输入路径。

use libfuzzer_sys::fuzz_target;
use garrison::secure::httpbasic::HttpBasicAuth;
use garrison::secure::httpdigest::HttpDigestAuth;

fuzz_target!(|data: &[u8]| {
    let Ok(header) = std::str::from_utf8(data) else {
        return;
    };
    // Basic：base64 解码 + UTF-8 校验 + user:pass 切分
    let _ = HttpBasicAuth::parse_authorization_header(header);
    // Digest：参数解析 + nonce/nc/cnonce/response 校验（fail-closed 返回 false）
    if let Ok(digest) = HttpDigestAuth::new("fuzz-realm", "SHA-256") {
        let _ = digest.validate(header, "GET", "/", "fuzz-ha1");
    }
});
