#![no_main]
// Fuzz target：JWT verify 入口（畸形 header / claims / base64 / 签名）。
// JwtHandler 固定 HS256 + 32 字节密钥；verify 必须对任意输入返回 Err 而非 panic。

use libfuzzer_sys::fuzz_target;
use garrison::protocol::jwt::JwtHandler;

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    // 32 字节密钥（满足 MIN_SECRET_BYTES），默认 HS256
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let _ = handler.verify(token);
});
