#![no_main]
// Fuzz target：JWT verify 入口（畸形 header / claims / base64 / 签名）；固定 HS256 + 32 字节密钥，verify 必须对任意输入返回 Err 而非 panic。

use garrison::protocol::jwt::JwtHandler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let _ = handler.verify(token);
});
