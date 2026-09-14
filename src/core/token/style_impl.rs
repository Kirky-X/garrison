//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! Token 风格实现块（从 mod.rs 迁移，遵守 mod.rs 接口隔离约定）。
//!
//! 包含 `UuidTokenStyle` / `Random64TokenStyle` / `SimpleTokenStyle` /
//! `JwtTokenStyle` / `TokenStyleFactory` 的 `impl` 块。

use super::*;
use uuid::Uuid;

// ====================================================================
// UuidTokenStyle
// ====================================================================

impl Token for UuidTokenStyle {
    fn generate(&self, _login_id: &str, _timeout: i64) -> GarrisonResult<String> {
        Ok(Uuid::new_v4().to_string())
    }

    fn verify(&self, _token: &str) -> GarrisonResult<Option<String>> {
        // UUID 无 payload，无法提取 login_id
        Ok(None)
    }

    fn parse(&self, _token: &str) -> GarrisonResult<TokenClaims> {
        Err(GarrisonError::Internal(
            "core-token-parse-not-supported::UUID".to_string(),
        ))
    }
}

// ====================================================================
// Random64TokenStyle
// ====================================================================

impl Token for Random64TokenStyle {
    fn generate(&self, _login_id: &str, _timeout: i64) -> GarrisonResult<String> {
        // 拼接两个 UUID v4 的 simple 表示（各 32 hex 字符 = 64 字符）
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        Ok(token)
    }

    fn verify(&self, _token: &str) -> GarrisonResult<Option<String>> {
        // 随机 hex 无 payload，无法提取 login_id
        Ok(None)
    }

    fn parse(&self, _token: &str) -> GarrisonResult<TokenClaims> {
        Err(GarrisonError::Internal(
            "core-token-parse-not-supported::random_64".to_string(),
        ))
    }
}

// ====================================================================
// SimpleTokenStyle
// ====================================================================

#[cfg(feature = "secure-simple-token")]
impl SimpleTokenStyle {
    /// 计算 HMAC-SHA256 并返回 URL-safe Base64 编码。
    ///
    /// 输入为 `login_id|uuid|exp`（管道分隔，exp 绑定进签名防篡改），
    /// 输出为 Base64 编码的 HMAC（43 字符，无 padding）。
    fn compute_hmac(&self, login_id: &str, uuid_part: &str, exp: i64) -> GarrisonResult<String> {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;
        let message = format!("{}|{}|{}", login_id, uuid_part, exp);
        let mut mac = HmacSha256::new_from_slice(self.secret.as_bytes())
            .map_err(|e| GarrisonError::Config(format!("core-hmac-key-invalid::{}", e)))?;
        mac.update(message.as_bytes());
        // URL-safe Base64 无 padding（43 字符），适合放入 token
        Ok(Self::base64_url_no_pad(&mac.finalize().into_bytes()))
    }

    /// 将字节切片编码为 URL-safe Base64（无 padding）。
    ///
    /// # 实现说明
    ///
    /// 手写实现属 crypto-adjacent 原语，理想方案是切换到 `base64` crate
    ///（已是本 crate 的 optional 依赖）。当前保持手写实现的原因：
    /// `base64` 未被 `secure-simple-token` feature 启用，切换需变更 feature 图谱
    /// 且输出必须逐字节兼容（存量 token 含此编码的 HMAC 段）。作为补偿：
    /// - 本函数是纯函数，RFC 4648 test vectors 在 `#[cfg(test)]` 中锁定行为
    /// - 输入恒为 HMAC-SHA256 输出（32 字节定长），编码分支极少
    /// - 切换 `base64::engine::general_purpose::URL_SAFE_NO_PAD` 已列入
    /// protocol-zeroize 迁移同一批次（见 SimpleTokenStyle 文档）
    fn base64_url_no_pad(bytes: &[u8]) -> String {
        // 手动实现 URL-safe Base64 无 padding，避免引入额外 base64 依赖
        // （base64 crate 已是 optional dep，但 secure-simple-token feature 未启用它）
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut result = String::with_capacity((bytes.len() * 4).div_ceil(3));
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
            }
            if chunk.len() > 2 {
                result.push(CHARS[(n & 0x3F) as usize] as char);
            }
        }
        result
    }
}

/// 拆分 Simple token 为四个部分：`<login_id>\x1f<uuid>.<exp>.<hmac>` →
/// (login_id, uuid, exp, hmac)。任一段缺失或 exp 非法时返回 None。
#[cfg(feature = "secure-simple-token")]
fn split_simple_token_parts(token: &str) -> Option<(&str, &str, i64, &str)> {
    // 格式：<login_id>\x1f<uuid>.<exp>.<hmac>（\x1f = ASCII Unit Separator；
    // exp 为 Unix 秒时间戳，Simple token 携带过期时间）
    // 先按 '.' 分离出 HMAC 部分，再取 body 的 exp 段，最后按 \x1f 分离 login_id 与 uuid
    let (body, hmac_part) = token.rsplit_once('.')?;
    let (left, exp_str) = body.rsplit_once('.')?;
    let exp: i64 = exp_str.parse().ok()?;
    let (login_id, uuid_part) = left.split_once('\x1f')?;
    Some((login_id, uuid_part, exp, hmac_part))
}

#[cfg(feature = "secure-simple-token")]
impl Token for SimpleTokenStyle {
    fn generate(&self, login_id: &str, timeout: i64) -> GarrisonResult<String> {
        // 对齐 JWT 双向强校验：secret 短于 32 字节拒绝生成 token
        if self.secret.len() < 32 {
            return Err(GarrisonError::Config(
                "core-simple-secret-too-short::".to_string(),
            ));
        }
        // Simple token 必须携带过期时间。timeout <= 0 无法构造
        // 有意义的 exp，拒绝生成（fail-closed），杜绝事实永久的泄露 token。
        // 空 login_id 同样拒绝：空 login_id 会产生 `\x1f<uuid>.<exp>.<hmac>`
        // 形态 token，verify 可还原出空身份，属身份旁路风险。
        // 含 `\x1f` 的 login_id 拒绝：`\x1f` 是 token body 的字段分隔符，
        // 内嵌 `\x1f` 的 login_id 会造成 verify 身份切分歧义（fail-closed 拒绝生成）。
        if login_id.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "core-simple-login-id-empty::".to_string(),
            ));
        }
        if login_id.contains('\x1f') {
            return Err(GarrisonError::InvalidParam(
                "core-simple-login-id-sep::".to_string(),
            ));
        }
        if timeout <= 0 {
            return Err(GarrisonError::InvalidParam(format!(
                "core-simple-timeout-invalid::{}",
                timeout
            )));
        }
        let uuid = Uuid::new_v4();
        let uuid_str = uuid.to_string();
        // exp = 当前 Unix 秒 + timeout；绑定进 HMAC 消息防篡改
        let exp = chrono::Utc::now().timestamp() + timeout;
        let exp_str = exp.to_string();
        // 格式：<login_id>\x1f<uuid>.<exp>.<hmac_sha256_base64(secret, login_id|uuid|exp)>
        //（\x1f = ASCII Unit Separator，替代 `-` 避免 login_id 含 `-` 时分割歧义）
        let hmac = self.compute_hmac(login_id, &uuid_str, exp)?;
        Ok(format!("{}\x1f{}.{}.{}", login_id, uuid_str, exp_str, hmac))
    }

    fn verify(&self, token: &str) -> GarrisonResult<Option<String>> {
        use subtle::ConstantTimeEq;

        // 对齐 JWT：secret 短于 32 字节视为无效（所有 token 拒绝）
        if self.secret.len() < 32 {
            return Ok(None);
        }
        // 携带 exp 的三段 body；旧格式（无 exp 段 / 无 HMAC）一律 None
        let (login_id, uuid_part, exp, hmac_part) = match split_simple_token_parts(token) {
            Some(parts) => parts,
            None => return Ok(None),
        };
        // 空 login_id 段防御性拒绝（generate 已禁止，防御手工构造）
        if login_id.is_empty() {
            return Ok(None);
        }
        // 校验 UUID 部分为合法格式
        if Uuid::parse_str(uuid_part).is_err() {
            return Ok(None);
        }
        // exp 已过期 → 视为无效（对齐 JWT verify 的过期语义）
        if exp != 0 && chrono::Utc::now().timestamp() >= exp {
            return Ok(None);
        }
        // 计算期望的 HMAC 并常数时间比较
        let expected_hmac = match self.compute_hmac(login_id, uuid_part, exp) {
            Ok(h) => h,
            Err(_) => return Ok(None),
        };
        // ConstantTimeEq 防止 timing side-channel 攻击
        let ct_result = expected_hmac.as_bytes().ct_eq(hmac_part.as_bytes());
        if bool::from(ct_result) {
            Ok(Some(login_id.to_string()))
        } else {
            Ok(None)
        }
    }

    fn parse(&self, token: &str) -> GarrisonResult<TokenClaims> {
        // 对齐 JWT：secret 短于 32 字节拒绝解析
        if self.secret.len() < 32 {
            return Err(GarrisonError::Config(
                "core-simple-secret-too-short::".to_string(),
            ));
        }
        // 三段 body；缺段返回 Internal（格式错误）
        let (login_id, uuid_part, exp, hmac_part) = split_simple_token_parts(token)
            .ok_or_else(|| GarrisonError::Internal("core-simple-token-no-sep::".to_string()))?;
        // 空 login_id 段防御性拒绝
        if login_id.is_empty() {
            return Err(GarrisonError::InvalidToken(
                "core-simple-token-login-id-empty::".to_string(),
            ));
        }
        // 校验 UUID 部分
        if Uuid::parse_str(uuid_part).is_err() {
            return Err(GarrisonError::Internal(
                "core-simple-token-uuid-invalid::".to_string(),
            ));
        }
        // 过期 token 解析失败（对齐 JWT parse 语义）
        if exp != 0 && chrono::Utc::now().timestamp() >= exp {
            return Err(GarrisonError::ExpiredToken(
                "core-simple-token-expired::".to_string(),
            ));
        }
        // 校验 HMAC（常数时间比较）
        use subtle::ConstantTimeEq;
        let expected_hmac = self.compute_hmac(login_id, uuid_part, exp)?;
        let ct_result = expected_hmac.as_bytes().ct_eq(hmac_part.as_bytes());
        if !bool::from(ct_result) {
            return Err(GarrisonError::InvalidToken(
                "core-simple-token-hmac-failed::".to_string(),
            ));
        }
        // exp 段即 token 过期时间（不再是永不过期的 0）
        Ok(TokenClaims {
            login_id: login_id.to_string(),
            expire_at: exp,
            device: None,
        })
    }
}

#[cfg(not(feature = "secure-simple-token"))]
impl Token for SimpleTokenStyle {
    fn generate(&self, _login_id: &str, _timeout: i64) -> GarrisonResult<String> {
        // fail-closed：未启用 secure-simple-token feature 时拒绝生成 token
        Err(GarrisonError::Config(
            "core-simple-requires-feature::".to_string(),
        ))
    }

    fn verify(&self, _token: &str) -> GarrisonResult<Option<String>> {
        // fail-closed：未启用 feature 时所有 token 视为无效
        Ok(None)
    }

    fn parse(&self, _token: &str) -> GarrisonResult<TokenClaims> {
        Err(GarrisonError::Config(
            "core-simple-requires-feature::".to_string(),
        ))
    }
}

// ====================================================================
// JwtTokenStyle
// ====================================================================

#[cfg(feature = "protocol-jwt")]
impl JwtTokenStyle {
    /// 创建新的 JWT Token 风格。
    ///
    /// # 参数
    /// - `secret`: 签名密钥。
    pub fn new(secret: &str) -> Self {
        Self {
            handler: crate::protocol::jwt::JwtHandler::new(secret),
        }
    }
}

#[cfg(feature = "protocol-jwt")]
impl Token for JwtTokenStyle {
    fn generate(&self, login_id: &str, timeout: i64) -> GarrisonResult<String> {
        self.handler.sign(login_id, timeout)
    }

    fn verify(&self, token: &str) -> GarrisonResult<Option<String>> {
        match self.handler.verify(token) {
            Ok(claims) => Ok(Some(claims.login_id)),
            Err(_) => Ok(None),
        }
    }

    fn parse(&self, token: &str) -> GarrisonResult<TokenClaims> {
        let claims = self.handler.verify(token)?;
        Ok(TokenClaims {
            login_id: claims.login_id,
            expire_at: claims.exp,
            device: claims.device.clone(),
        })
    }
}

// ====================================================================
// TokenStyleFactory
// ====================================================================

impl TokenStyleFactory {
    /// 依据风格字符串创建 Token 实现。
    ///
    /// # 参数
    /// - `style`: 风格字符串（`"uuid"` / `"random_64"` / `"simple"` / `"jwt"`）。
    /// - `secret`: 签名密钥（仅 `jwt` 风格使用，其他风格忽略）。
    ///
    /// # 返回
    /// - `Ok(Box<dyn Token>)`: 创建成功。
    /// - `Err(GarrisonError::Config)`: 未知风格，消息含 "unknown token_style"。
    #[allow(clippy::new_ret_no_self)]
    pub fn new(style: &str, secret: &str) -> GarrisonResult<Box<dyn Token>> {
        match style {
            "uuid" => Ok(Box::new(UuidTokenStyle)),
            "random_64" => Ok(Box::new(Random64TokenStyle)),
            // SimpleTokenStyle 需传入 secret 用于 HMAC-SHA256 签名
            "simple" => Ok(Box::new(SimpleTokenStyle::new(secret.to_string()))),
            #[cfg(feature = "protocol-jwt")]
            "jwt" => Ok(Box::new(JwtTokenStyle::new(secret))),
            #[cfg(not(feature = "protocol-jwt"))]
            "jwt" => {
                let _ = secret; // 避免 unused 警告（jwt 风格需 protocol-jwt feature）
                Err(GarrisonError::Config(
                    "config-unknown-token-style-jwt::".to_string(),
                ))
            },
            other => Err(GarrisonError::Config(format!(
                "config-unknown-token-style::{}",
                other
            ))),
        }
    }
}

// ====================================================================
// base64_url_no_pad 与 exp 过期语义的行为锁定测试（补偿控制）
//
// 手写 URL-safe Base64（无 padding）用于 HMAC 签名输出路径，属 crypto-adjacent
// 原语。在切换到 `base64` crate 前，用 RFC 4648 test vectors + 定长输出契约
// 锁定行为，防止实现漂移。exp 语义需构造合法签名 token，故在本模块
// （可访问私有 compute_hmac）锁定。
// ====================================================================
#[cfg(all(test, feature = "secure-simple-token"))]
mod simple_token_impl_tests {
    use super::*;

    /// 构造测试用 style（secret 满足 >= 32 字节强校验）。
    fn make_style() -> SimpleTokenStyle {
        SimpleTokenStyle::new("test-hmac-secret-key-for-unit-tests-01".to_string())
    }

    /// RFC 4648 test vectors（URL-safe 字母表与标准字母表在这些向量上输出一致）。
    #[test]
    fn base64_url_no_pad_rfc4648_vectors() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                &SimpleTokenStyle::base64_url_no_pad(input),
                expected,
                "input: {:?}",
                input
            );
        }
    }

    /// URL-safe 字母表契约：6 个 0xFF 字节应产生 `-`/`_`（而非 `+`/`/`）且无 padding `=`。
    #[test]
    fn base64_url_no_pad_uses_url_safe_alphabet_no_padding() {
        let encoded = SimpleTokenStyle::base64_url_no_pad(&[0xff; 6]);
        assert_eq!(encoded, "________"); // 6 字节 → 8 字符，无 padding
        assert!(
            !encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='),
            "URL-safe 输出不得含 '+', '/', '='"
        );
    }

    /// HMAC 输出契约：32 字节（HMAC-SHA256 定长）输入应产出 43 字符无 padding 编码。
    #[test]
    fn base64_url_no_pad_hmac_output_length() {
        let encoded = SimpleTokenStyle::base64_url_no_pad(&[0x42; 32]);
        assert_eq!(encoded.len(), 43, "32 字节输入应编码为 43 字符");
    }

    /// 过期 token verify 返回 None、parse 返回 ExpiredToken；
    /// 未过期 token 正常通过；篡改 exp 段因 HMAC 绑定而失效。
    #[test]
    fn simple_token_expiry_enforced() {
        let style = make_style();
        let uuid_str = Uuid::new_v4().to_string();

        // 过去的 exp（合法签名）→ verify None，parse ExpiredToken
        let past_exp = chrono::Utc::now().timestamp() - 100;
        let hmac = style.compute_hmac("u1", &uuid_str, past_exp).unwrap();
        let expired = format!("u1\x1f{}.{}.{}", uuid_str, past_exp, hmac);
        assert_eq!(style.verify(&expired).unwrap(), None, "过期 token 应无效");
        assert!(
            matches!(style.parse(&expired), Err(GarrisonError::ExpiredToken(_))),
            "过期 token parse 应返回 ExpiredToken，实际: {:?}",
            style.parse(&expired)
        );

        // 未来的 exp（合法签名）→ 正常通过
        let future_exp = chrono::Utc::now().timestamp() + 3600;
        let hmac_future = style.compute_hmac("u1", &uuid_str, future_exp).unwrap();
        let valid = format!("u1\x1f{}.{}.{}", uuid_str, future_exp, hmac_future);
        assert_eq!(style.verify(&valid).unwrap(), Some("u1".to_string()));
        let claims = style.parse(&valid).unwrap();
        assert_eq!(claims.expire_at, future_exp);

        // 篡改 exp（延长有效期）→ HMAC 绑定校验失败 → None
        let tampered = format!("u1\x1f{}.{}.{}", uuid_str, future_exp + 86_400, hmac_future);
        assert_eq!(
            style.verify(&tampered).unwrap(),
            None,
            "篡改 exp 后 HMAC 应失败"
        );
    }
}
