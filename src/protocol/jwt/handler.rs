// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! JwtHandler 实现：JWT 签发、校验、刷新。
//!
//! 类型定义见 [`JwtHandler`](crate::protocol::jwt::JwtHandler)。

use crate::error::{GarrisonError, GarrisonResult};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{GarrisonJwtClaims, JwtHandler};

/// JWT 签名密钥最小长度（字节）。
///
/// 256 位匹配 HS256 算法安全强度，与 OWASP / NIST SP 800-117 推荐一致。
/// 短于此阈值的密钥可被暴力破解，导致 JWT 伪造。
const MIN_SECRET_BYTES: usize = 32;

/// JWT 密钥材料（crate 内私有）：决定 sign/verify 的密钥来源与算法白名单。
///
/// 算法必须与密钥类型一致（如 RSA 密钥只能配 RS 系算法），防止
/// alg confusion / 算法替换攻击；匹配约束由 [`validate_algorithm_match`] 强制。
/// PEM 内容在 Debug 输出中脱敏（防私钥泄漏到日志）。
pub(crate) enum KeyMaterial {
    /// 对称 HMAC：`secret` 字段即密钥（HS256/HS384/HS512）。
    Hs,
    /// RSA PKCS#1 私钥 PEM（RS256/RS384/RS512）。
    RsaPkcs1Pem(String),
    /// EC 私钥 PEM（ES256/ES384）。
    EcPem(String),
    /// Ed25519 私钥 PEM（EdDSA）。
    EdPem(String),
}

impl KeyMaterial {
    /// 该密钥类型允许的算法白名单（fail-closed 语义：不在白名单即拒绝）。
    pub(crate) fn allowed_algorithms(&self) -> &'static [Algorithm] {
        match self {
            KeyMaterial::Hs => &[Algorithm::HS256, Algorithm::HS384, Algorithm::HS512],
            KeyMaterial::RsaPkcs1Pem(_) => &[Algorithm::RS256, Algorithm::RS384, Algorithm::RS512],
            KeyMaterial::EcPem(_) => &[Algorithm::ES256, Algorithm::ES384],
            KeyMaterial::EdPem(_) => &[Algorithm::EdDSA],
        }
    }
}

impl std::fmt::Debug for KeyMaterial {
    /// PEM 内容脱敏：错误消息 / 日志中不得出现私钥原文。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyMaterial::Hs => write!(f, "KeyMaterial::Hs"),
            KeyMaterial::RsaPkcs1Pem(_) => write!(f, "KeyMaterial::RsaPkcs1Pem(<redacted>"),
            KeyMaterial::EcPem(_) => write!(f, "KeyMaterial::EcPem(<redacted>"),
            KeyMaterial::EdPem(_) => write!(f, "KeyMaterial::EdPem(<redacted>"),
        }
    }
}

/// JWT 公钥参数（JWKS 导出用，无私钥成分）。
pub enum JwkPublicKey {
    /// RSA：模数 n 与指数 e（base64url，JWK 口径）。
    Rsa {
        /// RSA 模数 n（base64url，RFC 7518 §6.3.1）。
        n: String,
        /// RSA 公钥指数 e（base64url，RFC 7518 §6.3.1）。
        e: String,
    },
    /// EC：曲线名、坐标 x/y（base64url，JWK 口径）。
    Ec {
        /// 曲线标识（P-256 / P-384，RFC 7518 §6.2.1.1）。
        crv: &'static str,
        /// 公钥 x 坐标（base64url，RFC 7518 §6.2.1.2）。
        x: String,
        /// 公钥 y 坐标（base64url，RFC 7518 §6.2.1.3）。
        y: String,
    },
    /// OKP（Ed25519）：公钥 x（base64url，JWK 口径）。
    Okp {
        /// Ed25519 公钥（base64url，RFC 8037 §2）。
        x: String,
    },
}

/// 校验签名算法与密钥类型匹配（fail-closed）。
///
/// 白名单：Hs→{HS256,HS384,HS512}、RsaPkcs1Pem→{RS256,RS384,RS512}、
/// EcPem→{ES256,ES384}、EdPem→{EdDSA}。
pub(crate) fn validate_algorithm_match(
    key_material: &KeyMaterial,
    algorithm: Algorithm,
) -> GarrisonResult<()> {
    if key_material.allowed_algorithms().contains(&algorithm) {
        Ok(())
    } else {
        Err(GarrisonError::Config(format!(
            "jwt-key-algorithm-mismatch::key={:?}::alg={:?}",
            key_material, algorithm
        )))
    }
}

/// 从 RSA 私钥 PEM（PKCS#8 `BEGIN PRIVATE KEY` 或 PKCS#1 `BEGIN RSA PRIVATE KEY`）
/// 提取公钥组件 `(n, e)` 的 base64url 编码（JWK 口径，jsonwebtoken
/// `DecodingKey::from_rsa_components` 期望该格式）。
///
/// 仅做 DER 结构解析（pkcs1/pkcs8 纯解析库），无任何 RSA 运算。
/// PEM 剥壳：去掉 BEGIN/END 头尾行与空白，解码标准 Base64 得 DER 字节。
/// PEM（RFC 7468）使用标准 Base64（非 URL-safe），无 padding 差异问题。
fn pem_to_der(pem: &str) -> GarrisonResult<Vec<u8>> {
    use base64::Engine;

    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| GarrisonError::Internal(format!("jwt-rsa-pem-invalid::{}", e)))
}

fn extract_rsa_public_components(pem: &str) -> GarrisonResult<(String, String)> {
    use base64::Engine;
    use pkcs8::der::Decode;

    let der = pem_to_der(pem)?;
    // PKCS#8（"BEGIN PRIVATE KEY"）：PrivateKeyInfo.private_key（OCTET STRING）
    // 内嵌 PKCS#1 RSAPrivateKey DER；PKCS#1（"BEGIN RSA PRIVATE KEY"）：整段即
    // RsaPrivateKey DER。按 PEM label 区分。
    let key = if pem.contains("BEGIN RSA PRIVATE KEY") {
        pkcs1::RsaPrivateKey::from_der(&der)
    } else {
        let pki = pkcs8::PrivateKeyInfo::from_der(&der)
            .map_err(|e| GarrisonError::Internal(format!("jwt-rsa-pem-invalid::{}", e)))?;
        pkcs1::RsaPrivateKey::from_der(pki.private_key)
    }
    .map_err(|e| GarrisonError::Internal(format!("jwt-rsa-pem-invalid::{}", e)))?;

    let b64 = |data: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
    Ok((
        b64(key.modulus.as_bytes()),
        b64(key.public_exponent.as_bytes()),
    ))
}

/// 从 EC 私钥 PEM（PKCS#8）提取 SEC1 未压缩公钥字节（`0x04 ‖ X ‖ Y`）。
///
/// PKCS#8 EC 的 private_key 为 RFC 5915 `ECPrivateKey` DER；若其中内嵌公钥
/// （`publicKey` 位串，V2 可选）则直接取用，否则按曲线 OID 分派做标量乘法计算。
/// 仅支持 P-256 / P-384（对应 ES256 / ES384）。
fn extract_ec_public_sec1(pem: &str) -> GarrisonResult<Vec<u8>> {
    use pkcs8::der::asn1::ObjectIdentifier;
    use pkcs8::der::Decode;

    const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
    const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

    let der = pem_to_der(pem)?;
    let pki = pkcs8::PrivateKeyInfo::from_der(&der)
        .map_err(|e| GarrisonError::Internal(format!("jwt-ec-pem-invalid::{}", e)))?;
    let ec = sec1::EcPrivateKey::from_der(pki.private_key)
        .map_err(|e| GarrisonError::Internal(format!("jwt-ec-pem-invalid::{}", e)))?;

    // RFC 5915 V2 密钥内嵌公钥位串时直接取用（无运算）
    if let Some(pub_bytes) = ec.public_key {
        return Ok(pub_bytes.to_vec());
    }

    // 曲线 OID 判定后做标量乘法计算公钥点
    let oid = pki
        .algorithm
        .parameters
        .and_then(|any| any.decode_as::<ObjectIdentifier>().ok())
        .ok_or_else(|| GarrisonError::Internal("jwt-ec-curve-missing::".to_string()))?;
    if oid == OID_P256 {
        let secret = p256::SecretKey::from_slice(ec.private_key)
            .map_err(|e| GarrisonError::Internal(format!("jwt-ec-pem-invalid::{}", e)))?;
        Ok(secret.public_key().to_sec1_bytes().to_vec())
    } else if oid == OID_P384 {
        let secret = p384::SecretKey::from_slice(ec.private_key)
            .map_err(|e| GarrisonError::Internal(format!("jwt-ec-pem-invalid::{}", e)))?;
        Ok(secret.public_key().to_sec1_bytes().to_vec())
    } else {
        Err(GarrisonError::Internal(format!(
            "jwt-ec-curve-unsupported::{oid}"
        )))
    }
}

/// 从 Ed25519 私钥 PEM（PKCS#8，RFC 8410）提取 32 字节种子。
///
/// RFC 8410 §7：Ed25519 的 PrivateKeyInfo.private_key OCTET STRING 内容直接是
/// 种子字节（无嵌套 DER 结构），纯字节拷贝即可。
fn extract_ed25519_seed(pem: &str) -> GarrisonResult<[u8; 32]> {
    use pkcs8::der::Decode;

    let der = pem_to_der(pem)?;
    let pki = pkcs8::PrivateKeyInfo::from_der(&der)
        .map_err(|e| GarrisonError::Internal(format!("jwt-ed-pem-invalid::{}", e)))?;
    // RFC 8410：private_key OCTET STRING 的内容是 CurvePrivateKey 的 DER 编码
    // （即又一具 OCTET STRING：0x04 0x20 + 32 字节种子），需再剥一层
    let inner = pkcs8::der::asn1::OctetStringRef::from_der(pki.private_key)
        .map_err(|e| GarrisonError::Internal(format!("jwt-ed-pem-invalid::{}", e)))?;
    inner
        .as_bytes()
        .try_into()
        .map_err(|_| GarrisonError::Internal("jwt-ed-seed-len::".to_string()))
}

impl JwtHandler {
    /// 创建新的 JWT 处理器，默认采用 HS256 算法。
    ///
    /// # 参数
    /// - `secret`: 签名密钥（空字符串将在 `sign` 时拒绝）。
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            algorithm: Algorithm::HS256,
            device: None,
            key_material: KeyMaterial::Hs,
        }
    }

    /// 导出公钥参数（JWKS 端点用；无私钥成分）。
    ///
    /// 对称密钥（Hs）无可公开成分，返回 `Ok(None)`；非对称密钥返回
    /// [`JwkPublicKey`]。kid 由调用方按 RFC 7638 thumbprint 计算。
    pub fn export_public_jwk_parts(&self) -> GarrisonResult<Option<JwkPublicKey>> {
        use base64::Engine;

        match &self.key_material {
            KeyMaterial::Hs => Ok(None),
            KeyMaterial::RsaPkcs1Pem(pem) => {
                let (n, e) = extract_rsa_public_components(pem)?;
                Ok(Some(JwkPublicKey::Rsa { n, e }))
            },
            KeyMaterial::EcPem(pem) => {
                let sec1 = extract_ec_public_sec1(pem)?;
                // SEC1 未压缩点：0x04 ‖ X ‖ Y（X/Y 等长）
                if sec1.first() != Some(&0x04) || sec1.len() < 3 || (sec1.len() - 1) % 2 != 0 {
                    return Err(GarrisonError::Internal("jwt-ec-sec1-format::".to_string()));
                }
                let coord = (sec1.len() - 1) / 2;
                let b64 =
                    |data: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
                let crv = match coord {
                    32 => "P-256",
                    48 => "P-384",
                    _ => {
                        return Err(GarrisonError::Internal(
                            "jwt-ec-curve-unsupported::".to_string(),
                        ))
                    },
                };
                Ok(Some(JwkPublicKey::Ec {
                    crv,
                    x: b64(&sec1[1..1 + coord]),
                    y: b64(&sec1[1 + coord..]),
                }))
            },
            KeyMaterial::EdPem(pem) => {
                let seed = extract_ed25519_seed(pem)?;
                let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
                Ok(Some(JwkPublicKey::Okp {
                    x: base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(signing.verifying_key().as_bytes()),
                }))
            },
        }
    }

    /// 按算法名与私钥 PEM 构建 handler（config 透传共用入口）。
    ///
    /// `stp/token` 与 `core/token::TokenStyleFactory` 共用本分派逻辑，消除
    /// 构造分派重复；算法名非法或算法与密钥材料不匹配时 fail-fast。
    ///
    /// # 参数
    /// - `algorithm`: 算法名（config 白名单口径：HS256/HS384/HS512/RS256/ES256/EdDSA）。
    /// - `jwt_secret`: 对称密钥（HS 系使用；非对称路径作占位）。
    /// - `rsa_pem` / `ec_pem` / `ed_pem`: 对应私钥 PEM（未配置传 None）。
    pub(crate) fn from_algorithm_parts(
        algorithm: &str,
        jwt_secret: &str,
        rsa_pem: Option<&str>,
        ec_pem: Option<&str>,
        ed_pem: Option<&str>,
    ) -> GarrisonResult<Self> {
        let base = JwtHandler::new(jwt_secret);
        match algorithm {
            "HS256" => base.try_with_algorithm(Algorithm::HS256),
            "HS384" => base.try_with_algorithm(Algorithm::HS384),
            "HS512" => base.try_with_algorithm(Algorithm::HS512),
            "RS256" => base
                .with_rsa_private_pem(rsa_pem.unwrap_or(""))
                .and_then(|h| h.try_with_algorithm(Algorithm::RS256)),
            "ES256" => base
                .with_ec_pem(ec_pem.unwrap_or(""))
                .and_then(|h| h.try_with_algorithm(Algorithm::ES256)),
            "EdDSA" => base
                .with_ed_pem(ed_pem.unwrap_or(""))
                .and_then(|h| h.try_with_algorithm(Algorithm::EdDSA)),
            other => Err(GarrisonError::Config(format!(
                "config-jwt-algorithm-unsupported::{other}"
            ))),
        }
    }

    /// 切换签名算法（构造期 fail-fast 版本，推荐）。
    ///
    /// 与 [`with_algorithm`](Self::with_algorithm) 的差异：算法与当前密钥材料
    /// 不匹配时立即返回错误，而非延迟到 `sign`/`verify` 时才拒绝。
    ///
    /// # 参数
    /// - `algorithm`: 算法（必须 ∈ 密钥类型白名单，如 HS 密钥限
    ///   HS256/HS384/HS512）。
    ///
    /// # 返回
    /// - `Ok(Self)`: 算法合法。
    /// - `Err(GarrisonError::Config)`: 算法与密钥类型不匹配。
    pub fn try_with_algorithm(mut self, algorithm: Algorithm) -> GarrisonResult<Self> {
        validate_algorithm_match(&self.key_material, algorithm)?;
        self.algorithm = algorithm;
        Ok(self)
    }

    /// 切换签名算法（builder 兼容版本）。
    ///
    /// 保持既有 builder 签名（返回 `Self`）；算法与密钥材料不匹配时**不在
    /// 此处 panic**，而是在 `sign`/`verify` 入口被 `validate_algorithm_match`
    /// 拦截（fail-closed）。新代码推荐 [`try_with_algorithm`](Self::try_with_algorithm)。
    ///
    /// # 参数
    /// - `algorithm`: 算法（如 `Algorithm::HS512`）。
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// 设置设备标识。
    ///
    /// 签发时写入 claims 的 `device` 字段。
    ///
    /// # 参数
    /// - `device`: 设备标识。
    pub fn with_device(mut self, device: impl Into<String>) -> Self {
        self.device = Some(device.into());
        self
    }

    /// 以 RSA PKCS#1/PKCS#8 PEM 私钥切换为非对称签名（RS256/RS384/RS512）。
    ///
    /// 构造期验证 PEM 可解析（fail-fast）；PEM 内容存于私有 [`KeyMaterial`]，
    /// Debug 输出脱敏。切换后默认算法仍为 HS256，须配合
    /// [`try_with_algorithm`](Self::try_with_algorithm)（推荐）或
    /// [`with_algorithm`](Self::with_algorithm) 设置 RS 系算法。
    ///
    /// # 参数
    /// - `pem`: RSA 私钥 PEM 字符串（`-----BEGIN PRIVATE KEY-----` 或
    ///   `-----BEGIN RSA PRIVATE KEY-----`）。
    ///
    /// # 返回
    /// - `Ok(Self)`: PEM 解析成功。
    /// - `Err(GarrisonError::Config)`: PEM 解析失败。
    pub fn with_rsa_private_pem(mut self, pem: impl Into<String>) -> GarrisonResult<Self> {
        let pem = pem.into();
        // 构造期 fail-fast：PEM 可解析性在构造时验证，错误延迟到 sign 期难排查
        EncodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| GarrisonError::Config(format!("jwt-rsa-pem-invalid::{}", e)))?;
        self.key_material = KeyMaterial::RsaPkcs1Pem(pem);
        Ok(self)
    }

    /// 以 EC PEM 私钥切换为非对称签名（ES256/ES384，PKCS#8 格式）。
    ///
    /// 构造期验证 PEM 可解析（fail-fast）；PEM 内容存于私有 [`KeyMaterial`]，
    /// Debug 输出脱敏。须配合 [`try_with_algorithm`](Self::try_with_algorithm)
    /// 设置 ES 系算法。
    ///
    /// # 参数
    /// - `pem`: EC 私钥 PEM 字符串（PKCS#8，`-----BEGIN PRIVATE KEY-----`）。
    ///
    /// # 返回
    /// - `Ok(Self)`: PEM 解析成功。
    /// - `Err(GarrisonError::Config)`: PEM 解析失败。
    pub fn with_ec_pem(mut self, pem: impl Into<String>) -> GarrisonResult<Self> {
        let pem = pem.into();
        EncodingKey::from_ec_pem(pem.as_bytes())
            .map_err(|e| GarrisonError::Config(format!("jwt-ec-pem-invalid::{}", e)))?;
        self.key_material = KeyMaterial::EcPem(pem);
        Ok(self)
    }

    /// 以 Ed25519 私钥 PEM 切换为非对称签名（EdDSA，PKCS#8 格式，RFC 8410）。
    ///
    /// 构造期验证 PEM 可解析（fail-fast）；PEM 内容存于私有 [`KeyMaterial`]，
    /// Debug 输出脱敏。须配合 [`try_with_algorithm`](Self::try_with_algorithm)
    /// 设置 `EdDSA`。
    ///
    /// # 参数
    /// - `pem`: Ed25519 私钥 PEM 字符串（PKCS#8）。
    ///
    /// # 返回
    /// - `Ok(Self)`: PEM 解析成功。
    /// - `Err(GarrisonError::Config)`: PEM 解析失败。
    pub fn with_ed_pem(mut self, pem: impl Into<String>) -> GarrisonResult<Self> {
        let pem = pem.into();
        // 构造期 fail-fast：PKCS#8 结构可解析性验证（种子长度校验在 verify 路径）
        let _parsed_ok = extract_ed25519_seed(&pem)?;
        self.key_material = KeyMaterial::EdPem(pem);
        Ok(self)
    }

    /// 签发 JWT。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `timeout`: 有效期（秒），不可为负数。
    ///
    /// # 返回
    /// - `Ok(String)`: JWT 字符串（三段 Base64URL 通过 `.` 连接）。
    /// - `Err(GarrisonError::Config)`: 密钥为空、过短或 timeout 为负。
    /// - `Err(GarrisonError::InvalidParam)`: `now + timeout` 溢出（timeout 过大）。
    /// - `Err(GarrisonError::Internal)`: 签发失败。
    pub fn sign(&self, login_id: impl Into<String>, timeout: i64) -> GarrisonResult<String> {
        let login_id: String = login_id.into();
        if matches!(self.key_material, KeyMaterial::Hs) && self.secret.is_empty() {
            return Err(GarrisonError::Config("jwt-secret-empty::".to_string()));
        }
        // JWT 密钥最小长度校验（防暴力破解，仅对称路径适用；非对称路径密钥强度由 PEM 位长决定）
        if matches!(self.key_material, KeyMaterial::Hs) && self.secret.len() < MIN_SECRET_BYTES {
            return Err(GarrisonError::Config(format!(
                "jwt-secret-too-short::{}::{}",
                self.secret.len(),
                MIN_SECRET_BYTES
            )));
        }
        if timeout < 0 {
            return Err(GarrisonError::Config(format!(
                "jwt-timeout-negative::{}",
                timeout
            )));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| GarrisonError::Internal(format!("system-clock-error::{}", e)))?
            .as_secs() as i64;
        // 算法-密钥类型匹配校验（fail-closed）：防字段被直接改写绕过构造器
        validate_algorithm_match(&self.key_material, self.algorithm)?;
        // 溢出防护：`now + timeout` 在 timeout 接近 i64::MAX 时会溢出
        // （debug panic / release 回绕为负 exp，产生立即过期的 token）。
        // 溢出视为非法参数，fail-fast 返回 InvalidParam。
        let exp = now.checked_add(timeout).ok_or_else(|| {
            GarrisonError::InvalidParam(format!("jwt-timeout-overflow::{}", timeout))
        })?;
        let claims = GarrisonJwtClaims {
            sub: login_id.clone(),
            iat: now,
            exp,
            login_id,
            device: self.device.clone(),
            jti: Some(uuid::Uuid::new_v4().to_string()),
            nbf: Some(now), // 签发时设置 nbf，verify 时强制校验
        };
        let header = Header::new(self.algorithm);
        let key = match &self.key_material {
            KeyMaterial::Hs => EncodingKey::from_secret(self.secret.as_bytes()),
            KeyMaterial::RsaPkcs1Pem(pem) => EncodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|e| GarrisonError::Internal(format!("jwt-rsa-key::{}", e)))?,
            KeyMaterial::EcPem(pem) => EncodingKey::from_ec_pem(pem.as_bytes())
                .map_err(|e| GarrisonError::Internal(format!("jwt-ec-key::{}", e)))?,
            KeyMaterial::EdPem(pem) => EncodingKey::from_ed_pem(pem.as_bytes())
                .map_err(|e| GarrisonError::Internal(format!("jwt-ed-key::{}", e)))?,
        };
        encode(&header, &claims, &key)
            .map_err(|e| GarrisonError::Internal(format!("jwt-sign::{}", e)))
    }

    /// 校验 JWT 并返回 Claims。
    ///
    /// # 参数
    /// - `token`: JWT 字符串。
    ///
    /// # 返回
    /// - `Ok(GarrisonJwtClaims)`: 校验成功。
    /// - `Err(GarrisonError::Config)`: secret 为空。
    /// - `Err(GarrisonError::ExpiredToken)`: token 已过期。
    /// - `Err(GarrisonError::InvalidToken)`: 签名/格式/算法校验失败。
    pub fn verify(&self, token: &str) -> GarrisonResult<GarrisonJwtClaims> {
        // 空密钥检查仅对称路径适用（与 sign 一致）：config 层允许非对称算法下
        // jwt_secret 留空作占位（密钥强度由 PEM 决定），无条件检查会误拒该合法配置
        if matches!(self.key_material, KeyMaterial::Hs) && self.secret.is_empty() {
            return Err(GarrisonError::Config("jwt-secret-empty::".to_string()));
        }
        // JWT 密钥最小长度校验（防暴力破解，仅对称路径适用）
        if matches!(self.key_material, KeyMaterial::Hs) && self.secret.len() < MIN_SECRET_BYTES {
            return Err(GarrisonError::Config(format!(
                "jwt-secret-too-short::{}::{}",
                self.secret.len(),
                MIN_SECRET_BYTES
            )));
        }
        // 算法-密钥类型匹配校验（fail-closed）：防字段被直接改写绕过构造器
        validate_algorithm_match(&self.key_material, self.algorithm)?;
        let key = match &self.key_material {
            KeyMaterial::Hs => DecodingKey::from_secret(self.secret.as_bytes()),
            KeyMaterial::RsaPkcs1Pem(pem) => {
                // jsonwebtoken 的 DecodingKey::from_rsa_pem 仅接受公钥 PEM；私钥 PEM
                // 需自行提取公钥组件 (n, e)。用 pkcs1/pkcs8（纯 DER 解析，无 RSA 运算）
                // 读取，garrison 代码不接触 rsa crate（RUSTSEC-2023-0071 仅影响其解密路径）
                let (n, e) = extract_rsa_public_components(pem)?;
                DecodingKey::from_rsa_components(&n, &e)
                    .map_err(|e| GarrisonError::Internal(format!("jwt-rsa-key::{}", e)))?
            },
            KeyMaterial::EcPem(pem) => {
                // jsonwebtoken 验证端仅接受 SEC1 未压缩公钥字节（from_sec1_bytes）；
                // 私钥 PEM 需经曲线标量乘法计算公钥点（p256/p384 为 jsonwebtoken
                // rust_crypto 传递依赖，显式化零新增体积）
                let sec1 = extract_ec_public_sec1(pem)?;
                // from_ec_der 为原样字节入口，验证端内部用 VerifyingKey::from_sec1_bytes 消费
                DecodingKey::from_ec_der(&sec1)
            },
            KeyMaterial::EdPem(pem) => {
                // Ed25519 验证端需要 32 字节公钥（base64url，from_ed_components）；
                // RFC 8410 PKCS#8 的 private_key 即 32 字节种子，经 ed25519-dalek
                // 计算对应公钥（2.2.0 已修 RUSTSEC-2022-0093，树内版本不受影响）
                let seed = extract_ed25519_seed(pem)?;
                use base64::Engine;
                let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
                let b64 =
                    |data: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
                DecodingKey::from_ed_components(&b64(signing.verifying_key().as_bytes()))
                    .map_err(|e| GarrisonError::Internal(format!("jwt-ed-key::{}", e)))?
            },
        };
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = true;
        validation.validate_nbf = true; // 拒绝 nbf 为未来的 token
                                        // leeway=0：不容忍时钟偏差，过期立即拒绝（安全框架默认严格）
        validation.leeway = 0;
        decode::<GarrisonJwtClaims>(token, &key, &validation)
            .map(|data| data.claims)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("ExpiredSignature") {
                    GarrisonError::ExpiredToken(format!("jwt-expired::{}", e))
                } else if msg.contains("ImmatureSignature") || msg.contains("nbf") {
                    // nbf 为未来时间 → ImmatureSignature
                    GarrisonError::InvalidToken(format!("jwt-not-yet-valid::{}", e))
                } else {
                    GarrisonError::InvalidToken(format!("jwt-invalid::{}", e))
                }
            })
    }

    /// 刷新 JWT：解析旧 token 的 claims → 签发新 token。
    ///
    /// # 参数
    /// - `token`: 旧 JWT 字符串（需可成功 verify）。
    /// - `new_timeout`: 新 token 的有效期（秒）。
    ///
    /// # 返回
    /// - `Ok(String)`: 新 JWT 字符串。
    /// - `Err(GarrisonError)`: 旧 token 校验失败或新 token 签发失败。
    pub fn refresh(&self, token: &str, new_timeout: i64) -> GarrisonResult<String> {
        let claims = self.verify(token)?;
        self.sign(claims.login_id, new_timeout)
    }
}

// Drop 零化仅在 `protocol-zeroize` feature 下编译：启用后密钥内存在 handler 析构时
// 被覆写；未启用时为普通 `String` 释放，内存内容不保证被清除（可能残留于已释放
// 堆块 / swap / core dump）。保持 feature 结构（零开销默认构建），对密钥卫生有
// 要求的部署应显式启用 `protocol-zeroize`；`secret` 字段的可读性风险见
// `JwtHandler::secret` 字段文档。
#[cfg(feature = "protocol-zeroize")]
impl Drop for JwtHandler {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}
