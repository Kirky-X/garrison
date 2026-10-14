// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `HttpDigestAuth` 实现块，封装 RFC 7616 质询生成与响应校验。

use super::algorithm::hex_encode;
use super::{DigestAlgorithm, HttpDigestAuth};
use crate::error::{GarrisonError, GarrisonResult};
use crate::secure::ct_eq::constant_time_eq;
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// nonce 服务端签名 HKDF info（域分隔，避免与其他 HKDF 派生密钥域混用）。
const NONCE_HMAC_HKDF_INFO: &[u8] = b"garrison-httpdigest-nonce-v1";

/// 默认 nonce 有效期（秒），RFC 7616 §3.2.1 建议 nonce 应有合理 TTL。
const DEFAULT_NONCE_TTL_SECONDS: u64 = 300;
/// Authorization header 上限 8KB（正常 Digest header < 1KB）；超限时 `validate_inner` 直接拒绝认证，
/// 不进入 O(n) 解析 + 多次 hash，防恶意超长输入放大 CPU。
const MAX_AUTHORIZATION_HEADER_LEN: usize = 8 * 1024;
/// DAO 错误日志采样间隔：每 N 次错误只 warn 一次，其余降级 `debug!`，防 DAO 持续故障时日志洪水。
const DAO_ERROR_LOG_INTERVAL: u64 = 100;
/// DAO 错误日志采样计数器（进程级共享）：保证 warn 总量 = 错误数 / INTERVAL，与实例数无关。
static DAO_ERROR_LOG_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl HttpDigestAuth {
    /// 创建 Digest 认证工具（`algorithm` 取 "MD5" / "SHA256"，大小写不敏感）。
    ///
    /// 不支持的算法返回 `Err(GarrisonError::Internal)`。
    pub fn new(realm: &str, algorithm: &str) -> GarrisonResult<Self> {
        let algorithm: DigestAlgorithm = algorithm.parse()?;
        if algorithm == DigestAlgorithm::Md5 {
            // MD5 无 feature 门控，改为运行时告警便于审计每次使用（碰撞攻击风险，新系统须用 SHA256）
            tracing::warn!(
                realm = %realm,
                algorithm = "MD5",
                "HttpDigestAuth constructed with MD5; MD5 is collision-broken and must not be used in new deployments (use SHA256)"
            );
        }
        Ok(Self {
            realm: realm.to_string(),
            algorithm,
            nonce_ttl: DEFAULT_NONCE_TTL_SECONDS,
            dao: None,
            server_key: None,
        })
    }

    /// 注入 DAO 用于 nc 单调性校验（RFC 7616 §3.4.6）：跟踪每个 nonce 的最后 nc，拒绝回退/重复（重放）。
    ///
    /// 未注入时跳过 nc 校验，仅靠 nonce TTL（默认 300s 窗口内仍可重放），生产环境强烈建议注入。
    /// `validate*` 是 sync API 而 DAO 是 async：内部用 `block_in_place` + `Handle::block_on` 桥接，
    /// **须在 multi_thread tokio runtime 调用**（无 runtime / current_thread 下 fail-closed 并 warn）。
    /// `block_in_place` 会把 worker 转 blocking，高 QPS（如 API 网关）下需调优 worker / `max_blocking_threads`；
    /// fail-closed 下 DAO 持续故障会使 digest auth 整体不可用（等同 P1），需健康度监控与高可用 DAO（Sentinel/Cluster）。
    pub fn with_dao(mut self, dao: std::sync::Arc<dyn crate::dao::GarrisonDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 设置 nonce 有效期（秒），默认 300 秒。
    pub fn with_nonce_ttl(mut self, ttl_seconds: u64) -> Self {
        self.nonce_ttl = ttl_seconds;
        self
    }

    /// 注入服务端签名密钥：`HKDF-SHA256(salt = realm, ikm = secret, info = NONCE_HMAC_HKDF_INFO)` 派生 32 字节 HMAC 密钥（复用 protocol-sign 域分隔范式）。
    ///
    /// 注入后 nonce 带服务端 HMAC 签名，`is_nonce_valid` 先验签名再校验时间戳，拒绝自铸（无有效签名）的 nonce。
    pub fn with_server_key(mut self, secret: &[u8]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(self.realm.as_bytes()), secret);
        let mut key = [0u8; 32];
        hkdf.expand(NONCE_HMAC_HKDF_INFO, &mut key)
            .expect("HKDF-SHA256 derive 32 bytes must not fail");
        self.server_key = Some(key);
        self
    }

    /// 获取 nonce 有效期（秒）。
    pub fn nonce_ttl(&self) -> u64 {
        self.nonce_ttl
    }

    /// 获取当前算法。
    pub fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// 生成 `WWW-Authenticate` 质询头：`Digest realm="...", nonce="...", qop="auth,auth-int", algorithm=...`。
    pub fn challenge(&self) -> String {
        let nonce = self.generate_nonce();
        format!(
            r#"Digest realm="{}", nonce="{}", qop="auth,auth-int", algorithm={}"#,
            self.realm,
            nonce,
            self.algorithm.as_str()
        )
    }

    /// 生成带时间戳的 nonce：`base64("{timestamp}:{random_uuid}")`；注入 `server_key` 时为 `base64("{timestamp}:{uuid}:{hmac_sha256(server_key, timestamp:uuid)}")`。
    fn generate_nonce(&self) -> String {
        let timestamp = current_unix_seconds();
        let random = Uuid::new_v4().simple().to_string();
        let raw = match &self.server_key {
            Some(key) => {
                let mac = sign_nonce_payload(key, timestamp, &random);
                format!("{}:{}:{}", timestamp, random, mac)
            },
            None => format!("{}:{}", timestamp, random),
        };
        STANDARD.encode(raw.as_bytes())
    }

    /// 校验 nonce 是否有效：格式正确、注入 `server_key` 时 HMAC 签名有效（公共常量时间原语，ADR-0003）、时间戳未过期；任一步失败即拒绝。
    pub(super) fn is_nonce_valid(&self, nonce: &str) -> bool {
        let decoded = match STANDARD.decode(nonce) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let raw = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let now = current_unix_seconds();
        match &self.server_key {
            Some(key) => {
                // 签名格式：timestamp:uuid:mac（3 段）
                let parts: Vec<&str> = raw.splitn(3, ':').collect();
                if parts.len() != 3 {
                    return false;
                }
                let timestamp: u64 = match parts[0].parse() {
                    Ok(t) => t,
                    Err(_) => return false,
                };
                // 先验签名（先验 HMAC 再计时间戳，杜绝自铸 nonce）
                if !verify_nonce_signature(key, timestamp, parts[1], parts[2]) {
                    return false;
                }
                // 防止未来时间戳（允许 5 秒时钟漂移）
                if timestamp > now + 5 {
                    return false;
                }
                if timestamp + self.nonce_ttl < now {
                    return false;
                }
                true
            },
            None => {
                // 无签名格式（未注入 server_key）：timestamp:random（2 段）
                let parts: Vec<&str> = raw.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return false;
                }
                let timestamp: u64 = match parts[0].parse() {
                    Ok(t) => t,
                    Err(_) => return false,
                };
                if timestamp > now + 5 {
                    return false;
                }
                if timestamp + self.nonce_ttl < now {
                    return false;
                }
                true
            },
        }
    }

    /// 校验 nc 单调性防重放（RFC 7616 §3.4.6）：DAO 跟踪 `digest:nc:{nonce}` 的最后接受 nc（TTL 同 `nonce_ttl`）。
    ///
    /// 无 DAO 时跳过校验（fail-open：仅 TTL 防护，300s 内可重放，进程级 warn 一次）；DAO 错误或 nc 非法 hex
    /// 返回 false（fail-closed）；无 runtime / current_thread runtime 亦 fail-closed + warn（桥接约束同 `with_dao`）。
    fn validate_nc(&self, nonce: &str, nc_hex: &str) -> bool {
        let dao = match &self.dao {
            Some(d) => d,
            None => {
                // fail-open：未注入 DAO 时跳过 nc 校验（仅 TTL 防护，300s 内可重放）；进程级 warn 一次提醒注入 DAO。
                static WARNED_NO_DAO: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !WARNED_NO_DAO.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    tracing::warn!(
                        realm = %self.realm,
                        "validate_nc: no DAO injected, skipping nc monotonicity check (fail-open, replay possible within the 300s window); in production inject a DAO via with_dao to enable RFC 7616 §3.4.6 replay protection"
                    );
                }
                return true;
            },
        };
        // 解析 nc hex → u64（RFC 7616 §3.4.6：nc 为 8 位 hex）
        let nc = match u64::from_str_radix(nc_hex, 16) {
            Ok(v) => v,
            Err(_) => return false,
        };
        // 桥接 sync-to-async 要求 multi_thread runtime：`block_in_place` 在 current_thread 下会 panic，
        // 故 current_thread / 无 runtime 一律 fail-closed 拒绝（拒绝优于放行）。
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
                    tracing::warn!(
                        realm = %self.realm,
                        "validate_nc rejected: current_thread runtime does not support block_in_place (fail-closed per vuln-0012)"
                    );
                    return false; // fail-closed
                }
                let realm = self.realm.clone();
                tokio::task::block_in_place(|| {
                    handle.block_on(async move {
                        Self::validate_nc_async(dao, &realm, nonce, nc, self.nonce_ttl).await
                    })
                })
            },
            Err(_) => {
                tracing::warn!(
                    realm = %self.realm,
                    "validate_nc rejected: no tokio runtime available (fail-closed per vuln-0012)"
                );
                false // fail-closed
            },
        }
    }

    /// `validate_nc` 的 async 实现：经 `dao.compare_and_update_if_greater` 原子完成「读 last_nc → 比较 → 写」，消除 TOCTOU。
    ///
    /// 返回 `Ok(true)` 表示 nc > last_nc 已更新，`Ok(false)` 表示重放/回退；DAO 错误 fail-closed（返回 false）。
    async fn validate_nc_async(
        dao: &std::sync::Arc<dyn crate::dao::GarrisonDao>,
        realm: &str,
        nonce: &str,
        nc: u64,
        ttl_seconds: u64,
    ) -> bool {
        let key = format!("digest:nc:{}", nonce);
        match dao
            .compare_and_update_if_greater(&key, nc, ttl_seconds)
            .await
        {
            Ok(updated) => updated,
            Err(e) => {
                // fail-closed：DAO 错误即拒绝（nonce TTL 不足以防重放）。日志采样：每 N 次错误只 warn 一次，
                // 其余降级 debug!（不传 error 避免 Display 求值开销）；warn 含采样计数 + realm + error 便于推算真实错误量。
                let count =
                    DAO_ERROR_LOG_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if count.is_multiple_of(DAO_ERROR_LOG_INTERVAL) {
                    tracing::warn!(
                        realm = realm,
                        count = count + 1,
                        error = %e,
                        "validate_nc: DAO compare_and_update_if_greater failed, fail-closed (sampled 1/{})",
                        DAO_ERROR_LOG_INTERVAL
                    );
                } else {
                    tracing::debug!(
                        realm = realm,
                        count = count + 1,
                        "validate_nc: DAO compare_and_update_if_greater failed, fail-closed (sampled, suppressed warn)"
                    );
                }
                false
            },
        }
    }

    /// 计算 HA1 = H(username:realm:password)（预计算摘要，避免框架持有明文密码；算法依实例配置）。
    pub fn compute_ha1(&self, username: &str, password: &str) -> String {
        let data = format!("{}:{}:{}", username, self.realm, password);
        self.algorithm.hash(data.as_bytes())
    }

    /// 校验客户端 Authorization header（仅 qop=auth）；qop=auth-int 直接拒绝，须改用 [`validate_with_body`](Self::validate_with_body) 传入请求体。
    ///
    /// 失败（返回 `false`）覆盖：密码错 / method 不匹配 / qop 不支持 / nonce 过期或格式错 / nc 重放 / uri 不一致。
    pub fn validate(&self, authorization_header: &str, method: &str, uri: &str, ha1: &str) -> bool {
        self.validate_inner(authorization_header, method, uri, None, ha1)
    }

    /// 校验客户端 Authorization header（支持 qop=auth 与 qop=auth-int）。
    ///
    /// auth-int 时 HA2 = H(method:uri:H(body))（需传入请求体）；qop=auth 时 HA2 = H(method:uri)，body 被忽略。
    pub fn validate_with_body(
        &self,
        authorization_header: &str,
        method: &str,
        uri: &str,
        body: &[u8],
        ha1: &str,
    ) -> bool {
        self.validate_inner(authorization_header, method, uri, Some(body), ha1)
    }

    /// 内部校验逻辑，统一处理 qop=auth 和 qop=auth-int。
    fn validate_inner(
        &self,
        authorization_header: &str,
        method: &str,
        uri: &str,
        body: Option<&[u8]>,
        ha1: &str,
    ) -> bool {
        // 超长 header 会放大 O(n) 解析 + 多次 hash 计算；8KB 上限覆盖所有合法请求并拒绝恶意输入。
        if authorization_header.len() > MAX_AUTHORIZATION_HEADER_LEN {
            return false;
        }
        match self.parse_authorization(authorization_header) {
            Ok(resp) => {
                if !self.is_nonce_valid(&resp.nonce) {
                    return false;
                }
                // nc 单调性校验：拒绝同一 nonce 的 nc 回退/重复（防重放，RFC 7616 §3.4.6）
                if !self.validate_nc(&resp.nonce, &resp.nc) {
                    return false;
                }
                // RFC 7616 §3.4.6: 校验客户端 uri 与实际请求 URI 一致（常量时间比较，防跨 URI 重放）
                if !constant_time_eq(resp.uri.as_bytes(), uri.as_bytes()) {
                    return false;
                }
                let qop = resp.qop.as_deref();
                let ha2 = match qop {
                    Some("auth") => {
                        let ha2_input = format!("{}:{}", method, uri);
                        self.algorithm.hash(ha2_input.as_bytes())
                    },
                    Some("auth-int") => {
                        // auth-int 的 HA2 = H(method:uri:H(body))；body 缺失即拒绝（fail-closed），
                        // 防用空 body 预计算合法 response 绕过 body 绑定校验。
                        let body_bytes = match body {
                            Some(b) => b,
                            None => return false,
                        };
                        let body_hash = self.algorithm.hash(body_bytes);
                        let ha2_input = format!("{}:{}:{}", method, uri, body_hash);
                        self.algorithm.hash(ha2_input.as_bytes())
                    },
                    _ => return false,
                };
                // 计算 response = H(HA1:nonce:nc:cnonce:qop:HA2)
                let response_input = format!(
                    "{}:{}:{}:{}:{}:{}",
                    ha1,
                    resp.nonce,
                    resp.nc,
                    resp.cnonce,
                    qop.unwrap(),
                    ha2
                );
                let expected = self.algorithm.hash(response_input.as_bytes());
                // 常量时间比较防时序攻击；response 长度是公开协议参数（hex 后 MD5 32 / SHA-256 64），
                // 长度不符必然不等，提前短路——客户端可控长度不得进入比较循环放大计算量
                resp.response.len() == expected.len()
                    && constant_time_eq(expected.as_bytes(), resp.response.as_bytes())
            },
            Err(_) => false,
        }
    }

    /// 解析 Authorization header 为 DigestResponse。
    fn parse_authorization(&self, header: &str) -> GarrisonResult<DigestResponse> {
        let header = header.trim();
        let (scheme, params) = header
            .split_once(char::is_whitespace)
            .ok_or_else(|| GarrisonError::Internal("secure-http-digest-no-params::".to_string()))?;

        if !scheme.eq_ignore_ascii_case("digest") {
            return Err(GarrisonError::Internal(format!(
                "secure-httpdigest-unsupported-scheme::{}",
                scheme
            )));
        }

        let mut nonce = None;
        let mut response = None;
        let mut qop = None;
        let mut nc = None;
        let mut cnonce = None;
        let mut uri = None;

        for (key, value) in parse_digest_params(params) {
            match key.as_str() {
                // username/realm/uri 由 RFC 7616 要求存在，但 validate() 不使用，仅校验存在性
                "username" | "realm" => {},
                "uri" => uri = Some(value),
                "nonce" => nonce = Some(value),
                "response" => response = Some(value),
                "qop" => qop = Some(value),
                "nc" => nc = Some(value),
                "cnonce" => cnonce = Some(value),
                _ => {
                    tracing::debug!(key = %key, "httpdigest-unknown-param-ignored");
                },
            }
        }

        Ok(DigestResponse {
            nonce: nonce.ok_or_else(|| {
                GarrisonError::Internal("secure-http-digest-missing-nonce::".to_string())
            })?,
            response: response.ok_or_else(|| {
                GarrisonError::Internal("secure-http-digest-missing-response::".to_string())
            })?,
            qop,
            nc: nc.ok_or_else(|| {
                GarrisonError::Internal("secure-http-digest-missing-nc::".to_string())
            })?,
            cnonce: cnonce.ok_or_else(|| {
                GarrisonError::Internal("secure-http-digest-missing-cnonce::".to_string())
            })?,
            uri: uri.ok_or_else(|| {
                GarrisonError::Internal("secure-http-digest-missing-uri::".to_string())
            })?,
        })
    }
}

/// Digest 响应参数（解析自客户端 Authorization header）。
///
/// 仅保留 `validate()` 实际使用的字段；username/realm 虽由 RFC 7616 要求且校验存在性，但不存储（避免死字段）。
#[derive(Debug, Clone)]
struct DigestResponse {
    nonce: String,
    response: String,
    qop: Option<String>,
    nc: String,
    cnonce: String,
    /// RFC 7616 要求服务端校验客户端 uri 与实际请求 URI 一致，防止 digest 跨 URI 重放。
    uri: String,
}

/// 解析 Digest 参数串（key=value 或 key="quoted value" 形式，依据 RFC 7616）。
fn parse_digest_params(s: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();

    while chars.peek().is_some() {
        skip_whitespace_and_commas(&mut chars);
        if chars.peek().is_none() {
            break;
        }
        let key = parse_param_key(&mut chars);
        skip_whitespace_chars(&mut chars);
        if chars.peek() != Some(&'=') {
            break;
        }
        chars.next();
        skip_whitespace_chars(&mut chars);
        let value = parse_param_value(&mut chars);
        if !key.is_empty() {
            result.push((key, value));
        }
    }
    result
}

/// 跳过空白和逗号分隔符。
fn skip_whitespace_and_commas(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while matches!(chars.peek(), Some(c) if c.is_whitespace() || *c == ',') {
        chars.next();
    }
}

/// 跳过空白字符。
fn skip_whitespace_chars(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
        chars.next();
    }
}

/// 解析参数键名（到空白或 `=` 为止）。
fn parse_param_key(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut key = String::new();
    while let Some(c) = chars.peek() {
        if c.is_whitespace() || *c == '=' {
            break;
        }
        key.push(chars.next().unwrap());
    }
    key
}

/// 解析参数值：引号值（支持反斜杠转义）或非引号值。
fn parse_param_value(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    if chars.peek() == Some(&'"') {
        parse_quoted_value(chars)
    } else {
        parse_unquoted_value(chars)
    }
}

/// 解析引号包裹的值（支持 `\` 转义）。
fn parse_quoted_value(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    chars.next(); // consume opening quote
    let mut value = String::new();
    while let Some(c) = chars.next() {
        if c == '"' {
            break;
        }
        if c == '\\' {
            if let Some(escaped) = chars.next() {
                value.push(escaped);
            }
        } else {
            value.push(c);
        }
    }
    value
}

/// 解析非引号值（到空白或逗号为止）。
fn parse_unquoted_value(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut value = String::new();
    while let Some(c) = chars.peek() {
        if c.is_whitespace() || *c == ',' {
            break;
        }
        value.push(chars.next().unwrap());
    }
    value
}

/// 获取当前 Unix 时间戳（秒）。
pub(super) fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 计算 nonce 服务端签名：`hmac_sha256(server_key, "{timestamp}:{uuid}")` 的 hex 编码。
fn sign_nonce_payload(server_key: &[u8; 32], timestamp: u64, uuid: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(server_key).expect("HMAC accepts 32-byte keys");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b":");
    mac.update(uuid.as_bytes());
    let result = mac.finalize().into_bytes();
    hex_encode(&result)
}

/// 校验 nonce 服务端签名（常量时间比较）。
fn verify_nonce_signature(
    server_key: &[u8; 32],
    timestamp: u64,
    uuid: &str,
    mac_hex: &str,
) -> bool {
    let expected = sign_nonce_payload(server_key, timestamp, uuid);
    // mac 长度是公开参数（HMAC-SHA256 hex 64 字符），长度不符必然不等，
    // 提前短路避免客户端可控的超长输入进入比较循环
    mac_hex.len() == expected.len() && constant_time_eq(expected.as_bytes(), mac_hex.as_bytes())
}
