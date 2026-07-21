//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `HttpDigestAuth` 实现块，封装 RFC 7616 质询生成与响应校验。

use super::{DigestAlgorithm, HttpDigestAuth};
use crate::error::{GarrisonError, GarrisonResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// 默认 nonce 有效期（秒），RFC 7616 §3.2.1 建议 nonce 应有合理 TTL。
const DEFAULT_NONCE_TTL_SECONDS: u64 = 300;
/// Authorization header 最大长度（字节），L5 修复：防止超长 header 导致 DoS。
///
/// 8KB 覆盖正常 Digest Auth header（通常 < 1KB），拒绝明显恶意的超长输入。
/// 超过此长度时 validate_inner 直接返回 false（拒绝认证），不进入 parse_authorization
/// 避免 O(n) 解析 + 多次 hash 计算被恶意输入放大。
const MAX_AUTHORIZATION_HEADER_LEN: usize = 8 * 1024;
/// DAO 错误日志采样间隔（vuln-0012 性能修复：防止 DAO 持续故障期间日志洪水）。
///
/// 每 `DAO_ERROR_LOG_INTERVAL` 次 DAO 错误只打一次 `warn!`，其余降级为 `debug!`。
/// 100 是平衡可观测性与 I/O 开销的经验值（1000 QPS × 30s 故障 = 30000 次 → 300 条 warn）。
const DAO_ERROR_LOG_INTERVAL: u64 = 100;
/// DAO 错误日志采样计数器（进程级，跨所有 `HttpDigestAuth` 实例共享）。
///
/// **设计选型**：进程级共享（而非 per-instance）保证采样比例准确——若每个实例独立计数，
/// 多实例部署时 warn 总量 = 实例数 × (错误数 / INTERVAL)，仍可能打满日志磁盘。
/// 进程级共享确保无论多少实例，warn 总量 = 错误数 / INTERVAL。
static DAO_ERROR_LOG_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl HttpDigestAuth {
    /// 创建新的 Digest 认证工具。
    ///
    /// # 参数
    /// - `realm`: 认证域。
    /// - `algorithm`: 算法字符串（"MD5" / "SHA256"，大小写不敏感）。
    ///
    /// # 返回
    /// - `Ok(Self)`: 构造成功。
    /// - `Err(GarrisonError::Internal)`: 不支持的算法。
    pub fn new(realm: &str, algorithm: &str) -> GarrisonResult<Self> {
        Ok(Self {
            realm: realm.to_string(),
            algorithm: algorithm.parse()?,
            nonce_ttl: DEFAULT_NONCE_TTL_SECONDS,
            dao: None,
        })
    }

    /// 注入 DAO 用于 nc 单调性校验（vuln-0008 修复，RFC 7616 §3.4.6）。
    ///
    /// 注入后 `validate` / `validate_with_body` 会通过 DAO 跟踪每个 nonce 的最后 nc 值，
    /// 拒绝 nc 回退或重复（重放攻击）。未注入时跳过 nc 校验（向后兼容，仅依赖 nonce TTL 防护，
    /// 300s 窗口内仍可重放——生产环境强烈建议注入 DAO）。
    ///
    /// # 参数
    /// - `dao`: 分布式 DAO 实现（Redis / dbnexus / MockDao 等）。
    ///
    /// # 运行时要求
    ///
    /// `validate` / `validate_with_body` 是 sync API，但 DAO 操作是 async。
    /// 注入 DAO 后，validate 内部使用 `tokio::task::block_in_place` + `Handle::block_on`
    /// 桥接 sync-to-async，**要求在 multi_thread tokio runtime 上下文中调用**。
    /// 在无 runtime 或 current_thread runtime 下调用会拒绝 nc 校验（fail-closed，
    /// vuln-0012 修复：原 fail-open 允许重放，违背 RFC 7616 §3.4.6）并记录 warn。
    ///
    /// # 容量规划
    ///
    /// `block_in_place` 会把当前 tokio worker thread 转为 blocking thread。
    /// 高频 digest auth 场景（如 API 网关）下，多个并发请求会同时占用 worker thread
    /// 等 DAO I/O，可能耗尽默认 worker pool。建议通过 `tokio::runtime::Builder::worker_threads(n)`
    /// 调优 worker 数量，或使用 `max_blocking_threads` 增加 blocking 线程上限。
    ///
    /// # 运维注意
    ///
    /// fail-closed 策略下，DAO 持续故障会导致所有 digest auth 请求被拒绝
    /// （等同 digest auth 服务不可用）。建议部署 DAO 健康度监控 + 告警，
    /// DAO 故障视为 P1 事件。生产环境必须使用高可用 DAO（Redis Sentinel/Cluster）。
    pub fn with_dao(mut self, dao: std::sync::Arc<dyn crate::dao::GarrisonDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 设置 nonce 有效期（秒），默认 300 秒。
    pub fn with_nonce_ttl(mut self, ttl_seconds: u64) -> Self {
        self.nonce_ttl = ttl_seconds;
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

    /// 生成 WWW-Authenticate 质询头。
    ///
    /// # 返回
    /// 形如 `Digest realm="...", nonce="...", qop="auth,auth-int", algorithm=SHA256` 的字符串。
    /// nonce 为 `base64(timestamp:random_uuid)` 格式，validate 时校验时间戳。
    pub fn challenge(&self) -> String {
        let nonce = self.generate_nonce();
        format!(
            r#"Digest realm="{}", nonce="{}", qop="auth,auth-int", algorithm={}"#,
            self.realm,
            nonce,
            self.algorithm.as_str()
        )
    }

    /// 生成带时间戳的 nonce。
    ///
    /// 格式：`base64("{timestamp}:{random_uuid}")`
    /// - timestamp: 当前 Unix 秒
    /// - random_uuid: UUID v4（保证唯一性）
    fn generate_nonce(&self) -> String {
        let timestamp = current_unix_seconds();
        let random = Uuid::new_v4().simple().to_string();
        let raw = format!("{}:{}", timestamp, random);
        STANDARD.encode(raw.as_bytes())
    }

    /// 校验 nonce 是否有效（格式正确且未过期）。
    ///
    /// nonce 格式: `base64("{timestamp}:{random}")`
    /// - 解码失败 → 无效
    /// - timestamp 非数字 → 无效
    /// - timestamp 在未来 → 无效（防止客户端伪造未来 nonce）
    /// - 已超过 TTL → 无效（过期）
    pub(super) fn is_nonce_valid(&self, nonce: &str) -> bool {
        let decoded = match STANDARD.decode(nonce) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let raw = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let parts: Vec<&str> = raw.splitn(2, ':').collect();
        if parts.len() != 2 {
            return false;
        }
        let timestamp: u64 = match parts[0].parse() {
            Ok(t) => t,
            Err(_) => return false,
        };
        let now = current_unix_seconds();
        // 防止未来时间戳（允许 5 秒时钟漂移）
        if timestamp > now + 5 {
            return false;
        }
        // 检查是否过期
        if timestamp + self.nonce_ttl < now {
            return false;
        }
        true
    }

    /// 校验 nc（nonce count）单调性，拒绝重放攻击（vuln-0008，RFC 7616 §3.4.6）。
    ///
    /// 通过 DAO 跟踪每个 nonce 的最后接受的 nc 值，拒绝 nc 回退或重复。
    /// - `dao` 为 None：跳过校验（返回 true，向后兼容）。
    ///   **安全代价**：仅依赖 nonce TTL 防护（默认 300s），300s 窗口内可任意重放。
    ///   生产环境强烈建议通过 `with_dao` 注入 DAO；仅单元测试 / 无重放风险场景可省略。
    /// - `dao` 为 Some：get `digest:nc:{nonce}` → 比较 → set 更新
    /// - DAO 错误：fail-closed（返回 false，vuln-0012 修复：原 fail-open 允许重放，
    ///   违背 RFC 7616 §3.4.6；nonce TTL 不足以防重放，仅时间 bounded）
    /// - nc 非法 hex 格式：返回 false（拒绝畸形请求）
    /// - 无 runtime / current_thread runtime：fail-closed（返回 false）
    ///
    /// # Key 格式
    ///
    /// `digest:nc:{nonce}` — value 为最后接受的 nc 十进制字符串。
    /// TTL 与 `nonce_ttl` 一致，nonce 过期后 nc 记录自动清理。
    ///
    /// # 运行时要求
    ///
    /// `validate` / `validate_with_body` 是 sync API，但 DAO 操作是 async。
    /// 注入 DAO 后，本方法使用 `tokio::task::block_in_place` + `Handle::block_on`
    /// 桥接 sync-to-async，要求 multi_thread tokio runtime。
    /// 无 runtime / current_thread runtime 时 fail-closed（返回 false）并记录 warn
    /// （vuln-0012 修复：原 fail-open 允许重放）。
    fn validate_nc(&self, nonce: &str, nc_hex: &str) -> bool {
        let dao = match &self.dao {
            Some(d) => d,
            None => return true,
        };
        // 解析 nc hex → u64（RFC 7616 §3.4.6：nc 为 8 位 hex）
        let nc = match u64::from_str_radix(nc_hex, 16) {
            Ok(v) => v,
            Err(_) => return false,
        };
        // 桥接 sync-to-async：要求 multi_thread tokio runtime。
        // `Handle::try_current()` 对 multi_thread 和 current_thread runtime
        // 都返回 `Ok(handle)`，但 `block_in_place` 在 current_thread runtime 下会 panic
        // （"Cannot block the current thread from within a runtime"）。
        // vuln-0012 修复：原 fail-open 允许重放，改为 fail-closed（拒绝请求），
        // 强制要求 multi_thread runtime 才能使用 DAO 注入的 nc 校验。
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread {
                    tracing::warn!(
                        realm = %self.realm,
                        "validate_nc rejected: current_thread runtime does not support block_in_place (fail-closed per vuln-0012)"
                    );
                    return false; // fail-closed (vuln-0012)
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
                false // fail-closed (vuln-0012)
            },
        }
    }

    /// `validate_nc` 的 async 实现（通过 `block_in_place` + `block_on` 调用）。
    ///
    /// 通过 `dao.compare_and_update_if_greater` 原子地完成「读取当前 last_nc → 比较 → 写入新 nc」，
    /// 消除 TOCTOU 竞态（多个并发请求都读到相同的 last_nc 值，都通过 nc > last_nc 检查）。
    ///
    /// 逻辑：
    /// - `compare_and_update_if_greater` 返回 `Ok(true)`：nc > last_nc，已更新 → return true
    /// - `compare_and_update_if_greater` 返回 `Ok(false)`：nc <= last_nc，重放/回退 → return false
    /// - DAO 错误 → fail-closed（return false）+ warn（vuln-0012 修复：原 fail-open 允许重放）
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
                // fail-closed (vuln-0012)：DAO 错误时拒绝请求，强制要求 DAO 可用。
                // nonce TTL 不足以防重放（300s 窗口内仍可重放），必须 fail-closed。
                //
                // 日志采样（vuln-0012 性能修复）：DAO 持续故障期间每次请求都会触发错误，
                // 高 QPS 下会瞬间打满日志磁盘。每 DAO_ERROR_LOG_INTERVAL 次错误只 warn 一次，
                // 其余降级为 debug!（仅含 count，不传 error 避免 Display 求值开销），
                // warn 中含采样计数 + realm + error，可推算真实错误量并定位受影响实例。
                let count =
                    DAO_ERROR_LOG_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if count % DAO_ERROR_LOG_INTERVAL == 0 {
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

    /// 计算 HA1 = H(username:realm:password)。
    ///
    /// HA1 为预先计算的摘要，避免框架持有明文密码。
    /// 算法依据实例配置（MD5 或 SHA256）。
    ///
    /// # 参数
    /// - `username`: 用户名。
    /// - `password`: 密码。
    pub fn compute_ha1(&self, username: &str, password: &str) -> String {
        let data = format!("{}:{}:{}", username, self.realm, password);
        self.algorithm.hash(data.as_bytes())
    }

    /// 校验客户端 Authorization header（仅支持 qop=auth）。
    ///
    /// # 参数
    /// - `authorization_header`: 客户端发送的 Authorization header 值。
    /// - `method`: HTTP method（如 "GET" / "POST"）。
    /// - `uri`: 请求 URI。
    /// - `ha1`: 预先计算的 HA1 = H(user:realm:pass)。
    ///
    /// # 返回
    /// - `true`: 校验通过。
    /// - `false`: 校验失败（密码错误 / method 不匹配 / qop 不支持 / nonce 过期 / 格式错误）。
    pub fn validate(&self, authorization_header: &str, method: &str, uri: &str, ha1: &str) -> bool {
        self.validate_inner(authorization_header, method, uri, None, ha1)
    }

    /// 校验客户端 Authorization header（支持 qop=auth 和 qop=auth-int）。
    ///
    /// qop=auth-int 时，HA2 = H(method:uri:H(body))，需传入请求体。
    /// qop=auth 时，HA2 = H(method:uri)，body 参数被忽略。
    ///
    /// # 参数
    /// - `authorization_header`: 客户端 Authorization header。
    /// - `method`: HTTP method。
    /// - `uri`: 请求 URI。
    /// - `body`: 请求体字节（用于 auth-int 计算 HA2）。
    /// - `ha1`: 预先计算的 HA1。
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
        // L5 修复：input validation，拒绝过长的 Authorization header 防 DoS。
        // 超长 header 会触发 O(n) parse_authorization + 多次 hash 计算，
        // 恶意客户端可发送超大 header 耗尽 CPU。8KB 上限覆盖所有合法 Digest Auth 请求。
        if authorization_header.len() > MAX_AUTHORIZATION_HEADER_LEN {
            return false;
        }
        match self.parse_authorization(authorization_header) {
            Ok(resp) => {
                // 检查 nonce 是否有效（格式 + 过期）
                if !self.is_nonce_valid(&resp.nonce) {
                    return false;
                }
                // vuln-0008: nc 单调性校验（RFC 7616 §3.4.6）
                // 拒绝同一 nonce 的 nc 回退或重复，防止重放攻击
                if !self.validate_nc(&resp.nonce, &resp.nc) {
                    return false;
                }
                let qop = resp.qop.as_deref();
                // 根据 qop 计算 HA2
                let ha2 = match qop {
                    Some("auth") => {
                        let ha2_input = format!("{}:{}", method, uri);
                        self.algorithm.hash(ha2_input.as_bytes())
                    },
                    Some("auth-int") => {
                        // auth-int 需要 body，HA2 = H(method:uri:H(body))
                        let body_bytes = body.unwrap_or(&[]);
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
                // 常量时间比较，避免时序攻击
                constant_time_eq(expected.as_bytes(), resp.response.as_bytes())
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

        for (key, value) in parse_digest_params(params) {
            match key.as_str() {
                // username/realm/uri 由 RFC 7616 要求存在，但 validate() 不使用，仅校验存在性
                "username" | "realm" | "uri" => {},
                "nonce" => nonce = Some(value),
                "response" => response = Some(value),
                "qop" => qop = Some(value),
                "nc" => nc = Some(value),
                "cnonce" => cnonce = Some(value),
                _ => {},
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
        })
    }
}

/// Digest 响应参数（解析自客户端 Authorization header）。
///
/// 仅保留 `validate()` 实际使用的字段；username/realm/uri 虽由 RFC 7616 要求且
/// 在 `parse_authorization` 中校验存在性，但不存储（避免死字段）。
#[derive(Debug, Clone)]
struct DigestResponse {
    nonce: String,
    response: String,
    qop: Option<String>,
    nc: String,
    cnonce: String,
}

/// 解析 Digest 参数串（key=value 或 key="quoted value" 形式，依据 RFC 7616）。
fn parse_digest_params(s: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();

    while chars.peek().is_some() {
        while matches!(chars.peek(), Some(c) if c.is_whitespace() || *c == ',') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut key = String::new();
        while let Some(c) = chars.peek() {
            if c.is_whitespace() || *c == '=' {
                break;
            }
            key.push(chars.next().unwrap());
        }
        while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
            chars.next();
        }
        if chars.peek() != Some(&'=') {
            break;
        }
        chars.next();
        while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
            chars.next();
        }
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
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
        } else {
            while let Some(c) = chars.peek() {
                if c.is_whitespace() || *c == ',' {
                    break;
                }
                value.push(chars.next().unwrap());
            }
        }
        if !key.is_empty() {
            result.push((key, value));
        }
    }
    result
}

/// 常量时间字符串比较，避免时序攻击（L1 修复）。
///
/// 使用 `subtle::ConstantTimeEq` trait 的 `ct_eq` 方法，全程常量时间：
/// - 长度不等时返回 0（subtle 库内部处理，不提前 return，避免长度泄漏）
/// - 长度相等时按字节异或累积，最后一次性比较
///
/// 替代原手写的 `if a.len() != b.len() { return false; }` 实现，
/// 原实现虽然循环部分常量时间，但长度检查的提前 return 会泄漏长度信息。
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// 获取当前 Unix 时间戳（秒）。
pub(super) fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
