//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! 审计事件防篡改 HMAC 链（吸收自 inklog `ArchiveChain`，与 dbnexus 权限审计链同构）。
//!
//! 链条以**每次 [`AuditEventChain::new`] 生成的随机盐**为链首——
//! `hmac_0 = HMAC(key, salt)`，`hmac_n = HMAC(key, salt || prev_hash_n || event_n)`。
//! 盐随条目存储（secret 由使用方持有），校验方重算整条链：任一事件被
//! 篡改、删除、重排或伪造即校验失败。合规场景（等保审计取证）可将条目
//! JSONL 落盘（与审计日志分库存储），事后用 [`AuditEventChain::verify_entries`] 验证。
//!
//! 与 [`super::audit::AuditConfig::signing_key`](crate::listener::audit::AuditConfig)
//! 的导出签名链互补：后者为导出文件的逐行签名，本模块为**活动事件链**。
//!
//! ```rust
//! use garrison::listener::audit_chain::AuditEventChain;
//!
//! let mut chain = AuditEventChain::new(b"audit-chain-key");
//! chain.append(r#"{"event":"login","login_id":1}"#);
//! chain.append(r#"{"event":"logout","login_id":1}"#);
//! assert!(chain.verify());
//!
//! // 篡改任一事件 → 校验失败
//! let mut entries = chain.entries().to_vec();
//! entries[0].event = r#"{"event":"login","login_id":999}"#.to_string();
//! assert!(!AuditEventChain::verify_entries(&entries, b"audit-chain-key"));
//! ```

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 输出长度（字节）。
pub const CHAIN_HASH_LEN: usize = 32;

/// 链首随机盐长度（字节）。
pub const CHAIN_SALT_LEN: usize = 16;

/// 审计链条目（JSONL 友好：哈希以 hex 存储，可直接落盘）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainEntry {
    /// 链内序号（0 起，严格递增）。
    pub index: u64,
    /// 链首随机盐（hex；每个条目冗余携带，支持独立校验）。
    pub salt: String,
    /// 上一条目的 HMAC（hex；首条为全零）。
    pub prev_hash: String,
    /// 事件规范化 JSON（建议由调用方先经审计脱敏）。
    pub event: String,
    /// HMAC-SHA256(key, salt || prev_hash || event)（hex）。
    pub hmac: String,
}

/// 审计事件防篡改 HMAC 链。
///
/// # 用法
///
/// - 运行期：`new(key)` 创建 → 每个 `GarrisonEvent` 序列化后 `append` →
/// 周期性将 [`entries`](Self::entries) JSONL 导出到独立存储。
/// - 取证：读回 JSONL 后用 [`verify_entries`](Self::verify_entries) 重算整链。
///
/// key 建议 ≥32 字节（复用 JWT secret 或独立审计密钥，勿与签名密钥混用）。
pub struct AuditEventChain {
    key: Vec<u8>,
    salt: [u8; CHAIN_SALT_LEN],
    prev_hash: [u8; CHAIN_HASH_LEN],
    entries: Vec<AuditChainEntry>,
}

impl AuditEventChain {
    /// 以密钥创建链条；链首盐取 OS CSPRNG（`getrandom::fill`）。
    ///
    /// # Panics
    /// OS 随机源不可用时 panic（与令牌生成路径同一安全立场：无法取熵即拒绝服务）。
    pub fn new(key: &[u8]) -> Self {
        let mut salt = [0u8; CHAIN_SALT_LEN];
        getrandom::fill(&mut salt).expect("OS CSPRNG 不可用");
        Self {
            key: key.to_vec(),
            salt,
            prev_hash: [0u8; CHAIN_HASH_LEN],
            entries: Vec::new(),
        }
    }

    /// 追加事件（规范化 JSON 字符串）；返回条目序号。
    ///
    /// 调用方负责事件的脱敏（`mask_audit_token` / `SensitiveDataMasker`）——
    /// 链条只保证**完整性**（防篡改），不处理机密性。
    pub fn append(&mut self, canonical_event: &str) -> u64 {
        let index = self.entries.len() as u64;
        let hmac = Self::compute_hmac(
            &self.key,
            &self.salt,
            &self.prev_hash,
            canonical_event.as_bytes(),
        );

        let entry = AuditChainEntry {
            index,
            salt: hex_encode(&self.salt),
            prev_hash: hex_encode(&self.prev_hash),
            event: canonical_event.to_string(),
            hmac: hex_encode(&hmac),
        };
        self.prev_hash = hmac;
        self.entries.push(entry);
        index
    }

    /// 已追加的条目（JSONL 落盘形态）。
    pub fn entries(&self) -> &[AuditChainEntry] {
        &self.entries
    }

    /// 校验当前链条（实例方法便捷封装）。
    pub fn verify(&self) -> bool {
        Self::verify_entries(self.entries(), &self.key)
    }

    /// 校验完整链条：重算每条 HMAC 并核对 prev_hash 链与序号连续性。
    ///
    /// 任一事件被篡改、删除、重排或伪造（prev_hash 链断裂 / hmac 不匹配 /
    /// 序号跳跃 / 盐不一致）即返回 `false`。
    pub fn verify_entries(entries: &[AuditChainEntry], key: &[u8]) -> bool {
        let mut prev_hash = [0u8; CHAIN_HASH_LEN];
        let mut salt: Option<[u8; CHAIN_SALT_LEN]> = None;
        for (expected_index, entry) in entries.iter().enumerate() {
            if entry.index != expected_index as u64 {
                return false;
            }
            let Some(entry_salt) = hex_decode_fixed::<CHAIN_SALT_LEN>(&entry.salt) else {
                return false;
            };
            // 链首盐在整条链中必须一致（防换盐重放）
            match salt {
                None => salt = Some(entry_salt),
                Some(s) if s != entry_salt => return false,
                Some(_) => {},
            }
            let Some(prev) = hex_decode_fixed::<CHAIN_HASH_LEN>(&entry.prev_hash) else {
                return false;
            };
            if prev != prev_hash {
                return false;
            }
            let expected = Self::compute_hmac(key, &entry_salt, &prev_hash, entry.event.as_bytes());
            let Some(actual) = hex_decode_fixed::<CHAIN_HASH_LEN>(&entry.hmac) else {
                return false;
            };
            // 常量时间比较（subtle::ConstantTimeEq）；长度不等在上面的解码已失败——
            // 长度本身非秘密
            if !bool::from(expected.ct_eq(&actual)) {
                return false;
            }
            prev_hash = expected;
        }
        true
    }

    /// 条目序列化为 JSONL（每行一个 JSON 对象，无尾随换行）。
    pub fn to_jsonl(entries: &[AuditChainEntry]) -> String {
        entries
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_default()
            .join("\n")
    }

    /// 从 JSONL 解析条目（[`to_jsonl`](Self::to_jsonl) 的逆操作）。
    pub fn from_jsonl(jsonl: &str) -> Option<Vec<AuditChainEntry>> {
        jsonl
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<Vec<_>, _>>()
            .ok()
    }

    fn compute_hmac(
        key: &[u8],
        salt: &[u8],
        prev_hash: &[u8],
        event: &[u8],
    ) -> [u8; CHAIN_HASH_LEN] {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 接受任意长度 key");
        mac.update(salt);
        mac.update(prev_hash);
        mac.update(event);
        let mut out = [0u8; CHAIN_HASH_LEN];
        out.copy_from_slice(&mac.finalize().into_bytes());
        out
    }
}

/// 十六进制编码（小写）。
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 十六进制解码到定长数组（奇数长度/非 hex 字符/长度不符返回 None）。
fn hex_decode_fixed<const N: usize>(raw: &str) -> Option<[u8; N]> {
    if raw.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: &str, id: u64) -> String {
        serde_json::json!({ "event": kind, "login_id": id }).to_string()
    }

    #[test]
    fn chain_append_and_verify_roundtrip() {
        let mut chain = AuditEventChain::new(b"key-1");
        chain.append(&event("login", 1));
        chain.append(&event("logout", 1));
        chain.append(&event("ban", 2));
        assert_eq!(chain.entries().len(), 3);
        assert!(chain.verify());
        // 序号严格递增
        assert_eq!(chain.entries()[2].index, 2);
        // 链首盐为 32-hex（16 字节）
        assert_eq!(chain.entries()[0].salt.len(), CHAIN_SALT_LEN * 2);
    }

    #[test]
    fn verify_detects_tampered_event() {
        let mut chain = AuditEventChain::new(b"key-1");
        chain.append(&event("login", 1));
        chain.append(&event("logout", 1));
        let mut entries = chain.entries().to_vec();
        entries[0].event = event("login", 999);
        assert!(
            !AuditEventChain::verify_entries(&entries, b"key-1"),
            "tampered event must be detected"
        );
    }

    #[test]
    fn verify_detects_deletion_reorder_and_forgery() {
        let mut chain = AuditEventChain::new(b"key-1");
        chain.append(&event("a", 1));
        chain.append(&event("b", 2));
        chain.append(&event("c", 3));

        // 删除中间条目
        let mut entries = chain.entries().to_vec();
        entries.remove(1);
        assert!(
            !AuditEventChain::verify_entries(&entries, b"key-1"),
            "deletion must break the chain"
        );

        // 重排
        let mut entries = chain.entries().to_vec();
        entries.swap(0, 1);
        assert!(
            !AuditEventChain::verify_entries(&entries, b"key-1"),
            "reorder must break the chain"
        );

        // 伪造（追加一条非链上条目）
        let mut entries = chain.entries().to_vec();
        entries.push(AuditChainEntry {
            index: 3,
            salt: entries[0].salt.clone(),
            prev_hash: entries[2].hmac.clone(),
            event: event("forged", 4),
            hmac: hex_encode(&[0u8; 32]),
        });
        assert!(
            !AuditEventChain::verify_entries(&entries, b"key-1"),
            "forgery must be detected"
        );
    }

    #[test]
    fn verify_rejects_wrong_key_and_salt_swap() {
        let mut chain = AuditEventChain::new(b"key-1");
        chain.append(&event("a", 1));
        assert!(!AuditEventChain::verify_entries(
            chain.entries(),
            b"wrong-key"
        ));

        // 换盐重放：修改盐 → 链断裂
        let mut entries = chain.entries().to_vec();
        entries[0].salt = hex_encode(&[9u8; CHAIN_SALT_LEN]);
        assert!(
            !AuditEventChain::verify_entries(&entries, b"key-1"),
            "salt swap must be detected"
        );
    }

    #[test]
    fn chains_are_unpredictable_across_instances() {
        // 不同实例的链首盐必须不同（随机盐语义）
        let mut a = AuditEventChain::new(b"k");
        let mut b = AuditEventChain::new(b"k");
        a.append(&event("a", 1));
        b.append(&event("a", 1));
        assert_ne!(
            a.entries()[0].salt,
            b.entries()[0].salt,
            "chain-start salt must be random per instance"
        );
    }

    #[test]
    fn jsonl_roundtrip_preserves_verifiability() {
        // JSONL 落盘 → 读回校验（与审计日志分库存储的取证路径）
        let mut chain = AuditEventChain::new(b"key-1");
        chain.append(&event("login", 1));
        chain.append(&event("logout", 1));
        let jsonl = AuditEventChain::to_jsonl(chain.entries());

        let parsed = AuditEventChain::from_jsonl(&jsonl).expect("JSONL 解析应成功");
        assert_eq!(parsed.len(), 2);
        assert!(AuditEventChain::verify_entries(&parsed, b"key-1"));

        // 篡改条目后重新落盘 → 校验失败（模拟拿到 JSONL 后改写事件）
        let mut tampered_entries = AuditEventChain::from_jsonl(&jsonl).unwrap();
        tampered_entries[0].event = r#"{"event":"login_evil","login_id":1}"#.to_string();
        let tampered = AuditEventChain::to_jsonl(&tampered_entries);
        let reparsed = AuditEventChain::from_jsonl(&tampered).unwrap();
        assert!(!AuditEventChain::verify_entries(&reparsed, b"key-1"));
    }

    #[test]
    fn from_jsonl_rejects_malformed_input() {
        assert!(AuditEventChain::from_jsonl("not json").is_none());
        assert!(AuditEventChain::from_jsonl("")
            .unwrap_or_default()
            .is_empty());
    }
}
