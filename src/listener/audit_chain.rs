// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 审计事件防篡改 HMAC 链（内核：limiteron `AuditLogEntry::chain_onto` /
//! `verify_chain`；链首盐折入密钥派生）。
//!
//! 链条以**每次 [`AuditEventChain::new`] 生成的随机盐**为链首，garrison 侧派生
//! `chain_key = HMAC-SHA256(key, salt)`，链哈希由库原语计算（GENESIS 起步）；
//! 盐随每个条目冗余存储，校验方以「盐 + 密钥」重算派生密钥后重算整链：任一
//! 事件被篡改、删除、重排或伪造即校验失败。合规场景（等保审计取证）可将
//! 条目 JSONL 独立落盘，事后用 [`AuditEventChain::verify_entries`] 验证。
//!
//! **载荷适配（闭集枚举）**：garrison 事件是任意规范化 JSON，limiteron
//! `AuditEvent` 是闭集枚举，事件经 `SystemEvent { name: "garrison-audit", details }`
//! 承载（`details` 字节级保真）；库签名消息（`timestamp|operation|target|result`）
//! 不含 `SystemEvent.details`，故 garrison 侧把 details 的 SHA-256 摘要绑入
//! 被签名的 `level` 槽位（`info:{摘要}`）——篡改事件 JSON 会同时破坏 `level`
//! 与链哈希，防篡改性质不依赖库侧签名面。
//!
//! **归档格式**：JSONL 形态为 `index` + `salt` + limiteron `AuditLogEntry`
//! serde 视图；旧平铺格式不做读取兼容（取证是重算语义）。与
//! [`AuditConfig::signing_key`](crate::listener::audit::AuditConfig) 的导出
//! 签名链互补：后者为导出文件逐行签名，本模块为**活动事件链**。
//!
//! ```rust
//! use garrison::listener::audit_chain::AuditEventChain;
//!
//! let mut chain = AuditEventChain::new(b"audit-chain-key");
//! chain.append(r#"{"event":"login","login_id":1}"#);
//! chain.append(r#"{"event":"logout","login_id":1}"#);
//! assert!(chain.verify());
//!
//! // 篡改落盘 JSONL 中任一事件 → 校验失败
//! let mut jsonl = AuditEventChain::to_jsonl(chain.entries());
//! jsonl = jsonl.replace("login_id", "evil_id");
//! let entries = AuditEventChain::from_jsonl(&jsonl).unwrap();
//! assert!(!AuditEventChain::verify_entries(&entries, b"audit-chain-key"));
//! ```

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use limiteron::logging::audit::{AuditEvent, AuditLogEntry};

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 输出长度（字节）。
pub const CHAIN_HASH_LEN: usize = 32;

/// 链首随机盐长度（字节）。
pub const CHAIN_SALT_LEN: usize = 16;

/// garrison 审计事件在 limiteron 闭集枚举中的载体名（`SystemEvent.name`）。
const GARRISON_AUDIT_NAME: &str = "garrison-audit";

/// 审计链条目（JSONL 友好：链哈希以 hex 存储，可直接落盘）。
///
/// 条目由 garrison 侧元数据（`index` 序号、`salt` 链首盐）包装 limiteron
/// [`AuditLogEntry`]（事件经 `SystemEvent.details` 承载规范化 JSON，链哈希
/// `chain_prev`/`chain_hash` 由库原语计算）构成。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainEntry {
    /// 链内序号（0 起，严格递增；库层无序号字段，garrison 侧保留）。
    pub index: u64,
    /// 链首随机盐（hex；每个条目冗余携带，支持独立校验与防换盐重放）。
    pub salt: String,
    /// limiteron 审计条目（事件载荷 + 库计算的链哈希）。
    pub entry: AuditLogEntry,
}

/// 审计事件防篡改 HMAC 链。
///
/// # 用法
///
/// - 运行期：`new(key)` 创建 → 每个 `GarrisonEvent` 序列化后 `append` →
///   周期性将 [`entries`](Self::entries) JSONL 导出到独立存储。
/// - 取证：读回 JSONL 后用 [`verify_entries`](Self::verify_entries) 重算整链。
///
/// key 建议 ≥32 字节（复用 JWT secret 或独立审计密钥，勿与签名密钥混用）。
pub struct AuditEventChain {
    key: Vec<u8>,
    salt: [u8; CHAIN_SALT_LEN],
    /// 链密钥 = `HMAC-SHA256(key, salt)`（hex）——盐折入派生，链间不可链接。
    chain_key: String,
    /// 前一链哈希（首条为 [`AuditLogEntry::GENESIS`]）。
    prev_hash: String,
    entries: Vec<AuditChainEntry>,
}

impl AuditEventChain {
    /// 以密钥创建链条；链首盐取 OS CSPRNG（`getrandom::fill`），OS 随机源
    /// 不可用时 panic（与令牌生成同一立场：无法取熵即拒绝服务）。
    pub fn new(key: &[u8]) -> Self {
        let mut salt = [0u8; CHAIN_SALT_LEN];
        getrandom::fill(&mut salt).expect("OS CSPRNG 不可用");
        Self {
            key: key.to_vec(),
            chain_key: derive_chain_key(key, &salt),
            salt,
            prev_hash: AuditLogEntry::GENESIS.to_string(),
            entries: Vec::new(),
        }
    }

    /// 追加事件（规范化 JSON 字符串）；返回条目序号。
    ///
    /// 调用方负责事件的脱敏（`mask_audit_token` / `SensitiveDataMasker`）——
    /// 链条只保证**完整性**（防篡改），不处理机密性。
    pub fn append(&mut self, canonical_event: &str) -> u64 {
        let index = self.entries.len() as u64;
        let mut entry = AuditLogEntry::new(Self::to_audit_event(canonical_event));
        let hash = entry.chain_onto(&self.chain_key, &self.prev_hash);
        self.prev_hash = hash;
        self.entries.push(AuditChainEntry {
            index,
            salt: hex::encode(self.salt),
            entry,
        });
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

    /// 校验完整链条：序号连续 + 全链盐一致 + 载荷绑定 + 库原语重算链哈希。
    ///
    /// 任一事件被篡改、删除、重排或伪造（链断裂 / 序号跳跃 / 盐不一致 /
    /// 载荷绑定破坏）即返回 `false`。
    pub fn verify_entries(entries: &[AuditChainEntry], key: &[u8]) -> bool {
        let mut salt_bytes: Option<[u8; CHAIN_SALT_LEN]> = None;
        let mut chain_key = String::new();
        for (expected_index, item) in entries.iter().enumerate() {
            if item.index != expected_index as u64 {
                return false;
            }
            // 载荷绑定核对：库签名消息不含 details，只改事件 JSON 不改 level
            // 时链哈希不变，故 garrison 侧显式核对（改 level 则破坏链哈希）
            if !details_binding_ok(&item.entry.event) {
                return false;
            }
            let Ok(salt_vec) = hex::decode(&item.salt) else {
                return false;
            };
            let Ok(salt) = <[u8; CHAIN_SALT_LEN]>::try_from(salt_vec) else {
                return false;
            };
            // 链首盐在整条链中必须一致（防换盐重放）
            match salt_bytes {
                None => {
                    chain_key = derive_chain_key(key, &salt);
                    salt_bytes = Some(salt);
                },
                Some(s) if s != salt => return false,
                Some(_) => {},
            }
        }
        let inner: Vec<AuditLogEntry> = entries.iter().map(|e| e.entry.clone()).collect();
        // 库原语：首条 chain_prev==GENESIS、逐条重算 HMAC(key, prev‖payload)
        matches!(AuditLogEntry::verify_chain(&inner, &chain_key), Ok(true))
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

    /// garrison 规范化 JSON 事件 → limiteron `SystemEvent` 载荷。
    ///
    /// `level` 槽位绑入 `details` 的 SHA-256 摘要：库签名消息不含
    /// `SystemEvent.details`，摘要使「篡改事件 JSON」必然破坏链哈希
    /// （防篡改性质不依赖库侧签名面，见模块头说明）。
    fn to_audit_event(canonical_event: &str) -> AuditEvent {
        AuditEvent::SystemEvent {
            timestamp: Utc::now(),
            level: format!("info:{}", details_digest(canonical_event)),
            name: GARRISON_AUDIT_NAME.to_string(),
            details: canonical_event.to_string(),
        }
    }
}

/// 链密钥派生：`HMAC-SHA256(key, salt)`（hex）——盐折入密钥派生，
/// 同密钥不同链的链哈希互不相关（链间不可链接）。
fn derive_chain_key(key: &[u8], salt: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 接受任意长度 key");
    mac.update(salt);
    hex::encode(mac.finalize().into_bytes())
}

/// 事件 JSON 的 SHA-256 摘要（hex）——绑入被签名的 `level` 槽位。
fn details_digest(details: &str) -> String {
    hex::encode(Sha256::digest(details.as_bytes()))
}

/// 校验 `SystemEvent` 载荷绑定：`details` 的 SHA-256 摘要须与 `level`
/// 槽位（`info:{摘要}`）一致。
///
/// garrison 只产出 `SystemEvent` 形态，其他变体一律拒绝（闭集枚举的
/// 未知形态视为伪造入口）。
fn details_binding_ok(event: &AuditEvent) -> bool {
    match event {
        AuditEvent::SystemEvent { level, details, .. } => {
            level == &format!("info:{}", details_digest(details))
        },
        _ => false,
    }
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
        // 载荷经 SystemEvent.details 字节级保真
        match &chain.entries()[0].entry.event {
            AuditEvent::SystemEvent { name, details, .. } => {
                assert_eq!(name, "garrison-audit");
                assert_eq!(details, &event("login", 1));
            },
            other => panic!("事件应承载为 SystemEvent，实际: {other:?}"),
        }
    }

    #[test]
    fn verify_detects_tampered_event() {
        let mut chain = AuditEventChain::new(b"key-1");
        chain.append(&event("login", 1));
        chain.append(&event("logout", 1));
        let mut entries = chain.entries().to_vec();
        // 模拟拿到 JSONL 后改写事件 JSON（details 槽位）
        if let AuditEvent::SystemEvent { details, .. } = &mut entries[0].entry.event {
            *details = event("login", 999);
        }
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

        let mut entries = chain.entries().to_vec();
        entries.remove(1);
        assert!(
            !AuditEventChain::verify_entries(&entries, b"key-1"),
            "deletion must break the chain"
        );

        let mut entries = chain.entries().to_vec();
        entries.swap(0, 1);
        assert!(
            !AuditEventChain::verify_entries(&entries, b"key-1"),
            "reorder must break the chain"
        );

        // 伪造（追加一条未串链条目：chain_hash 缺失）
        let mut entries = chain.entries().to_vec();
        entries.push(AuditChainEntry {
            index: 3,
            salt: entries[0].salt.clone(),
            entry: AuditLogEntry::new(AuditEventChain::to_audit_event(&event("forged", 4))),
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

        // 换盐重放：修改盐 → 派生密钥变化，链断裂
        let mut entries = chain.entries().to_vec();
        entries[0].salt = hex::encode(&[9u8; CHAIN_SALT_LEN]);
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
    fn same_key_same_events_chain_hashes_differ() {
        // 链间不可链接性：同密钥、同事件序列的两条链，链哈希序列互不相同
        let mut a = AuditEventChain::new(b"k");
        let mut b = AuditEventChain::new(b"k");
        a.append(&event("a", 1));
        b.append(&event("a", 1));
        assert_ne!(
            a.entries()[0].entry.chain_hash,
            b.entries()[0].entry.chain_hash,
            "同密钥同事件的链哈希必须互不相同（盐折入密钥派生）"
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
        if let AuditEvent::SystemEvent { details, .. } = &mut tampered_entries[0].entry.event {
            *details = r#"{"event":"login_evil","login_id":1}"#.to_string();
        }
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
