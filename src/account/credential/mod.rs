//! 凭证模型 SPI 子模块（v0.6.0 新增，吸收 keycloak CredentialModel SPI）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 提供统一凭证抽象，支持 password / TOTP / WebAuthn（v0.7+）等多种凭证类型。
//! 详见 spec `credential-model`。
//!
//! # 核心类型
//!
//! - `Credential` trait：统一凭证校验接口（对象安全，可作 `dyn Credential`）
//! - `CredentialModel`：凭证存储模型（DAO 持久化结构，8 字段 schema）
//! - `CredentialRepository` trait：凭证存储抽象（CRUD 5 方法）
//!
//! # 设计决策
//!
//! - D1: `Credential::verify(&self, input: &str)` 接收 `&str` 而非泛型（对象安全）
//! - D5: `PasswordHasher` 从 `secure/password/` 破坏性迁移到本模块的 `password` 子模块

/// 密码哈希子模块（v0.6.0 从 secure/password/ 迁移）。
///
/// 提供 `PasswordHasher` trait + `Argon2Hasher` / `BcryptHasher` + `PasswordVerifier`。
pub mod password;

/// TOTP 凭证子模块（v0.6.0 新增，复用 `secure::totp::TotpHandler`）。
///
/// 需同时启用 `account-credential` + `secure-totp` feature。
#[cfg(all(feature = "account-credential", feature = "secure-totp"))]
pub mod totp;

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use std::sync::Arc;

// ============================================================================
// 类型别名
// ============================================================================

/// 凭证类型标识（字符串形式，如 `"password"` / `"totp"` / `"webauthn"`）。
///
/// 使用 `&'static str` 而非 `String`：凭证类型在编译期已知，避免分配。
pub type CredentialType = &'static str;

// ============================================================================
// Credential trait（统一凭证校验接口）
// ============================================================================

/// 凭证统一 trait（吸收 keycloak CredentialModel SPI）。
///
/// 每种凭证类型（password / TOTP / WebAuthn）实现此 trait，提供统一的
/// `credential_type()` / `to_model()` / `verify()` 接口。
///
/// # 对象安全
///
/// `verify` 接收 `&str` 而非泛型（决策 D1），保证 trait 对象安全，
/// 可作 `Box<dyn Credential>` / `Arc<dyn Credential>` 使用。
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::credential::{Credential, CredentialModel};
///
/// let cred: Box<dyn Credential> = /* PasswordCredential / TotpCredential */;
/// let ok = cred.verify("user-input").await?;
/// ```
#[async_trait]
pub trait Credential: Send + Sync {
    /// 凭证类型标识（如 `"password"` / `"totp"`）。
    fn credential_type(&self) -> CredentialType;

    /// 转换为存储模型（序列化用于 DAO 持久化）。
    fn to_model(&self) -> CredentialModel;

    /// 校验用户输入与存储凭证是否匹配。
    ///
    /// # 参数
    /// - `input`: 用户输入（明文密码 / TOTP code / WebAuthn challenge JSON）
    ///
    /// # 返回
    /// - `Ok(true)`: 校验通过
    /// - `Ok(false)`: 校验失败（凭证不匹配）
    /// - `Err(_)`: 校验过程出错（如哈希格式不支持、DAO 故障）
    async fn verify(&self, input: &str) -> BulwarkResult<bool>;
}

// ============================================================================
// CredentialModel（凭证存储模型）
// ============================================================================

/// 凭证存储模型（DAO 持久化结构）。
///
/// 8 字段 schema（pre-1.0 锁定，与 design.md §3.1 严格一致）。
/// 通过 `serde::Serialize` / `serde::Deserialize` 序列化为 JSON 存入 DAO。
///
/// # 字段说明
///
/// | 字段 | 类型 | 说明 |
/// |:---|:---|:---|
/// | `id` | `String` | 凭证 ID（UUID v4） |
/// | `user_id` | `String` | 用户 ID（关联 login_id） |
/// | `credential_type` | `String` | 凭证类型（`"password"` / `"totp"` / ...） |
/// | `secret_data` | `String` | 凭证数据（hash / secret / public key，JSON 编码） |
/// | `label` | `Option<String>` | 用户自定义标签（如 `"iPhone TOTP"`） |
/// | `created_at` | `i64` | 创建时间（Unix 时间戳） |
/// | `enabled` | `bool` | 是否启用 |
/// | `priority` | `i32` | 优先级（多凭证时排序，小值优先） |
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialModel {
    /// 凭证 ID（UUID v4）。
    pub id: String,
    /// 用户 ID（关联 login_id）。
    pub user_id: String,
    /// 凭证类型（`"password"` / `"totp"` / `"webauthn"`）。
    pub credential_type: String,
    /// 凭证数据（hash / secret / public key，JSON 编码）。
    pub secret_data: String,
    /// 凭证标签（用户自定义名称，如 `"iPhone TOTP"`）。
    pub label: Option<String>,
    /// 创建时间（Unix 时间戳）。
    pub created_at: i64,
    /// 是否启用。
    pub enabled: bool,
    /// 优先级（多凭证时排序，小值优先）。
    pub priority: i32,
}

// ============================================================================
// CredentialRepository trait（凭证存储抽象）
// ============================================================================

/// 凭证存储抽象（DAO 层接口）。
///
/// 5 方法 CRUD：`create` / `find_by_user` / `find_by_user_and_type` / `update` / `delete`。
/// 由 `DaoCredentialRepository`（T006 实现）基于 `BulwarkDao` 实现，也可由业务方自定义实现。
///
/// # DAO key 格式
///
/// `cred:{user_id}:{cred_id}`（如 `cred:alice:550e8400-...`）
///
/// # 示例
///
/// ```ignore
/// use bulwark::account::credential::{CredentialModel, CredentialRepository};
/// use std::sync::Arc;
///
/// let repo: Arc<dyn CredentialRepository> = /* DaoCredentialRepository */;
/// let creds = repo.find_by_user("alice").await?;
/// ```
#[async_trait]
pub trait CredentialRepository: Send + Sync {
    /// 创建凭证。
    ///
    /// # 错误
    /// - 凭证 ID 已存在：`BulwarkError::InvalidParam`
    /// - DAO 故障：透传 `BulwarkError::Dao`
    async fn create(&self, credential: CredentialModel) -> BulwarkResult<()>;

    /// 按 `user_id` 查询所有凭证。
    ///
    /// 返回顺序按 `priority` 升序（小值优先）。
    async fn find_by_user(&self, user_id: &str) -> BulwarkResult<Vec<CredentialModel>>;

    /// 按 `user_id` + `credential_type` 查询凭证。
    ///
    /// 在 `find_by_user` 基础上按 `credential_type` 字段过滤。
    async fn find_by_user_and_type(
        &self,
        user_id: &str,
        cred_type: &str,
    ) -> BulwarkResult<Vec<CredentialModel>>;

    /// 更新凭证（覆盖写）。
    ///
    /// # 错误
    /// - 凭证 ID 不存在：`BulwarkError::InvalidParam`
    /// - DAO 故障：透传 `BulwarkError::Dao`
    async fn update(&self, credential: CredentialModel) -> BulwarkResult<()>;

    /// 删除凭证。
    ///
    /// # 错误
    /// - 凭证 ID 不存在：`BulwarkError::InvalidParam`
    /// - DAO 故障：透传 `BulwarkError::Dao`
    async fn delete(&self, credential_id: &str) -> BulwarkResult<()>;
}

// ============================================================================
// DaoCredentialRepository（基于 BulwarkDao 的默认实现，依据 spec R-006）
// ============================================================================

/// 基于 `BulwarkDao` 的 `CredentialRepository` 默认实现。
///
/// 凭证以 JSON 序列化存入 DAO，key 格式严格为 `cred:{user_id}:{cred_id}`，
/// 永久存储（无 TTL，使用 `set_permanent`）。
///
/// # DAO key 格式
///
/// `cred:{user_id}:{cred_id}`（如 `cred:alice:550e8400-e29b-...`）
///
/// # 已知限制
///
/// - `find_by_user` / `find_by_user_and_type` / `delete` 依赖 `BulwarkDao::keys()`。
///   `BulwarkDaoOxcache` 当前未实现 `keys()`（返回 `NotImplemented`，详见 A-010），
///   生产环境需使用支持 `keys()` 的 DAO 后端，或由业务方维护 key 索引。
/// - `delete(credential_id)` 因 trait 签名仅含 `credential_id`，需扫描
///   `cred:*:{credential_id}` 定位完整 key（`credential_id` 为 UUID v4 全局唯一，
///   理论上仅匹配一个 key）。
pub struct DaoCredentialRepository {
    dao: Arc<dyn BulwarkDao>,
}

impl DaoCredentialRepository {
    /// 创建 `DaoCredentialRepository`。
    ///
    /// # 参数
    /// - `dao`: 已初始化的 `BulwarkDao` 实现（`Arc<dyn BulwarkDao>`）。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }

    /// 生成 DAO key：`cred:{user_id}:{cred_id}`。
    fn make_key(user_id: &str, cred_id: &str) -> String {
        format!("cred:{}:{}", user_id, cred_id)
    }
}

#[async_trait]
impl CredentialRepository for DaoCredentialRepository {
    async fn create(&self, credential: CredentialModel) -> BulwarkResult<()> {
        let key = Self::make_key(&credential.user_id, &credential.id);
        // 检查重复（trait 契约：已存在返回 InvalidParam）
        if self.dao.get(&key).await?.is_some() {
            return Err(BulwarkError::InvalidParam(format!(
                "credential already exists: {}",
                credential.id
            )));
        }
        let json = serde_json::to_string(&credential)
            .map_err(|e| BulwarkError::Internal(format!("CredentialModel 序列化失败: {}", e)))?;
        self.dao.set_permanent(&key, &json).await
    }

    async fn find_by_user(&self, user_id: &str) -> BulwarkResult<Vec<CredentialModel>> {
        let pattern = format!("cred:{}:*", user_id);
        let keys = self.dao.keys(&pattern).await?;
        let mut result = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(json) = self.dao.get(&key).await? {
                let model: CredentialModel = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Internal(format!("CredentialModel 反序列化失败: {}", e))
                })?;
                result.push(model);
            }
        }
        // 按 priority 升序（trait 契约）
        result.sort_by_key(|c| c.priority);
        Ok(result)
    }

    async fn find_by_user_and_type(
        &self,
        user_id: &str,
        cred_type: &str,
    ) -> BulwarkResult<Vec<CredentialModel>> {
        let all = self.find_by_user(user_id).await?;
        Ok(all
            .into_iter()
            .filter(|c| c.credential_type == cred_type)
            .collect())
    }

    async fn update(&self, credential: CredentialModel) -> BulwarkResult<()> {
        let key = Self::make_key(&credential.user_id, &credential.id);
        // 检查存在性（trait 契约：不存在返回 InvalidParam）
        if self.dao.get(&key).await?.is_none() {
            return Err(BulwarkError::InvalidParam(format!(
                "credential not found: {}",
                credential.id
            )));
        }
        let json = serde_json::to_string(&credential)
            .map_err(|e| BulwarkError::Internal(format!("CredentialModel 序列化失败: {}", e)))?;
        self.dao.set_permanent(&key, &json).await
    }

    async fn delete(&self, credential_id: &str) -> BulwarkResult<()> {
        // credential_id 全局唯一（UUID v4），扫描 cred:*:{credential_id} 定位完整 key
        let pattern = format!("cred:*:{}", credential_id);
        let keys = self.dao.keys(&pattern).await?;
        if keys.is_empty() {
            return Err(BulwarkError::InvalidParam(format!(
                "credential not found: {}",
                credential_id
            )));
        }
        for key in keys {
            self.dao.delete(&key).await?;
        }
        Ok(())
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    // ========================================================================
    // R-001: Credential trait 对象安全测试
    // ========================================================================

    /// R-001: `Credential` trait 可作 `Box<dyn Credential>` 使用（对象安全编译验证）。
    ///
    /// 若 `Credential` trait 非对象安全（如使用了泛型方法），此测试无法编译。
    #[test]
    fn credential_trait_is_object_safe() {
        // 编译期验证：trait 可作 dyn 使用
        fn _assert_object_safe(_cred: Box<dyn Credential>) {}
        fn _assert_arc_object_safe(_cred: std::sync::Arc<dyn Credential>) {}
        // 空函数，仅验证类型签名编译通过
    }

    /// R-001: `CredentialRepository` trait 可作 `Arc<dyn CredentialRepository>` 使用。
    #[test]
    fn credential_repository_trait_is_object_safe() {
        fn _assert_object_safe(_repo: std::sync::Arc<dyn CredentialRepository>) {}
    }

    // ========================================================================
    // R-002: CredentialModel 序列化测试
    // ========================================================================

    /// R-002: `CredentialModel` serde 序列化输出包含全部 8 字段。
    #[test]
    fn credential_model_serializes_all_8_fields() {
        let model = CredentialModel {
            id: "cred-001".to_string(),
            user_id: "alice".to_string(),
            credential_type: "password".to_string(),
            secret_data: "$argon2id$v=19$...".to_string(),
            label: Some("主密码".to_string()),
            created_at: 1700000000,
            enabled: true,
            priority: 0,
        };
        let json = serde_json::to_string(&model).expect("序列化应成功");
        // 验证全部 8 字段存在于 JSON 输出中
        assert!(
            json.contains("\"id\":\"cred-001\""),
            "JSON 缺少 id 字段: {}",
            json
        );
        assert!(
            json.contains("\"user_id\":\"alice\""),
            "JSON 缺少 user_id 字段: {}",
            json
        );
        assert!(
            json.contains("\"credential_type\":\"password\""),
            "JSON 缺少 credential_type 字段: {}",
            json
        );
        assert!(
            json.contains("\"secret_data\""),
            "JSON 缺少 secret_data 字段: {}",
            json
        );
        assert!(
            json.contains("\"label\":\"主密码\""),
            "JSON 缺少 label 字段: {}",
            json
        );
        assert!(
            json.contains("\"created_at\":1700000000"),
            "JSON 缺少 created_at 字段: {}",
            json
        );
        assert!(
            json.contains("\"enabled\":true"),
            "JSON 缺少 enabled 字段: {}",
            json
        );
        assert!(
            json.contains("\"priority\":0"),
            "JSON 缺少 priority 字段: {}",
            json
        );
    }

    /// R-002: `CredentialModel` serde 反序列化可解析包含全部 8 字段的完整 JSON。
    #[test]
    fn credential_model_deserializes_from_full_json() {
        let json = r#"{
            "id": "cred-002",
            "user_id": "bob",
            "credential_type": "totp",
            "secret_data": "{\"secret\":\"JBSWY3DPEHPK3PXP\"}",
            "label": null,
            "created_at": 1700000001,
            "enabled": false,
            "priority": 1
        }"#;
        let model: CredentialModel = serde_json::from_str(json).expect("反序列化应成功");
        assert_eq!(model.id, "cred-002");
        assert_eq!(model.user_id, "bob");
        assert_eq!(model.credential_type, "totp");
        assert!(model.secret_data.contains("JBSWY3DPEHPK3PXP"));
        assert!(model.label.is_none(), "label 应为 None");
        assert_eq!(model.created_at, 1700000001);
        assert!(!model.enabled, "enabled 应为 false");
        assert_eq!(model.priority, 1);
    }

    /// R-002: `label` 字段为 `None` 时序列化为 JSON `null`。
    #[test]
    fn credential_model_label_none_serializes_as_null() {
        let model = CredentialModel {
            id: "cred-003".to_string(),
            user_id: "carol".to_string(),
            credential_type: "password".to_string(),
            secret_data: "hash".to_string(),
            label: None,
            created_at: 0,
            enabled: true,
            priority: 0,
        };
        let json = serde_json::to_string(&model).expect("序列化应成功");
        assert!(
            json.contains("\"label\":null"),
            "label 为 None 时应序列化为 null，实际: {}",
            json
        );
    }

    /// R-002: `CredentialModel` Clone 后字段一致。
    #[test]
    fn credential_model_clone_preserves_fields() {
        let model = CredentialModel {
            id: "cred-004".to_string(),
            user_id: "dave".to_string(),
            credential_type: "webauthn".to_string(),
            secret_data: "key".to_string(),
            label: Some("YubiKey".to_string()),
            created_at: 1700000002,
            enabled: true,
            priority: 5,
        };
        let cloned = model.clone();
        assert_eq!(cloned.id, model.id);
        assert_eq!(cloned.user_id, model.user_id);
        assert_eq!(cloned.credential_type, model.credential_type);
        assert_eq!(cloned.secret_data, model.secret_data);
        assert_eq!(cloned.label, model.label);
        assert_eq!(cloned.created_at, model.created_at);
        assert_eq!(cloned.enabled, model.enabled);
        assert_eq!(cloned.priority, model.priority);
    }

    // ========================================================================
    // R-003: CredentialRepository mock CRUD 测试
    // ========================================================================

    /// Mock `CredentialRepository` 实现（内存 HashMap），用于测试 trait 契约。
    #[derive(Default)]
    struct MockCredentialRepository {
        store: std::sync::Mutex<std::collections::HashMap<String, CredentialModel>>,
    }

    #[async_trait]
    impl CredentialRepository for MockCredentialRepository {
        async fn create(&self, credential: CredentialModel) -> BulwarkResult<()> {
            let mut store = self.store.lock().unwrap();
            if store.contains_key(&credential.id) {
                return Err(crate::error::BulwarkError::InvalidParam(format!(
                    "credential already exists: {}",
                    credential.id
                )));
            }
            store.insert(credential.id.clone(), credential);
            Ok(())
        }

        async fn find_by_user(&self, user_id: &str) -> BulwarkResult<Vec<CredentialModel>> {
            let store = self.store.lock().unwrap();
            let mut creds: Vec<CredentialModel> = store
                .values()
                .filter(|c| c.user_id == user_id)
                .cloned()
                .collect();
            // 按 priority 升序排序
            creds.sort_by_key(|c| c.priority);
            Ok(creds)
        }

        async fn find_by_user_and_type(
            &self,
            user_id: &str,
            cred_type: &str,
        ) -> BulwarkResult<Vec<CredentialModel>> {
            let store = self.store.lock().unwrap();
            let mut creds: Vec<CredentialModel> = store
                .values()
                .filter(|c| c.user_id == user_id && c.credential_type == cred_type)
                .cloned()
                .collect();
            creds.sort_by_key(|c| c.priority);
            Ok(creds)
        }

        async fn update(&self, credential: CredentialModel) -> BulwarkResult<()> {
            let mut store = self.store.lock().unwrap();
            if !store.contains_key(&credential.id) {
                return Err(crate::error::BulwarkError::InvalidParam(format!(
                    "credential not found: {}",
                    credential.id
                )));
            }
            store.insert(credential.id.clone(), credential);
            Ok(())
        }

        async fn delete(&self, credential_id: &str) -> BulwarkResult<()> {
            let mut store = self.store.lock().unwrap();
            if !store.contains_key(credential_id) {
                return Err(crate::error::BulwarkError::InvalidParam(format!(
                    "credential not found: {}",
                    credential_id
                )));
            }
            store.remove(credential_id);
            Ok(())
        }
    }

    /// 辅助函数：构造测试用 CredentialModel。
    fn make_model(id: &str, user: &str, cred_type: &str, priority: i32) -> CredentialModel {
        CredentialModel {
            id: id.to_string(),
            user_id: user.to_string(),
            credential_type: cred_type.to_string(),
            secret_data: "hash".to_string(),
            label: None,
            created_at: 0,
            enabled: true,
            priority,
        }
    }

    /// R-003: `create` + `find_by_user` 正常路径。
    #[tokio::test]
    async fn repository_create_and_find_by_user() {
        let repo = MockCredentialRepository::default();
        let m1 = make_model("c1", "alice", "password", 0);
        let m2 = make_model("c2", "alice", "totp", 1);
        repo.create(m1.clone()).await.unwrap();
        repo.create(m2.clone()).await.unwrap();

        let found = repo.find_by_user("alice").await.unwrap();
        assert_eq!(found.len(), 2);
        // 按 priority 升序：password(0) 在前，totp(1) 在后
        assert_eq!(found[0].id, "c1");
        assert_eq!(found[1].id, "c2");
    }

    /// R-003: `create` 重复 ID 返回错误。
    #[tokio::test]
    async fn repository_create_duplicate_returns_error() {
        let repo = MockCredentialRepository::default();
        let m = make_model("c1", "alice", "password", 0);
        repo.create(m).await.unwrap();
        let dup = make_model("c1", "alice", "password", 0);
        let result = repo.create(dup).await;
        assert!(result.is_err(), "重复 create 应返回错误");
    }

    /// R-003: `find_by_user_and_type` 按 credential_type 过滤。
    #[tokio::test]
    async fn repository_find_by_user_and_type_filters() {
        let repo = MockCredentialRepository::default();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();
        repo.create(make_model("c2", "alice", "totp", 1))
            .await
            .unwrap();
        repo.create(make_model("c3", "alice", "password", 2))
            .await
            .unwrap();

        let passwords = repo
            .find_by_user_and_type("alice", "password")
            .await
            .unwrap();
        assert_eq!(passwords.len(), 2);
        assert!(passwords.iter().all(|c| c.credential_type == "password"));

        let totps = repo.find_by_user_and_type("alice", "totp").await.unwrap();
        assert_eq!(totps.len(), 1);
        assert_eq!(totps[0].id, "c2");
    }

    /// R-003: `update` 覆盖写 + 不存在返回错误。
    #[tokio::test]
    async fn repository_update_overwrites_and_errors_on_missing() {
        let repo = MockCredentialRepository::default();
        let m = make_model("c1", "alice", "password", 0);
        repo.create(m).await.unwrap();

        // 更新已存在凭证
        let updated = CredentialModel {
            id: "c1".to_string(),
            user_id: "alice".to_string(),
            credential_type: "password".to_string(),
            secret_data: "new-hash".to_string(),
            label: Some("updated".to_string()),
            created_at: 100,
            enabled: false,
            priority: 5,
        };
        repo.update(updated.clone()).await.unwrap();
        let found = repo.find_by_user("alice").await.unwrap();
        assert_eq!(found[0].secret_data, "new-hash");
        assert_eq!(found[0].label, Some("updated".to_string()));
        assert!(!found[0].enabled);
        assert_eq!(found[0].priority, 5);

        // 更新不存在凭证
        let missing = make_model("nonexistent", "alice", "password", 0);
        let result = repo.update(missing).await;
        assert!(result.is_err(), "更新不存在的凭证应返回错误");
    }

    /// R-003: `delete` 删除 + 不存在返回错误。
    #[tokio::test]
    async fn repository_delete_removes_and_errors_on_missing() {
        let repo = MockCredentialRepository::default();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();

        // 删除已存在凭证
        repo.delete("c1").await.unwrap();
        let found = repo.find_by_user("alice").await.unwrap();
        assert_eq!(found.len(), 0, "删除后应查不到凭证");

        // 删除不存在凭证
        let result = repo.delete("c1").await;
        assert!(result.is_err(), "删除不存在的凭证应返回错误");
    }

    /// R-003: 多用户隔离 — 不同用户的凭证互不影响。
    #[tokio::test]
    async fn repository_multi_user_isolation() {
        let repo = MockCredentialRepository::default();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();
        repo.create(make_model("c2", "bob", "password", 0))
            .await
            .unwrap();

        let alice_creds = repo.find_by_user("alice").await.unwrap();
        assert_eq!(alice_creds.len(), 1);
        assert_eq!(alice_creds[0].id, "c1");

        let bob_creds = repo.find_by_user("bob").await.unwrap();
        assert_eq!(bob_creds.len(), 1);
        assert_eq!(bob_creds[0].id, "c2");

        let empty = repo.find_by_user("carol").await.unwrap();
        assert_eq!(empty.len(), 0);
    }

    /// R-003: `CredentialRepository` 可作 `Arc<dyn CredentialRepository>` 使用。
    #[tokio::test]
    async fn repository_usable_as_trait_object() {
        let repo: std::sync::Arc<dyn CredentialRepository> =
            std::sync::Arc::new(MockCredentialRepository::default());
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();
        let found = repo.find_by_user("alice").await.unwrap();
        assert_eq!(found.len(), 1);
    }

    // ========================================================================
    // R-006: DaoCredentialRepository 测试（基于 MockDao）
    // ========================================================================

    /// 辅助函数：构造 DaoCredentialRepository（基于 MockDao）。
    fn make_dao_repo() -> DaoCredentialRepository {
        DaoCredentialRepository::new(Arc::new(MockDao::new()))
    }

    /// R-006: `create` + `find_by_user` 正常路径（DAO key = `cred:{user_id}:{cred_id}`）。
    #[tokio::test]
    async fn dao_repo_create_and_find_by_user() {
        let repo = make_dao_repo();
        let m = make_model("c1", "alice", "password", 0);
        repo.create(m.clone()).await.unwrap();

        let found = repo.find_by_user("alice").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "c1");
        assert_eq!(found[0].user_id, "alice");
        assert_eq!(found[0].credential_type, "password");
    }

    /// R-006: `find_by_user` 未知用户返回空 Vec。
    #[tokio::test]
    async fn dao_repo_find_by_user_returns_empty_for_unknown() {
        let repo = make_dao_repo();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();

        let found = repo.find_by_user("bob").await.unwrap();
        assert!(found.is_empty(), "未知用户应返回空 Vec");
    }

    /// R-006: `find_by_user_and_type` 按 `credential_type` 过滤。
    #[tokio::test]
    async fn dao_repo_find_by_user_and_type_filters() {
        let repo = make_dao_repo();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();
        repo.create(make_model("c2", "alice", "totp", 1))
            .await
            .unwrap();
        repo.create(make_model("c3", "alice", "password", 2))
            .await
            .unwrap();

        let passwords = repo
            .find_by_user_and_type("alice", "password")
            .await
            .unwrap();
        assert_eq!(passwords.len(), 2);
        assert!(passwords.iter().all(|c| c.credential_type == "password"));

        let totps = repo.find_by_user_and_type("alice", "totp").await.unwrap();
        assert_eq!(totps.len(), 1);
        assert_eq!(totps[0].id, "c2");
    }

    /// R-006: `update` 覆盖写 + 不存在返回错误。
    #[tokio::test]
    async fn dao_repo_update_overwrites_and_errors_on_missing() {
        let repo = make_dao_repo();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();

        // 覆盖写已存在凭证
        let updated = CredentialModel {
            id: "c1".to_string(),
            user_id: "alice".to_string(),
            credential_type: "password".to_string(),
            secret_data: "new-hash".to_string(),
            label: Some("updated".to_string()),
            created_at: 100,
            enabled: false,
            priority: 5,
        };
        repo.update(updated.clone()).await.unwrap();
        let found = repo.find_by_user("alice").await.unwrap();
        assert_eq!(found[0].secret_data, "new-hash");
        assert_eq!(found[0].label, Some("updated".to_string()));
        assert!(!found[0].enabled);
        assert_eq!(found[0].priority, 5);

        // 更新不存在凭证
        let missing = make_model("nonexistent", "alice", "password", 0);
        let result = repo.update(missing).await;
        assert!(result.is_err(), "更新不存在的凭证应返回错误");
    }

    /// R-006: `delete` 删除 + 不存在返回错误。
    #[tokio::test]
    async fn dao_repo_delete_removes_and_errors_on_missing() {
        let repo = make_dao_repo();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();

        repo.delete("c1").await.unwrap();
        let found = repo.find_by_user("alice").await.unwrap();
        assert!(found.is_empty(), "删除后应查不到凭证");

        // 删除不存在凭证
        let result = repo.delete("c1").await;
        assert!(result.is_err(), "删除不存在的凭证应返回错误");
    }

    /// R-006: 多用户隔离 — 不同用户的凭证互不影响（DAO key 含 user_id 前缀）。
    #[tokio::test]
    async fn dao_repo_multi_user_isolation() {
        let repo = make_dao_repo();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();
        repo.create(make_model("c2", "bob", "password", 0))
            .await
            .unwrap();

        let alice = repo.find_by_user("alice").await.unwrap();
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].id, "c1");

        let bob = repo.find_by_user("bob").await.unwrap();
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0].id, "c2");

        // carol 无凭证
        let carol = repo.find_by_user("carol").await.unwrap();
        assert!(carol.is_empty());
    }

    /// R-006: 单用户多凭证类型（password + totp + webauthn 共存）。
    #[tokio::test]
    async fn dao_repo_multi_credential_types_per_user() {
        let repo = make_dao_repo();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();
        repo.create(make_model("c2", "alice", "totp", 1))
            .await
            .unwrap();
        repo.create(make_model("c3", "alice", "webauthn", 2))
            .await
            .unwrap();

        let all = repo.find_by_user("alice").await.unwrap();
        assert_eq!(all.len(), 3);
        let types: Vec<&str> = all.iter().map(|c| c.credential_type.as_str()).collect();
        assert!(types.contains(&"password"));
        assert!(types.contains(&"totp"));
        assert!(types.contains(&"webauthn"));
    }

    /// R-006: `find_by_user` 返回含 `enabled=false` 的凭证（trait 层不过滤 enabled，业务层负责）。
    #[tokio::test]
    async fn dao_repo_find_returns_disabled_credentials() {
        let repo = make_dao_repo();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();
        // 创建一个 enabled=false 的凭证
        let disabled = CredentialModel {
            id: "c2".to_string(),
            user_id: "alice".to_string(),
            credential_type: "totp".to_string(),
            secret_data: "secret".to_string(),
            label: None,
            created_at: 0,
            enabled: false,
            priority: 1,
        };
        repo.create(disabled).await.unwrap();

        let found = repo.find_by_user("alice").await.unwrap();
        assert_eq!(
            found.len(),
            2,
            "find_by_user 应返回 enabled + disabled 凭证"
        );
        let disabled_cred = found.iter().find(|c| c.id == "c2").unwrap();
        assert!(!disabled_cred.enabled, "disabled 凭证 enabled 应为 false");
    }

    /// R-006: `find_by_user` 按 `priority` 升序返回（trait 契约）。
    #[tokio::test]
    async fn dao_repo_priority_order_ascending() {
        let repo = make_dao_repo();
        // 故意乱序插入：priority 5, 1, 3
        repo.create(make_model("c1", "alice", "password", 5))
            .await
            .unwrap();
        repo.create(make_model("c2", "alice", "totp", 1))
            .await
            .unwrap();
        repo.create(make_model("c3", "alice", "webauthn", 3))
            .await
            .unwrap();

        let found = repo.find_by_user("alice").await.unwrap();
        assert_eq!(found.len(), 3);
        // 按 priority 升序：1, 3, 5
        assert_eq!(found[0].id, "c2");
        assert_eq!(found[0].priority, 1);
        assert_eq!(found[1].id, "c3");
        assert_eq!(found[1].priority, 3);
        assert_eq!(found[2].id, "c1");
        assert_eq!(found[2].priority, 5);
    }

    /// R-006: `create` 重复 ID 返回错误。
    #[tokio::test]
    async fn dao_repo_create_duplicate_returns_error() {
        let repo = make_dao_repo();
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();
        let dup = make_model("c1", "alice", "password", 0);
        let result = repo.create(dup).await;
        assert!(result.is_err(), "重复 create 应返回错误");
    }

    /// R-006: `DaoCredentialRepository` 可作 `Arc<dyn CredentialRepository>` 使用。
    #[tokio::test]
    async fn dao_repo_usable_as_trait_object() {
        let repo: Arc<dyn CredentialRepository> = Arc::new(make_dao_repo());
        repo.create(make_model("c1", "alice", "password", 0))
            .await
            .unwrap();
        let found = repo.find_by_user("alice").await.unwrap();
        assert_eq!(found.len(), 1);
    }
}
