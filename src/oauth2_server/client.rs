//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 客户端管理模块。
//!
//! 提供 `OAuth2Client` struct + `OAuth2ClientStore` trait + `DaoOAuth2ClientStore` 实现。
//!
//! ## 设计
//!
//! - `client_secret` 使用 Argon2id 哈希存储，不明文
//! - `pkce_required` 始终为 `true`（R-oauth2-006 强制 PKCE）
//! - `OAuth2ClientStore` 基于 `BulwarkDao`（key-value 存储），客户端配置序列化为 JSON
//! - `DaoKeyPrefix::OAuth2Client` 提供 key 前缀（`oauth2:client:`）

use crate::constants::DaoKeyPrefix;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Version,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// OAuth2 授权类型。
///
/// 对应 RFC 6749 定义的四种 grant_type。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// 授权码流程（authorization_code）。
    AuthorizationCode,
    /// 刷新令牌流程（refresh_token）。
    RefreshToken,
    /// 客户端凭证流程（client_credentials）。
    ClientCredentials,
    /// 密码流程（password，遗留兼容）。
    Password,
}

impl GrantType {
    /// 返回 OAuth2 规范的 grant_type 字符串。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
            Self::Password => "password",
        }
    }
}

impl std::str::FromStr for GrantType {
    type Err = BulwarkError;

    /// 从字符串解析 grant_type（RFC 6749 §4）。
    ///
    /// 与项目内 `Annotation` / `DigestAlgorithm` 一致采用 `std::str::FromStr` trait，
    /// 调用方用 `"authorization_code".parse::<GrantType>()` 而非 inherent method，
    /// 避免遮蔽 std trait。
    fn from_str(s: &str) -> BulwarkResult<Self> {
        match s {
            "authorization_code" => Ok(Self::AuthorizationCode),
            "refresh_token" => Ok(Self::RefreshToken),
            "client_credentials" => Ok(Self::ClientCredentials),
            "password" => Ok(Self::Password),
            other => Err(BulwarkError::OAuth2(format!(
                "unsupported_grant_type: {other}"
            ))),
        }
    }
}

/// OAuth2 客户端配置。
///
/// 管理 OAuth2 客户端的元数据与凭证，对应 RFC 6749 §2 客户端凭证。
///
/// `client_secret` 使用 Argon2id 哈希存储，不明文保存。
/// `pkce_required` 始终为 `true`（R-oauth2-006 强制 PKCE）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Client {
    /// 客户端 ID（唯一标识）。
    pub client_id: String,
    /// 客户端密钥的 Argon2id 哈希字符串。
    pub client_secret_hash: String,
    /// 允许的 redirect_uri 白名单。
    pub redirect_uris: Vec<String>,
    /// 允许的 grant_type 列表。
    pub grant_types: Vec<GrantType>,
    /// 允许的 scope 列表。
    pub scopes: Vec<String>,
    /// 是否强制 PKCE（始终为 `true`，R-oauth2-006）。
    pub pkce_required: bool,
}

impl OAuth2Client {
    /// 创建新的 OAuth2 客户端。
    ///
    /// 对 `client_secret` 执行 Argon2id 哈希后存储，不明文保存。
    /// `pkce_required` 始终设为 `true`。
    ///
    /// # 参数
    /// - `client_id`：客户端 ID
    /// - `client_secret`：客户端明文密钥（哈希后存储）
    /// - `redirect_uris`：允许的 redirect_uri 白名单
    /// - `grant_types`：允许的 grant_type 列表
    /// - `scopes`：允许的 scope 列表
    pub fn new(
        client_id: &str,
        client_secret: &str,
        redirect_uris: Vec<String>,
        grant_types: Vec<GrantType>,
        scopes: Vec<String>,
    ) -> BulwarkResult<Self> {
        if client_id.is_empty() {
            return Err(BulwarkError::InvalidParam("client_id 不能为空".into()));
        }
        if client_secret.is_empty() {
            return Err(BulwarkError::InvalidParam("client_secret 不能为空".into()));
        }
        let client_secret_hash = hash_secret(client_secret)?;
        Ok(Self {
            client_id: client_id.to_string(),
            client_secret_hash,
            redirect_uris,
            grant_types,
            scopes,
            pkce_required: true,
        })
    }

    /// 验证客户端密钥。
    ///
    /// 将明文 `client_secret` 与存储的 Argon2id 哈希比对。
    ///
    /// # 返回
    /// - `Ok(true)`：密钥匹配
    /// - `Ok(false)`：密钥不匹配
    /// - `Err`：哈希格式无效
    pub fn verify_secret(&self, client_secret: &str) -> BulwarkResult<bool> {
        verify_secret(client_secret, &self.client_secret_hash)
    }

    /// 校验 redirect_uri 是否在白名单中。
    ///
    /// 精确匹配（不支持通配符），防止 open redirect 攻击（R-oauth2-002）。
    pub fn is_redirect_uri_allowed(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|uri| uri == redirect_uri)
    }

    /// 校验是否允许指定 grant_type。
    pub fn allows_grant_type(&self, grant_type: &GrantType) -> bool {
        self.grant_types.iter().any(|gt| gt == grant_type)
    }

    /// 校验是否允许指定 scope。
    ///
    /// 空scopes 列表表示允许任意 scope。
    pub fn allows_scope(&self, scope: &str) -> bool {
        self.scopes.is_empty() || self.scopes.iter().any(|s| s == scope)
    }

    /// 批量校验 scope 列表是否全部在 allowed_scopes 内。
    ///
    /// 空 allowed_scopes 表示允许任意 scope（向后兼容）。
    /// 任一 scope 不在 allowed_scopes 内则返回 `invalid_scope` 错误。
    ///
    /// # 参数
    /// - `scopes`: 待校验的 scope 列表
    ///
    /// # 返回
    /// - `Ok(())`: 所有 scope 均允许（或 allowed_scopes 为空）
    /// - `Err(BulwarkError::OAuth2)`: 存在不允许的 scope，错误消息含 `invalid_scope`
    pub fn validate_scopes(&self, scopes: &[String]) -> BulwarkResult<()> {
        if self.scopes.is_empty() {
            return Ok(());
        }
        for s in scopes {
            if !self.allows_scope(s) {
                return Err(BulwarkError::OAuth2(format!(
                    "invalid_scope: scope '{}' 不在客户端 allowed_scopes 内",
                    s
                )));
            }
        }
        Ok(())
    }
}

/// OAuth2 客户端存储 trait。
///
/// 提供 CRUD 操作抽象，`DaoOAuth2ClientStore` 基于 `BulwarkDao` 实现。
#[async_trait]
pub trait OAuth2ClientStore: Send + Sync {
    /// 创建客户端（若 client_id 已存在则返回错误）。
    async fn create(&self, client: OAuth2Client) -> BulwarkResult<()>;

    /// 获取客户端配置。
    async fn get(&self, client_id: &str) -> BulwarkResult<Option<OAuth2Client>>;

    /// 更新客户端配置（必须已存在）。
    async fn update(&self, client: OAuth2Client) -> BulwarkResult<()>;

    /// 删除客户端。
    async fn delete(&self, client_id: &str) -> BulwarkResult<()>;

    /// 列出所有客户端（按 client_id 排序）。
    async fn list(&self) -> BulwarkResult<Vec<OAuth2Client>>;
}

/// 基于 `BulwarkDao` 的 `OAuth2ClientStore` 实现。
///
/// 客户端配置序列化为 JSON 存储，key 格式：`oauth2:client:{client_id}`。
/// 使用 `keys()` 扫描实现 `list()`。
pub struct DaoOAuth2ClientStore {
    dao: Arc<dyn BulwarkDao>,
}

impl DaoOAuth2ClientStore {
    /// 创建 store 实例。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }

    /// 构造 DAO key。
    fn build_key(client_id: &str) -> String {
        DaoKeyPrefix::OAuth2Client.build_key(client_id)
    }
}

#[async_trait]
impl OAuth2ClientStore for DaoOAuth2ClientStore {
    async fn create(&self, client: OAuth2Client) -> BulwarkResult<()> {
        let key = Self::build_key(&client.client_id);
        if self.dao.get(&key).await?.is_some() {
            return Err(BulwarkError::OAuth2(format!(
                "客户端已存在: {}",
                client.client_id
            )));
        }
        let json = serde_json::to_string(&client)
            .map_err(|e| BulwarkError::Internal(format!("OAuth2Client 序列化失败: {e}")))?;
        self.dao.set_permanent(&key, &json).await
    }

    async fn get(&self, client_id: &str) -> BulwarkResult<Option<OAuth2Client>> {
        let key = Self::build_key(client_id);
        match self.dao.get(&key).await? {
            Some(json) => {
                let client: OAuth2Client = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Internal(format!("OAuth2Client 反序列化失败: {e}"))
                })?;
                Ok(Some(client))
            },
            None => Ok(None),
        }
    }

    async fn update(&self, client: OAuth2Client) -> BulwarkResult<()> {
        let key = Self::build_key(&client.client_id);
        if self.dao.get(&key).await?.is_none() {
            return Err(BulwarkError::OAuth2(format!(
                "客户端不存在: {}",
                client.client_id
            )));
        }
        let json = serde_json::to_string(&client)
            .map_err(|e| BulwarkError::Internal(format!("OAuth2Client 序列化失败: {e}")))?;
        self.dao.update(&key, &json).await
    }

    async fn delete(&self, client_id: &str) -> BulwarkResult<()> {
        let key = Self::build_key(client_id);
        self.dao.delete(&key).await
    }

    async fn list(&self) -> BulwarkResult<Vec<OAuth2Client>> {
        let pattern = format!("{}*", DaoKeyPrefix::OAuth2Client.as_str());
        let keys = self.dao.keys(&pattern).await?;
        let mut clients = Vec::with_capacity(keys.len());
        for key in keys {
            match self.dao.get(&key).await? {
                Some(json) => {
                    let client: OAuth2Client = serde_json::from_str(&json).map_err(|e| {
                        BulwarkError::Internal(format!("OAuth2Client 反序列化失败: {e}"))
                    })?;
                    clients.push(client);
                },
                None => continue,
            }
        }
        clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));
        Ok(clients)
    }
}

// ============================================================================
// 内部 Argon2 哈希工具
// ============================================================================

/// 使用 Argon2id 哈希密钥。
///
/// 与 `account::credential::Argon2Hasher` 独立（不同能力域，不引入 account-credential 依赖）。
/// 参数：Argon2id, m=19456, t=2, p=1（与 Argon2Hasher 默认一致）。
fn hash_secret(secret: &str) -> BulwarkResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2::Params::default(),
    );
    let hash = argon2
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| BulwarkError::Internal(format!("Argon2 哈希失败: {e}")))?;
    Ok(hash.to_string())
}

/// 验证明文密钥与 Argon2id 哈希是否匹配。
fn verify_secret(secret: &str, hash_str: &str) -> BulwarkResult<bool> {
    let parsed = PasswordHash::new(hash_str)
        .map_err(|e| BulwarkError::InvalidParam(format!("Argon2 哈希格式无效: {e}")))?;
    Ok(Argon2::default()
        .verify_password(secret.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    // === GrantType 测试 ===

    #[test]
    fn grant_type_as_str() {
        assert_eq!(GrantType::AuthorizationCode.as_str(), "authorization_code");
        assert_eq!(GrantType::RefreshToken.as_str(), "refresh_token");
        assert_eq!(GrantType::ClientCredentials.as_str(), "client_credentials");
        assert_eq!(GrantType::Password.as_str(), "password");
    }

    #[test]
    fn grant_type_serde_roundtrip() {
        let gt = GrantType::AuthorizationCode;
        let json = serde_json::to_string(&gt).unwrap();
        assert_eq!(json, "\"authorization_code\"");
        let de: GrantType = serde_json::from_str(&json).unwrap();
        assert_eq!(de, gt);
    }

    // === FromStr trait 测试（与项目内 Annotation/DigestAlgorithm 惯例对齐） ===

    #[test]
    fn grant_type_from_str_parses_all_known_types() {
        assert_eq!(
            "authorization_code".parse::<GrantType>().unwrap(),
            GrantType::AuthorizationCode
        );
        assert_eq!(
            "refresh_token".parse::<GrantType>().unwrap(),
            GrantType::RefreshToken
        );
        assert_eq!(
            "client_credentials".parse::<GrantType>().unwrap(),
            GrantType::ClientCredentials
        );
        assert_eq!(
            "password".parse::<GrantType>().unwrap(),
            GrantType::Password
        );
    }

    #[test]
    fn grant_type_from_str_rejects_unknown() {
        let err = "unknown_grant".parse::<GrantType>().unwrap_err();
        assert!(
            matches!(err, BulwarkError::OAuth2(_)),
            "未知 grant_type 应返回 OAuth2 错误"
        );
        assert!(
            err.to_string().contains("unsupported_grant_type"),
            "错误信息应包含 unsupported_grant_type"
        );
    }

    #[test]
    fn grant_type_from_str_roundtrips_with_as_str() {
        for original in [
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::Password,
        ] {
            let s = original.as_str();
            let parsed: GrantType = s.parse().unwrap();
            assert_eq!(parsed, original, "as_str -> FromStr 往返失败");
        }
    }

    // === OAuth2Client 测试 ===

    #[test]
    fn new_client_hashes_secret_and_enforces_pkce() {
        let client = OAuth2Client::new(
            "client-001",
            "super-secret",
            vec!["https://app.example.com/callback".into()],
            vec![GrantType::AuthorizationCode],
            vec!["read".into()],
        )
        .expect("创建客户端");
        assert_eq!(client.client_id, "client-001");
        assert_ne!(client.client_secret_hash, "super-secret");
        assert!(client.client_secret_hash.starts_with("$argon2id$"));
        assert!(client.pkce_required, "pkce_required 必须始终为 true");
        assert_eq!(client.redirect_uris.len(), 1);
        assert_eq!(client.grant_types.len(), 1);
    }

    #[test]
    fn new_client_rejects_empty_id() {
        let err = OAuth2Client::new("", "secret", vec![], vec![], vec![]).unwrap_err();
        assert!(matches!(err, BulwarkError::InvalidParam(_)));
    }

    #[test]
    fn new_client_rejects_empty_secret() {
        let err = OAuth2Client::new("cid", "", vec![], vec![], vec![]).unwrap_err();
        assert!(matches!(err, BulwarkError::InvalidParam(_)));
    }

    #[test]
    fn verify_secret_matches_correct() {
        let client = OAuth2Client::new("client-001", "super-secret", vec![], vec![], vec![])
            .expect("创建客户端");
        assert!(client.verify_secret("super-secret").expect("验证"));
    }

    #[test]
    fn verify_secret_rejects_wrong() {
        let client = OAuth2Client::new("client-001", "super-secret", vec![], vec![], vec![])
            .expect("创建客户端");
        assert!(!client.verify_secret("wrong-secret").expect("验证"));
    }

    #[test]
    fn verify_secret_rejects_invalid_hash() {
        let err = verify_secret("secret", "not-a-valid-hash").unwrap_err();
        assert!(matches!(err, BulwarkError::InvalidParam(_)));
    }

    // === redirect_uri 白名单测试 ===

    #[test]
    fn is_redirect_uri_allowed_exact_match() {
        let client = OAuth2Client::new(
            "c1",
            "s",
            vec![
                "https://app1.example.com/callback".into(),
                "https://app2.example.com/callback".into(),
            ],
            vec![],
            vec![],
        )
        .unwrap();
        assert!(client.is_redirect_uri_allowed("https://app1.example.com/callback"));
        assert!(client.is_redirect_uri_allowed("https://app2.example.com/callback"));
    }

    #[test]
    fn is_redirect_uri_allowed_rejects_not_in_whitelist() {
        let client = OAuth2Client::new(
            "c1",
            "s",
            vec!["https://app.example.com/callback".into()],
            vec![],
            vec![],
        )
        .unwrap();
        assert!(!client.is_redirect_uri_allowed("https://evil.example.com/callback"));
    }

    #[test]
    fn is_redirect_uri_allowed_rejects_partial_match() {
        let client = OAuth2Client::new(
            "c1",
            "s",
            vec!["https://app.example.com/callback".into()],
            vec![],
            vec![],
        )
        .unwrap();
        assert!(!client.is_redirect_uri_allowed("https://app.example.com/callback/extra"));
        assert!(!client.is_redirect_uri_allowed("http://app.example.com/callback"));
    }

    // === grant_type / scope 校验测试 ===

    #[test]
    fn allows_grant_type() {
        let client = OAuth2Client::new(
            "c1",
            "s",
            vec![],
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            vec![],
        )
        .unwrap();
        assert!(client.allows_grant_type(&GrantType::AuthorizationCode));
        assert!(client.allows_grant_type(&GrantType::RefreshToken));
        assert!(!client.allows_grant_type(&GrantType::ClientCredentials));
    }

    #[test]
    fn allows_scope_empty_means_any() {
        let client = OAuth2Client::new("c1", "s", vec![], vec![], vec![]).unwrap();
        assert!(client.allows_scope("anything"));
    }

    #[test]
    fn allows_scope_explicit_list() {
        let client = OAuth2Client::new(
            "c1",
            "s",
            vec![],
            vec![],
            vec!["read".into(), "write".into()],
        )
        .unwrap();
        assert!(client.allows_scope("read"));
        assert!(client.allows_scope("write"));
        assert!(!client.allows_scope("admin"));
    }

    // === DaoOAuth2ClientStore 测试 ===

    use crate::dao::MockDao;

    fn make_test_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            vec!["read".into(), "write".into()],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn store_create_and_get() {
        let store = DaoOAuth2ClientStore::new(Arc::new(MockDao::new()));
        let client = make_test_client("store-001");
        store.create(client.clone()).await.expect("创建");
        let got = store.get("store-001").await.expect("查询").expect("应存在");
        assert_eq!(got.client_id, "store-001");
        assert_eq!(got.redirect_uris, client.redirect_uris);
        assert_eq!(got.grant_types, client.grant_types);
        assert!(got.pkce_required);
    }

    #[tokio::test]
    async fn store_create_duplicate_fails() {
        let store = DaoOAuth2ClientStore::new(Arc::new(MockDao::new()));
        let client = make_test_client("dup-001");
        store.create(client.clone()).await.expect("首次创建");
        let err = store.create(client).await.unwrap_err();
        assert!(matches!(err, BulwarkError::OAuth2(_)));
    }

    #[tokio::test]
    async fn store_get_nonexistent_returns_none() {
        let store = DaoOAuth2ClientStore::new(Arc::new(MockDao::new()));
        let got = store.get("no-such").await.expect("查询");
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn store_update_existing() {
        let store = DaoOAuth2ClientStore::new(Arc::new(MockDao::new()));
        let mut client = make_test_client("upd-001");
        store.create(client.clone()).await.expect("创建");
        client.scopes = vec!["admin".into()];
        store.update(client).await.expect("更新");
        let got = store.get("upd-001").await.unwrap().unwrap();
        assert_eq!(got.scopes, vec!["admin"]);
    }

    #[tokio::test]
    async fn store_update_nonexistent_fails() {
        let store = DaoOAuth2ClientStore::new(Arc::new(MockDao::new()));
        let client = make_test_client("no-exist");
        let err = store.update(client).await.unwrap_err();
        assert!(matches!(err, BulwarkError::OAuth2(_)));
    }

    #[tokio::test]
    async fn store_delete() {
        let store = DaoOAuth2ClientStore::new(Arc::new(MockDao::new()));
        store
            .create(make_test_client("del-001"))
            .await
            .expect("创建");
        store.delete("del-001").await.expect("删除");
        assert!(store.get("del-001").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn store_list_sorted_by_client_id() {
        let store = DaoOAuth2ClientStore::new(Arc::new(MockDao::new()));
        store.create(make_test_client("charlie")).await.unwrap();
        store.create(make_test_client("alpha")).await.unwrap();
        store.create(make_test_client("bravo")).await.unwrap();
        let list = store.list().await.expect("列表");
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].client_id, "alpha");
        assert_eq!(list[1].client_id, "bravo");
        assert_eq!(list[2].client_id, "charlie");
    }

    #[tokio::test]
    async fn store_list_empty() {
        let store = DaoOAuth2ClientStore::new(Arc::new(MockDao::new()));
        let list = store.list().await.expect("列表");
        assert!(list.is_empty());
    }

    #[test]
    fn build_key_format() {
        let key = DaoOAuth2ClientStore::build_key("my-client");
        assert_eq!(key, "oauth2:client:my-client");
    }
}
