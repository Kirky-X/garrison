//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SAML 2.0 协议支持骨架。
//!
//! 提供 SAML 2.0 核心数据结构（`SamlAssertion`/`SamlResponse`/`SamlRequest`）
//! 和 `SamlProvider` trait（`build_authn_request`/`parse_response`/`validate_assertion`）。
//!
//! `DefaultSamlProvider` 提供基础实现：
//! - `build_authn_request`：生成 AuthnRequest XML（UUID 作为 id，当前时间作为 issue_instant）
//! - `parse_response`：使用 quick-xml 解析 Response XML 提取关键字段
//! - `validate_assertion`：返回 `NotImplemented`（签名验证 defer 到后续变更）
//!
//! 仅在启用 `protocol-sso` 特性时编译。
//!
//! # Known Limitations
//!
//! ## SAML 签名验证未实现（fail-closed）
//!
//! 当前 `DefaultSamlProvider::validate_assertion` 返回 `BulwarkError::NotImplemented`，
//! **不执行任何 XML 签名验证**。出于安全考虑（fail-closed 原则），`parse_response`
//! 在检测到未验证的 Assertion 时会将其剥离（`response.assertion = None`），
//! 并通过 `tracing::warn!` 记录告警。这意味着：
//!
//! - 使用 `DefaultSamlProvider` 解析的 Response **不会包含 Assertion 数据**，
//!   无法完成 SSO 单点登录流程。
//! - 调用方拿到的 `SamlResponse` 中 `assertion` 字段为 `None`。
//!
//! ## 生产环境使用建议
//!
//! 生产环境必须自行实现 `SamlProvider` trait 并覆盖 `validate_assertion`，
//! 使用成熟的 XML 签名库（如 `openssl` / `ring` / `xmlsec`）验证：
//!
//! 1. Response 签名（`<ds:Signature>` 覆盖 `<samlp:Response>`）
//! 2. Assertion 签名（`<ds:Signature>` 覆盖 `<saml:Assertion>`）
//! 3. 签名证书信任链（对接 IdP 元数据中的 X.509 证书）
//! 4. 算法白名单（禁止 `rsa-1_5` 等弱算法，仅允许 `rsa-sha256` / `ecdsa-sha256`）
//!
//! ## 已实现的安全检查
//!
//! 以下安全检查已内置，无需自行实现：
//!
//! - **NotOnOrAfter 过期校验**：`parse_saml_response_xml` 解析后立即校验
//!   Assertion 的 `NotOnOrAfter` 时间戳，过期则返回 `InvalidToken` 错误。
//! - **Assertion 重放防护**：[`check_assertion_replay`] 函数通过 DAO 记录已消费的
//!   Assertion ID（key = `saml:replay:{assertion_id}`），TTL 由 `not_on_or_after` 决定。
//! - **fail-closed 剥离**：未验证的 Assertion 一律剥离，不会泄漏给调用方。

use crate::constants::DaoKeyPrefix;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// SAML 2.0 数据结构
// ============================================================================

/// SAML Assertion 结构，包含 IdP 签发的身份声明。
///
/// 对应 SAML 2.0 `<saml:Assertion>` 元素。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlAssertion {
    /// Assertion ID（`<saml:Assertion ID="...">` 属性，用于重放防护）。
    #[serde(default)]
    pub id: String,
    /// 签发者标识（`<saml:Issuer>`）。
    pub issuer: String,
    /// 主体标识（`<saml:Subject>`，通常为 name_id）。
    pub subject: String,
    /// 受众限制（`<saml:Audience>`）。
    pub audience: String,
    /// 断言过期时间（`NotOnOrAfter`，RFC 3339 格式字符串）。
    pub not_on_or_after: String,
    /// 属性集合（`<saml:AttributeStatement>` 中的键值对）。
    pub attributes: Vec<(String, String)>,
}

/// SAML Response 结构，IdP 返回给 SP 的响应。
///
/// 对应 SAML 2.0 `<samlp:Response>` 元素。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlResponse {
    /// 目标 URL（`Destination` 属性）。
    pub destination: String,
    /// 签发者标识（`<saml:Issuer>`）。
    pub issuer: String,
    /// 包含的 Assertion（可选，状态码非成功时可能为 None）。
    pub assertion: Option<SamlAssertion>,
    /// 状态码（`<samlp:StatusCode>` Value 属性，如 `urn:oasis:names:tc:SAML:2.0:status:Success`）。
    pub status_code: String,
}

/// SAML AuthnRequest 结构，SP 发送给 IdP 的认证请求。
///
/// 对应 SAML 2.0 `<samlp:AuthnRequest>` 元素。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlRequest {
    /// 请求 ID（唯一标识，UUID 格式）。
    pub id: String,
    /// 签发时间（RFC 3339 格式字符串）。
    pub issue_instant: String,
    /// 目标 URL（IdP 的 SSO 端点）。
    pub destination: String,
    /// 签发者标识（SP 的 entity_id）。
    pub issuer: String,
    /// Assertion Consumer Service URL（IdP 回调 SP 的 URL）。
    pub assertion_consumer_service_url: String,
}

// ============================================================================
// SamlProvider trait
// ============================================================================

/// SAML 2.0 协议交互 trait。
///
/// 支持构建 AuthnRequest、解析 Response、验证 Assertion。
#[async_trait]
pub trait SamlProvider: Send + Sync {
    /// 构建 SAML AuthnRequest。
    ///
    /// # 参数
    /// - `sp_entity_id`: SP 的 entity_id。
    /// - `acs_url`: Assertion Consumer Service URL。
    ///
    /// # 返回
    /// `SamlRequest` 结构。
    async fn build_authn_request(
        &self,
        sp_entity_id: &str,
        acs_url: &str,
    ) -> BulwarkResult<SamlRequest>;

    /// 解析 SAML Response XML。
    ///
    /// 输入为 base64 解码后的原始 XML 字符串，调用方负责 base64 解码。
    ///
    /// # 参数
    /// - `response_xml`: SAML Response XML 字符串。
    ///
    /// # 返回
    /// 解析后的 `SamlResponse` 结构。
    async fn parse_response(&self, response_xml: &str) -> BulwarkResult<SamlResponse>;

    /// 验证 SAML Assertion 签名。
    ///
    /// # 参数
    /// - `assertion`: 待验证的 Assertion。
    ///
    /// # 返回
    /// - `Ok(true)`: 签名验证通过。
    /// - `Err(BulwarkError::NotImplemented)`: 签名验证尚未实现。
    async fn validate_assertion(&self, assertion: &SamlAssertion) -> BulwarkResult<bool>;
}

// ============================================================================
// DefaultSamlProvider
// ============================================================================

/// 默认 SAML Provider 实现。
///
/// 提供基础的 AuthnRequest 构建和 Response 解析功能。
/// 签名验证返回 `NotImplemented`，defer 到后续变更。
pub struct DefaultSamlProvider;

impl DefaultSamlProvider {
    /// 创建新的 `DefaultSamlProvider` 实例。
    ///
    /// # 返回
    /// 可用的 `DefaultSamlProvider` 实例。
    pub fn new() -> BulwarkResult<Self> {
        Ok(Self)
    }
}

impl Default for DefaultSamlProvider {
    fn default() -> Self {
        Self::new().expect("DefaultSamlProvider::new 不应失败")
    }
}

#[async_trait]
impl SamlProvider for DefaultSamlProvider {
    async fn build_authn_request(
        &self,
        sp_entity_id: &str,
        acs_url: &str,
    ) -> BulwarkResult<SamlRequest> {
        Ok(SamlRequest {
            id: Uuid::new_v4().to_string(),
            issue_instant: Utc::now().to_rfc3339(),
            destination: String::new(), // IdP 端点由调用方填入
            issuer: sp_entity_id.to_string(),
            assertion_consumer_service_url: acs_url.to_string(),
        })
    }

    async fn parse_response(&self, response_xml: &str) -> BulwarkResult<SamlResponse> {
        let mut response = parse_saml_response_xml(response_xml)?;
        if let Some(ref assertion) = response.assertion {
            match self.validate_assertion(assertion).await {
                Ok(true) => {},
                Ok(false) => {
                    tracing::warn!("SAML Assertion 签名验证失败，已剥离");
                    response.assertion = None;
                },
                Err(BulwarkError::NotImplemented(_)) => {
                    tracing::warn!("SAML 签名验证未实现，已剥离 Assertion（fail-closed）");
                    response.assertion = None;
                },
                Err(e) => return Err(e),
            }
        }
        Ok(response)
    }

    async fn validate_assertion(&self, _assertion: &SamlAssertion) -> BulwarkResult<bool> {
        Err(BulwarkError::NotImplemented(
            "SAML 签名验证尚未实现".to_string(),
        ))
    }
}

// ============================================================================
// XML 解析辅助
// ============================================================================

/// 从 SAML Response XML 中提取关键字段。
///
/// 使用 quick-xml 的 pull reader 解析 XML，提取 Destination / Issuer / StatusCode / Assertion。
fn parse_saml_response_xml(xml: &str) -> BulwarkResult<SamlResponse> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();

    let mut destination = String::new();
    let mut issuer = String::new();
    let mut status_code = String::new();
    let mut assertion: Option<SamlAssertion> = None;

    // Assertion 解析状态
    let mut in_assertion = false;
    let mut in_issuer = false;
    let mut in_subject = false;
    let mut in_audience = false;
    let mut in_attribute = false;
    let mut current_attr_name = String::new();

    let mut assertion_issuer = String::new();
    let mut assertion_subject = String::new();
    let mut assertion_audience = String::new();
    let mut assertion_not_on_or_after = String::new();
    let mut assertion_id = String::new();
    let mut assertion_attributes: Vec<(String, String)> = Vec::new();
    let mut current_text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(BulwarkError::Internal(format!("SAML XML 解析失败: {}", e))),
            Ok(Event::Eof) => break,

            // Start 元素：设置状态标志 + 提取属性
            Ok(Event::Start(e)) => {
                if !check_saml_namespace(e.name().as_ref()) {
                    continue;
                }
                let local_name = extract_local_name(e.name().as_ref());
                match local_name.as_str() {
                    "Response" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Destination" {
                                destination = attr_value_to_string(&attr.value);
                            }
                        }
                    },
                    "Assertion" => {
                        in_assertion = true;
                        assertion_issuer.clear();
                        assertion_subject.clear();
                        assertion_audience.clear();
                        assertion_not_on_or_after.clear();
                        assertion_id.clear();
                        assertion_attributes.clear();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"ID" {
                                assertion_id = attr_value_to_string(&attr.value);
                            }
                        }
                    },
                    "Issuer" => {
                        in_issuer = true;
                        current_text.clear();
                    },
                    "Subject" => in_subject = true,
                    "Audience" => {
                        in_audience = true;
                        current_text.clear();
                    },
                    "Attribute" => {
                        in_attribute = true;
                        current_attr_name.clear();
                        current_text.clear();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Name" {
                                current_attr_name = attr_value_to_string(&attr.value);
                            }
                        }
                    },
                    "SubjectConfirmationData" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"NotOnOrAfter" {
                                assertion_not_on_or_after = attr_value_to_string(&attr.value);
                            }
                        }
                    },
                    _ => {},
                }
            },

            // Empty 元素（自闭合如 <StatusCode Value="..."/>）：仅提取属性
            Ok(Event::Empty(e)) => {
                if !check_saml_namespace(e.name().as_ref()) {
                    continue;
                }
                let local_name = extract_local_name(e.name().as_ref());
                match local_name.as_str() {
                    "StatusCode" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Value" {
                                status_code = attr_value_to_string(&attr.value);
                            }
                        }
                    },
                    "SubjectConfirmationData" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"NotOnOrAfter" {
                                assertion_not_on_or_after = attr_value_to_string(&attr.value);
                            }
                        }
                    },
                    "AttributeValue" if in_attribute => {
                        if assertion_attributes
                            .iter()
                            .any(|(n, _)| n == &current_attr_name)
                        {
                            tracing::warn!(
                                attr_name = %current_attr_name,
                                "SAML Assertion 包含重复属性名，可能为属性污染攻击"
                            );
                        }
                        assertion_attributes.push((current_attr_name.clone(), String::new()));
                    },
                    _ => {},
                }
            },

            Ok(Event::End(e)) => {
                let local_name = extract_local_name(e.name().as_ref());
                match local_name.as_str() {
                    "Assertion" => {
                        if in_assertion {
                            assertion = Some(SamlAssertion {
                                id: assertion_id.clone(),
                                issuer: assertion_issuer.clone(),
                                subject: assertion_subject.clone(),
                                audience: assertion_audience.clone(),
                                not_on_or_after: assertion_not_on_or_after.clone(),
                                attributes: assertion_attributes.clone(),
                            });
                            in_assertion = false;
                        }
                    },
                    "Issuer" => {
                        if in_issuer {
                            if in_assertion {
                                assertion_issuer = current_text.clone();
                            } else {
                                issuer = current_text.clone();
                            }
                            in_issuer = false;
                            current_text.clear();
                        }
                    },
                    "Subject" => in_subject = false,
                    "Audience" => {
                        if in_audience {
                            assertion_audience = current_text.clone();
                            in_audience = false;
                            current_text.clear();
                        }
                    },
                    "Attribute" => {
                        if in_attribute {
                            if assertion_attributes
                                .iter()
                                .any(|(n, _)| n == &current_attr_name)
                            {
                                tracing::warn!(
                                    attr_name = %current_attr_name,
                                    "SAML Assertion 包含重复属性名，可能为属性污染攻击"
                                );
                            }
                            assertion_attributes
                                .push((current_attr_name.clone(), current_text.clone()));
                            in_attribute = false;
                            current_text.clear();
                        }
                    },
                    "NameID" => {
                        if in_subject {
                            assertion_subject = current_text.clone();
                            current_text.clear();
                        }
                    },
                    "AttributeValue" => {
                        // AttributeValue 文本已收集到 current_text，在 Attribute End 时处理
                    },
                    _ => {},
                }
            },

            Ok(Event::Text(e)) => {
                let text = String::from_utf8_lossy(e.as_ref());
                current_text.push_str(&text);
            },

            _ => {},
        }
        buf.clear();
    }

    if let Some(ref assertion) = assertion {
        if !assertion.not_on_or_after.is_empty() {
            let expiry =
                chrono::DateTime::parse_from_rfc3339(&assertion.not_on_or_after).map_err(|e| {
                    BulwarkError::InvalidToken(format!("SAML NotOnOrAfter 解析失败: {}", e))
                })?;
            if Utc::now().timestamp() >= expiry.timestamp() {
                return Err(BulwarkError::InvalidToken(format!(
                    "SAML Assertion 已过期 (NotOnOrAfter: {})",
                    assertion.not_on_or_after
                )));
            }
        }
    }

    Ok(SamlResponse {
        destination,
        issuer,
        assertion,
        status_code,
    })
}

/// 检查 SAML Assertion 是否被重放（C-3 重放防护）。
///
/// 生产环境应在 [`SamlProvider::parse_response`] 后调用此函数，
/// 确保同一 Assertion ID 不被重复消费。
///
/// # 参数
/// - `assertion_id`: SAML Assertion ID（`<saml:Assertion ID="...">` 属性）。
/// - `not_on_or_after`: Assertion 过期时间（RFC 3339），用于计算缓存 TTL。
/// - `dao`: DAO 抽象（用于记录已消费的 Assertion ID）。
///
/// # 返回
/// - `Ok(true)`: 首次消费，已记录到 DAO。
/// - `Ok(false)`: 已被消费（重放拒绝）。
/// - `Err(_)`: DAO 读写失败或时间解析失败。
///
/// # TTL 计算
/// TTL = `NotOnOrAfter - now`（剩余有效期）。若 `not_on_or_after` 为空或已过期，
/// 使用 300 秒（5 分钟）兜底，确保缓存不会过早失效。
pub async fn check_assertion_replay(
    assertion_id: &str,
    not_on_or_after: &str,
    dao: &dyn crate::dao::BulwarkDao,
) -> BulwarkResult<bool> {
    if assertion_id.is_empty() {
        return Ok(true);
    }
    let key = format!("{}consumed:{}", DaoKeyPrefix::Saml, assertion_id);
    if dao.get(&key).await?.is_some() {
        return Ok(false);
    }
    let ttl = if not_on_or_after.is_empty() {
        300
    } else {
        let expiry = chrono::DateTime::parse_from_rfc3339(not_on_or_after).map_err(|e| {
            BulwarkError::InvalidToken(format!("SAML NotOnOrAfter 解析失败: {}", e))
        })?;
        let remaining = expiry.timestamp().saturating_sub(Utc::now().timestamp());
        if remaining > 0 {
            remaining as u64
        } else {
            300
        }
    };
    dao.set(&key, "1", ttl).await?;
    Ok(true)
}

/// 提取 XML 元素的 local name（去除命名空间前缀）。
///
/// 例如 `samlp:Response` → `Response`，`saml:Issuer` → `Issuer`。
fn extract_local_name(qualified: &[u8]) -> String {
    let full = String::from_utf8_lossy(qualified);
    match full.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => full.to_string(),
    }
}

/// 检查 XML 限定名的命名空间前缀是否为 SAML 允许的前缀。
///
/// 允许：`saml`、`samlp`、`ds`（XML 签名）、或无前缀（兼容无命名空间的 XML）。
/// 不允许的前缀（如 `evil:Assertion`）记录告警，防止命名空间混淆攻击。
///
/// 返回 true 表示前缀合法，false 表示不合法（调用方可选择跳过该元素）。
fn check_saml_namespace(qualified: &[u8]) -> bool {
    let full = String::from_utf8_lossy(qualified);
    match full.rsplit_once(':') {
        Some((prefix, _)) => {
            let valid = matches!(prefix, "saml" | "samlp" | "ds");
            if !valid {
                tracing::warn!(
                    qualified = %full,
                    "SAML XML 元素使用非标准命名空间前缀，可能为命名空间混淆攻击"
                );
            }
            valid
        },
        None => true,
    }
}

/// 将 quick-xml 的 attribute value 转为 String。
fn attr_value_to_string(value: &[u8]) -> String {
    String::from_utf8_lossy(value).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // 数据结构测试
    // ========================================================================

    /// SamlAssertion 序列化/反序列化往返（spec R-001: 所有结构实现 Serialize/Deserialize）。
    #[test]
    fn saml_assertion_serde_roundtrip() {
        let assertion = SamlAssertion {
            id: "assertion-001".to_string(),
            issuer: "https://idp.example.com".to_string(),
            subject: "user@example.com".to_string(),
            audience: "https://sp.example.com".to_string(),
            not_on_or_after: "2026-07-10T12:00:00Z".to_string(),
            attributes: vec![("email".to_string(), "user@example.com".to_string())],
        };
        let json = serde_json::to_string(&assertion).unwrap();
        let deserialized: SamlAssertion = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, assertion.id);
        assert_eq!(deserialized.issuer, assertion.issuer);
        assert_eq!(deserialized.subject, assertion.subject);
        assert_eq!(deserialized.audience, assertion.audience);
        assert_eq!(deserialized.not_on_or_after, assertion.not_on_or_after);
        assert_eq!(deserialized.attributes.len(), 1);
        assert_eq!(deserialized.attributes[0].0, "email");
        assert_eq!(deserialized.attributes[0].1, "user@example.com");
    }

    /// SamlResponse 序列化/反序列化往返（spec R-001）。
    #[test]
    fn saml_response_serde_roundtrip() {
        let response = SamlResponse {
            destination: "https://sp.example.com/acs".to_string(),
            issuer: "https://idp.example.com".to_string(),
            assertion: None,
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: SamlResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.destination, response.destination);
        assert_eq!(deserialized.issuer, response.issuer);
        assert!(deserialized.assertion.is_none());
        assert_eq!(deserialized.status_code, response.status_code);
    }

    /// SamlRequest 序列化/反序列化往返（spec R-001）。
    #[test]
    fn saml_request_serde_roundtrip() {
        let request = SamlRequest {
            id: "id-12345".to_string(),
            issue_instant: "2026-07-10T12:00:00Z".to_string(),
            destination: "https://idp.example.com/sso".to_string(),
            issuer: "https://sp.example.com".to_string(),
            assertion_consumer_service_url: "https://sp.example.com/acs".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: SamlRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, request.id);
        assert_eq!(deserialized.issue_instant, request.issue_instant);
        assert_eq!(deserialized.destination, request.destination);
        assert_eq!(deserialized.issuer, request.issuer);
        assert_eq!(
            deserialized.assertion_consumer_service_url,
            request.assertion_consumer_service_url
        );
    }

    /// SamlAssertion 实现 Clone + Debug（spec R-001 验收标准）。
    #[test]
    fn saml_assertion_implements_clone_debug() {
        let assertion = SamlAssertion {
            id: "assertion-002".to_string(),
            issuer: "idp".to_string(),
            subject: "user".to_string(),
            audience: "sp".to_string(),
            not_on_or_after: "2026-07-10T12:00:00Z".to_string(),
            attributes: vec![],
        };
        let cloned = assertion.clone();
        assert_eq!(cloned.issuer, assertion.issuer);
        let debug_str = format!("{:?}", assertion);
        assert!(debug_str.contains("SamlAssertion"));
    }

    // ========================================================================
    // DefaultSamlProvider 测试
    // ========================================================================

    /// DefaultSamlProvider::new() 返回可用实例（spec R-002 验收标准）。
    #[test]
    fn default_saml_provider_new_returns_ok() {
        let provider = DefaultSamlProvider::new();
        assert!(provider.is_ok());
    }

    /// SamlProvider trait 编译验证：DefaultSamlProvider 实现 SamlProvider trait（spec R-002）。
    #[test]
    fn default_saml_provider_implements_saml_provider() {
        fn assert_saml_provider<T: SamlProvider>(_provider: &T) {}
        let provider = DefaultSamlProvider::new().unwrap();
        assert_saml_provider(&provider);
    }

    /// build_authn_request 返回包含正确字段的 SamlRequest（spec R-002）。
    #[tokio::test]
    async fn build_authn_request_returns_valid_request() {
        let provider = DefaultSamlProvider::new().unwrap();
        let request = provider
            .build_authn_request("https://sp.example.com", "https://sp.example.com/acs")
            .await
            .unwrap();
        assert_eq!(request.issuer, "https://sp.example.com");
        assert_eq!(
            request.assertion_consumer_service_url,
            "https://sp.example.com/acs"
        );
        assert!(!request.id.is_empty());
        assert!(!request.issue_instant.is_empty());
    }

    /// build_authn_request 生成唯一 id（每次调用不同）（spec R-002）。
    #[tokio::test]
    async fn build_authn_request_generates_unique_ids() {
        let provider = DefaultSamlProvider::new().unwrap();
        let r1 = provider
            .build_authn_request("sp1", "https://sp1.example.com/acs")
            .await
            .unwrap();
        let r2 = provider
            .build_authn_request("sp1", "https://sp1.example.com/acs")
            .await
            .unwrap();
        assert_ne!(r1.id, r2.id);
    }

    /// parse_response 解析成功响应（spec R-002）。
    ///
    /// C-1: DefaultSamlProvider::validate_assertion 返回 NotImplemented，
    /// parse_response fail-closed 剥离 Assertion（不返回未验证的 Assertion）。
    /// XML 字段（destination / issuer / status_code）仍正常解析。
    #[tokio::test]
    async fn parse_response_success() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="assertion-123">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions>
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>user@example.com</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"#;
        let provider = DefaultSamlProvider::new().unwrap();
        let response = provider.parse_response(xml).await.unwrap();
        assert_eq!(response.destination, "https://sp.example.com/acs");
        assert_eq!(response.issuer, "https://idp.example.com");
        assert_eq!(
            response.status_code,
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        );
        assert!(
            response.assertion.is_none(),
            "C-1: validate_assertion 未实现时应剥离 Assertion（fail-closed）"
        );
    }

    /// parse_response 解析无 Assertion 的响应（状态码非成功）（spec R-002）。
    #[tokio::test]
    async fn parse_response_without_assertion() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/>
  </samlp:Status>
</samlp:Response>"#;
        let provider = DefaultSamlProvider::new().unwrap();
        let response = provider.parse_response(xml).await.unwrap();
        assert_eq!(response.destination, "https://sp.example.com/acs");
        assert_eq!(response.issuer, "https://idp.example.com");
        assert_eq!(
            response.status_code,
            "urn:oasis:names:tc:SAML:2.0:status:Requester"
        );
        assert!(response.assertion.is_none());
    }

    /// parse_response 解析非 SAML XML 返回空字段（spec R-002）。
    ///
    /// quick-xml 是宽松解析器，非 XML 文本不会报错，但解析结果中 SAML 字段均为空。
    #[tokio::test]
    async fn parse_response_non_saml_xml_returns_empty_fields() {
        let provider = DefaultSamlProvider::new().unwrap();
        let response = provider
            .parse_response("not a saml response")
            .await
            .unwrap();
        assert!(response.destination.is_empty());
        assert!(response.issuer.is_empty());
        assert!(response.status_code.is_empty());
        assert!(response.assertion.is_none());
    }

    /// C-2: 过期的 SAML Assertion（NotOnOrAfter < now）应返回 InvalidToken 错误。
    #[tokio::test]
    async fn parse_response_rejects_expired_assertion() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
      <saml:SubjectConfirmation>
        <saml:SubjectConfirmationData NotOnOrAfter="2020-01-01T00:00:00Z"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"#;
        let provider = DefaultSamlProvider::new().unwrap();
        let result = provider.parse_response(xml).await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "过期 Assertion 应返回 InvalidToken，实际: {:?}",
            result
        );
    }

    /// C-2: 未过期的 SAML Assertion（NotOnOrAfter > now）正常解析（不报 InvalidToken 错误）。
    ///
    /// 注意：C-1 修复后，DefaultSamlProvider 会剥离未验证的 Assertion（fail-closed），
    /// 但 parse_response 本身不应返回错误——NotOnOrAfter 校验通过。
    #[tokio::test]
    async fn parse_response_accepts_valid_assertion() {
        let future = Utc::now().timestamp() + 3600;
        let future_str = chrono::DateTime::from_timestamp(future, 0)
            .unwrap()
            .to_rfc3339();
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
      <saml:SubjectConfirmation>
        <saml:SubjectConfirmationData NotOnOrAfter="{}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"#,
            future_str
        );
        let provider = DefaultSamlProvider::new().unwrap();
        let response = provider.parse_response(&xml).await.unwrap();
        assert_eq!(
            response.status_code,
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        );
    }

    /// validate_assertion 返回 NotImplemented（spec R-002: 签名验证 defer）。
    #[tokio::test]
    async fn validate_assertion_returns_not_implemented() {
        let provider = DefaultSamlProvider::new().unwrap();
        let assertion = SamlAssertion {
            id: "assertion-003".to_string(),
            issuer: "https://idp.example.com".to_string(),
            subject: "user@example.com".to_string(),
            audience: "https://sp.example.com".to_string(),
            not_on_or_after: "2026-07-10T12:00:00Z".to_string(),
            attributes: vec![],
        };
        let result = provider.validate_assertion(&assertion).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::NotImplemented(_)) => {},
            other => panic!("期望 NotImplemented 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // C-3 断言重放防护测试
    // ========================================================================

    /// C-3: 同一 Assertion ID 首次消费通过，二次拒绝。
    #[tokio::test]
    async fn check_assertion_replay_rejects_replay() {
        let dao = crate::dao::tests::MockDao::new();
        let future = Utc::now().timestamp() + 3600;
        let future_str = chrono::DateTime::from_timestamp(future, 0)
            .unwrap()
            .to_rfc3339();

        let first = check_assertion_replay("assertion-replay-001", &future_str, &dao)
            .await
            .expect("首次 check 不应报错");
        assert!(first, "首次消费应通过");

        let second = check_assertion_replay("assertion-replay-001", &future_str, &dao)
            .await
            .expect("二次 check 不应报错");
        assert!(
            !second,
            "同一 Assertion ID 二次消费应被拒绝（C-3 重放防护）"
        );
    }

    /// C-3: 不同 Assertion ID 互不影响（隔离性）。
    #[tokio::test]
    async fn check_assertion_replay_isolates_by_id() {
        let dao = crate::dao::tests::MockDao::new();
        let future = Utc::now().timestamp() + 3600;
        let future_str = chrono::DateTime::from_timestamp(future, 0)
            .unwrap()
            .to_rfc3339();

        let a = check_assertion_replay("assertion-A", &future_str, &dao)
            .await
            .unwrap();
        assert!(a, "assertion-A 首次应通过");

        let b = check_assertion_replay("assertion-B", &future_str, &dao)
            .await
            .unwrap();
        assert!(b, "assertion-B 首次应通过（不同 ID 隔离）");
    }

    /// C-3: 空 Assertion ID 放行（无法做重放检查）。
    #[tokio::test]
    async fn check_assertion_replay_empty_id_passes() {
        let dao = crate::dao::tests::MockDao::new();
        let result = check_assertion_replay("", "", &dao)
            .await
            .expect("空 ID 不应报错");
        assert!(result, "空 Assertion ID 应放行（无法做重放检查）");
    }

    // ========================================================================
    // 辅助函数测试
    // ========================================================================

    /// extract_local_name 正确去除命名空间前缀。
    #[test]
    fn extract_local_name_strips_namespace() {
        assert_eq!(extract_local_name(b"samlp:Response"), "Response");
        assert_eq!(extract_local_name(b"saml:Issuer"), "Issuer");
        assert_eq!(extract_local_name(b"Assertion"), "Assertion");
    }

    // ========================================================================
    // H-2: SAML 命名空间强制测试
    // ========================================================================

    /// check_saml_namespace 接受合法前缀（saml/samlp/ds/无前缀）。
    #[test]
    fn check_saml_namespace_accepts_valid_prefixes() {
        assert!(check_saml_namespace(b"samlp:Response"));
        assert!(check_saml_namespace(b"saml:Assertion"));
        assert!(check_saml_namespace(b"saml:Issuer"));
        assert!(check_saml_namespace(b"ds:Signature"));
        assert!(check_saml_namespace(b"Response")); // 无前缀
        assert!(check_saml_namespace(b"Assertion")); // 无前缀
    }

    /// check_saml_namespace 拒绝非标准前缀（evil/foo/xs 等）。
    #[test]
    fn check_saml_namespace_rejects_invalid_prefixes() {
        assert!(!check_saml_namespace(b"evil:Assertion"));
        assert!(!check_saml_namespace(b"foo:Response"));
        assert!(!check_saml_namespace(b"xs:Issuer"));
        assert!(!check_saml_namespace(b"attack:Attribute"));
    }

    /// H-2: 非标准命名空间的 Assertion 被跳过（不解析为 Assertion）。
    #[tokio::test]
    async fn parse_saml_response_skips_invalid_namespace_assertion() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <evil:Assertion xmlns:evil="http://evil.example.com">
    <Issuer>https://idp.example.com</Issuer>
    <Subject>user@example.com</Subject>
    <Audience>https://sp.example.com</Audience>
    <SubjectConfirmationData NotOnOrAfter="2099-12-31T23:59:59Z"/>
  </evil:Assertion>
</Response>"#;
        let result = parse_saml_response_xml(xml).expect("解析不应报错");
        // evil:Assertion 应被跳过，response.assertion 应为 None
        assert!(
            result.assertion.is_none(),
            "非标准命名空间的 Assertion 应被跳过"
        );
    }

    // ========================================================================
    // H-3: SAML 属性污染告警测试
    // ========================================================================

    /// H-3: 重复属性名的 Assertion 仍被解析（两个值都保留），但应触发告警。
    #[tokio::test]
    async fn parse_saml_response_with_duplicate_attributes_preserves_both() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Assertion ID="attr-dup-001">
    <Issuer>https://idp.example.com</Issuer>
    <Subject>user@example.com</Subject>
    <Audience>https://sp.example.com</Audience>
    <SubjectConfirmationData NotOnOrAfter="2099-12-31T23:59:59Z"/>
    <AttributeStatement>
      <Attribute Name="role">
        <AttributeValue>user</AttributeValue>
      </Attribute>
      <Attribute Name="role">
        <AttributeValue>admin</AttributeValue>
      </Attribute>
    </AttributeStatement>
  </Assertion>
</Response>"#;
        let result = parse_saml_response_xml(xml).expect("解析不应报错");
        // Assertion 会被 fail-closed 剥离（DefaultSamlProvider），但 parse_saml_response_xml
        // 本身不做剥离——它返回原始解析结果。两个 role 属性都应保留。
        let assertion = result
            .assertion
            .expect("parse_saml_response_xml 应返回 Assertion（剥离由 parse_response 负责）");
        let roles: Vec<&str> = assertion
            .attributes
            .iter()
            .filter(|(name, _)| name == "role")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(
            roles.len(),
            2,
            "重复属性名应保留两个值（供消费方决策），实际: {:?}",
            roles
        );
        assert!(roles.contains(&"user"));
        assert!(roles.contains(&"admin"));
    }
}
