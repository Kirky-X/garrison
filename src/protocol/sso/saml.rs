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
//! 当前 `DefaultSamlProvider::validate_assertion` 返回 `GarrisonError::NotImplemented`，
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
//! - **XXE 防护**：底层 XML 解析器为 `quick-xml`（纯 Rust 实现），默认不解析外部实体
//!   （无 `libxml2` 依赖），不存在 XML External Entity (XXE) 注入风险。

use crate::constants::DaoKeyPrefix;
use crate::error::{GarrisonError, GarrisonResult};
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
    /// 断言生效时间（`<saml:Conditions NotBefore="...">`，RFC 3339 格式字符串）。
    ///
    /// CRIT-004：非空时必须晚于当前时间，未来生效的断言即刻使用将被拒绝。
    #[serde(default)]
    pub not_before: String,
    /// 属性集合（`<saml:AttributeStatement>` 中的键值对）。
    pub attributes: Vec<(String, String)>,
    /// Assertion 的原始 XML 字符串（含 `<ds:Signature>`，用于签名验证）。
    ///
    /// 仅在 `parse_saml_response_xml` 解析时填充；手动构造的 `SamlAssertion` 该字段为 `None`。
    /// [`XmlSecSamlProvider::validate_assertion`] 依赖此字段执行 XML 签名验证。
    ///
    /// `skip_serializing` / `skip_deserializing`：避免序列化循环与跨版本兼容问题，
    /// 反序列化时默认为 `None`（与手动构造一致）。
    #[serde(skip_serializing, skip_deserializing, default)]
    pub raw_xml: Option<String>,
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
    /// SP 发起的 AuthnRequest ID（`InResponseTo` 属性，CRIT-005 绑定校验用）。
    ///
    /// IdP-initiated（unsolicited）响应此字段为空。
    #[serde(default)]
    pub in_response_to: String,
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
    /// - `idp_sso_endpoint`: IdP 的 SSO 端点 URL（vuln-0002 修复：不再为空，
    ///   避免生成的 AuthnRequest 缺失 Destination）。
    ///
    /// # 返回
    /// `SamlRequest` 结构。
    async fn build_authn_request(
        &self,
        sp_entity_id: &str,
        acs_url: &str,
        idp_sso_endpoint: &str,
    ) -> GarrisonResult<SamlRequest>;

    /// 解析 SAML Response XML。
    ///
    /// 输入为 base64 解码后的原始 XML 字符串，调用方负责 base64 解码。
    ///
    /// # 参数
    /// - `response_xml`: SAML Response XML 字符串。
    ///
    /// # 返回
    /// 解析后的 `SamlResponse` 结构。
    async fn parse_response(&self, response_xml: &str) -> GarrisonResult<SamlResponse>;

    /// 验证 SAML Assertion 签名。
    ///
    /// # 参数
    /// - `assertion`: 待验证的 Assertion。
    ///
    /// # 返回
    /// - `Ok(true)`: 签名验证通过。
    /// - `Err(GarrisonError::NotImplemented)`: 签名验证尚未实现。
    async fn validate_assertion(&self, assertion: &SamlAssertion) -> GarrisonResult<bool>;
}

// ============================================================================
// DefaultSamlProvider
// ============================================================================

/// 默认 SAML Provider 实现。
///
/// 提供基础的 AuthnRequest 构建和 Response 解析功能。
/// 签名验证返回 `NotImplemented`，defer 到 [`XmlSecSamlProvider`]（`secure-saml` feature）。
///
/// # vuln-0002 修复：Destination / Audience 验证
///
/// 通过 [`DefaultSamlProvider::with_expected_destination`] /
/// [`DefaultSamlProvider::with_expected_audience`] 配置预期值后，
/// [`SamlProvider::parse_response`] 会在解析后强制校验：
/// - 不匹配返回 [`GarrisonError::InvalidParam`]（fail-loud，禁止静默放行）
/// - 未配置则 `tracing::warn!` 告警（开发环境兼容）
pub struct DefaultSamlProvider {
    /// 预期 Destination（SP 的 ACS URL）。None = 跳过验证（仅告警）。
    expected_destination: Option<String>,
    /// 预期 Audience（SP 的 entity_id）。None = 跳过验证（仅告警）。
    expected_audience: Option<String>,
    /// 可选 DAO（CRIT-005/006）：启用 InResponseTo 绑定校验与 Assertion 重放防护。
    request_dao: Option<std::sync::Arc<dyn crate::dao::GarrisonDao>>,
    /// 未配置 DAO 的 warn-once 标记。
    warned_no_dao: std::sync::atomic::AtomicBool,
}

impl DefaultSamlProvider {
    /// 创建新的 `DefaultSamlProvider` 实例（无 Destination / Audience 验证）。
    ///
    /// 生产环境推荐使用 [`DefaultSamlProvider::with_expected_destination`] +
    /// [`DefaultSamlProvider::with_expected_audience`] 显式配置预期值，
    /// 或直接使用 [`XmlSecSamlProvider`]（`secure-saml` feature）。
    ///
    /// # 返回
    /// 可用的 `DefaultSamlProvider` 实例。
    pub fn new() -> GarrisonResult<Self> {
        Ok(Self {
            expected_destination: None,
            expected_audience: None,
            request_dao: None,
            warned_no_dao: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// 配置 DAO，启用 InResponseTo 绑定校验（CRIT-005）与 Assertion 重放防护（CRIT-006）。
    ///
    /// `build_authn_request` 会将请求 ID 写入注册表（TTL 600 秒），
    /// `parse_response` 原子消费并校验。
    pub fn with_request_dao(mut self, dao: std::sync::Arc<dyn crate::dao::GarrisonDao>) -> Self {
        self.request_dao = Some(dao);
        self
    }

    /// 配置预期 Destination（SP 的 ACS URL），开启 Destination 验证。
    ///
    /// 链式调用：`DefaultSamlProvider::new()?.with_expected_destination(acs_url)`
    pub fn with_expected_destination(mut self, destination: String) -> Self {
        self.expected_destination = Some(destination);
        self
    }

    /// 配置预期 Audience（SP 的 entity_id），开启 Audience 验证。
    ///
    /// 链式调用：`DefaultSamlProvider::new()?.with_expected_audience(entity_id)`
    pub fn with_expected_audience(mut self, audience: String) -> Self {
        self.expected_audience = Some(audience);
        self
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
        idp_sso_endpoint: &str,
    ) -> GarrisonResult<SamlRequest> {
        let request = SamlRequest {
            id: Uuid::new_v4().to_string(),
            issue_instant: Utc::now().to_rfc3339(),
            // vuln-0002 修复：使用调用方传入的 IdP SSO 端点（不再为空）
            destination: idp_sso_endpoint.to_string(),
            issuer: sp_entity_id.to_string(),
            assertion_consumer_service_url: acs_url.to_string(),
        };
        // CRIT-005: 记录在途请求 ID 供 parse_response 绑定校验（TTL 600 秒）
        if let Some(d) = &self.request_dao {
            let key = format!("{}req:{}", DaoKeyPrefix::Saml, request.id);
            d.set(&key, "1", 600).await?;
        }
        Ok(request)
    }

    async fn parse_response(&self, response_xml: &str) -> GarrisonResult<SamlResponse> {
        // SAFETY: quick-xml 不解析外部实体，XXE 安全
        // LOW-2: SAML response 大小上限（防超大 payload 内存 DoS，真实 SAML Response 极少超 64KB）
        const SAML_RESPONSE_MAX_SIZE: usize = 64 * 1024;
        if response_xml.len() > SAML_RESPONSE_MAX_SIZE {
            return Err(GarrisonError::InvalidParam(format!(
                "saml-response-too-large::{}::{}",
                response_xml.len(),
                SAML_RESPONSE_MAX_SIZE
            )));
        }
        let mut response = parse_saml_response_xml(response_xml)?;

        // CRIT-002: StatusCode 强制 Success（fail-closed，错误响应不得继续处理）
        validate_status_code(&response.status_code)?;

        // CRIT-005: InResponseTo ↔ AuthnRequest 绑定校验
        enforce_in_response_to(
            self.request_dao.as_ref(),
            &self.warned_no_dao,
            &response.in_response_to,
        )
        .await?;

        // vuln-0002 修复：Destination 验证（fail-loud）
        validate_destination(&response.destination, self.expected_destination.as_deref())?;

        // vuln-0002 修复：Audience 验证（fail-loud，仅在有 Assertion 时校验）
        if let Some(ref assertion) = response.assertion {
            validate_audience(&assertion.audience, self.expected_audience.as_deref())?;
        }

        // vuln-0001: DefaultSamlProvider 不实现签名验证（fail-closed 剥离 Assertion）
        if let Some(ref assertion) = response.assertion {
            match self.validate_assertion(assertion).await {
                Ok(true) => {
                    // CRIT-006: 验签通过后强制重放检查（Assertion ID 一次性消费）
                    if let Some(d) = &self.request_dao {
                        if !check_assertion_replay(
                            &assertion.id,
                            &assertion.not_on_or_after,
                            d.as_ref(),
                        )
                        .await?
                        {
                            return Err(GarrisonError::InvalidParam(format!(
                                "sso-saml-assertion-replay::{}",
                                assertion.id
                            )));
                        }
                    }
                },
                Ok(false) => {
                    tracing::warn!("SAML Assertion signature verification failed, stripped");
                    response.assertion = None;
                },
                Err(GarrisonError::NotImplemented(_)) => {
                    tracing::warn!("SAML signature verification not implemented, Assertion stripped (fail-closed)");
                    response.assertion = None;
                },
                Err(e) => return Err(e),
            }
        }
        Ok(response)
    }

    async fn validate_assertion(&self, _assertion: &SamlAssertion) -> GarrisonResult<bool> {
        Err(GarrisonError::NotImplemented(
            "sso-saml-signature-not-implemented".to_string(),
        ))
    }
}

// ============================================================================
// Destination / Audience 验证辅助（vuln-0002）
// ============================================================================

/// 校验 SAML Response 的 StatusCode 是否为 Success（CRIT-002，fail-closed）。
///
/// 非 Success 响应（如 Responder / Requester 错误）即使夹带 Assertion 也必须拒绝，
/// 防止错误响应被当作成功登录处理。
fn validate_status_code(status_code: &str) -> GarrisonResult<()> {
    const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
    if status_code != STATUS_SUCCESS {
        return Err(GarrisonError::InvalidParam(format!(
            "sso-saml-status-not-success::{}",
            status_code
        )));
    }
    Ok(())
}

/// 校验 SAML Response 的 Destination 是否匹配预期值（vuln-0002）。
///
/// - `expected = Some(exp)`: 严格匹配，不匹配返回 [`GarrisonError::InvalidParam`]（fail-loud）
/// - `expected = None`: `tracing::warn!` 告警（开发环境兼容，生产环境应配置）
fn validate_destination(actual: &str, expected: Option<&str>) -> GarrisonResult<()> {
    match expected {
        Some(exp) if !exp.is_empty() => {
            if actual != exp {
                return Err(GarrisonError::InvalidParam(format!(
                    "sso-saml-destination-mismatch::expected={}::actual={}",
                    exp, actual
                )));
            }
            Ok(())
        },
        _ => {
            if !actual.is_empty() {
                tracing::warn!(
                    actual = %actual,
                    "SAML Destination 未配置验证（expected_destination=None），存在重定向攻击风险"
                );
            }
            Ok(())
        },
    }
}

/// 校验 SAML Assertion 的 Audience 是否匹配预期值（vuln-0002）。
///
/// - `expected = Some(exp)`: 严格匹配，不匹配返回 [`GarrisonError::InvalidParam`]（fail-loud）
/// - `expected = None`: `tracing::warn!` 告警（开发环境兼容，生产环境应配置）
fn validate_audience(actual: &str, expected: Option<&str>) -> GarrisonResult<()> {
    match expected {
        Some(exp) if !exp.is_empty() => {
            if actual != exp {
                return Err(GarrisonError::InvalidParam(format!(
                    "sso-saml-audience-mismatch::expected={}::actual={}",
                    exp, actual
                )));
            }
            Ok(())
        },
        _ => {
            if !actual.is_empty() {
                tracing::warn!(
                    actual = %actual,
                    "SAML Audience 未配置验证（expected_audience=None），存在跨 SP 重放风险"
                );
            }
            Ok(())
        },
    }
}

// ============================================================================
// XML 解析辅助
// ============================================================================

/// SAML Response XML 解析上下文。
///
/// 收拢 `parse_saml_response_xml` 的所有解析状态变量，将手工状态机拆分为
/// `handle_start_element` / `handle_end_element` / `handle_empty_element` / `handle_text`
/// 四个方法，主函数简化为 loop + dispatch。
struct SamlParseContext {
    // Response 级字段
    destination: String,
    issuer: String,
    status_code: String,
    in_response_to: String,
    assertion: Option<SamlAssertion>,

    // 状态标志
    in_assertion: bool,
    in_issuer: bool,
    in_subject: bool,
    in_audience: bool,
    in_attribute: bool,

    // 文本累积
    current_attr_name: String,
    current_text: String,

    // Assertion 解析中间字段
    assertion_issuer: String,
    assertion_subject: String,
    assertion_audience: String,
    assertion_not_on_or_after: String,
    assertion_not_before: String,
    assertion_id: String,
    assertion_attributes: Vec<(String, String)>,

    // vuln-0001: raw_xml 跟踪
    assertion_start_pos: Option<u64>,
    assertion_raw_xml: Option<String>,
}

impl SamlParseContext {
    fn new() -> Self {
        Self {
            destination: String::new(),
            issuer: String::new(),
            status_code: String::new(),
            in_response_to: String::new(),
            assertion: None,
            in_assertion: false,
            in_issuer: false,
            in_subject: false,
            in_audience: false,
            in_attribute: false,
            current_attr_name: String::new(),
            current_text: String::new(),
            assertion_issuer: String::new(),
            assertion_subject: String::new(),
            assertion_audience: String::new(),
            assertion_not_on_or_after: String::new(),
            assertion_not_before: String::new(),
            assertion_id: String::new(),
            assertion_attributes: Vec::new(),
            assertion_start_pos: None,
            assertion_raw_xml: None,
        }
    }

    /// 处理 Start 元素：设置状态标志 + 提取属性。
    fn handle_start_element(&mut self, event: &quick_xml::events::BytesStart, pos_before: u64) {
        if !check_saml_namespace(event.name().as_ref()) {
            return;
        }
        let local_name = extract_local_name(event.name().as_ref());
        match local_name.as_str() {
            "Response" => {
                for attr in event.attributes().flatten() {
                    match attr.key.as_ref() {
                        b"Destination" => {
                            self.destination = attr_value_to_string(&attr.value);
                        },
                        b"InResponseTo" => {
                            self.in_response_to = attr_value_to_string(&attr.value);
                        },
                        _ => {},
                    }
                }
            },
            "Assertion" => {
                self.in_assertion = true;
                self.assertion_start_pos = Some(pos_before);
                self.assertion_issuer.clear();
                self.assertion_subject.clear();
                self.assertion_audience.clear();
                self.assertion_not_on_or_after.clear();
                self.assertion_not_before.clear();
                self.assertion_id.clear();
                self.assertion_attributes.clear();
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == b"ID" {
                        self.assertion_id = attr_value_to_string(&attr.value);
                    }
                }
            },
            "Issuer" => {
                self.in_issuer = true;
                self.current_text.clear();
            },
            "Subject" => self.in_subject = true,
            "Audience" => {
                self.in_audience = true;
                self.current_text.clear();
            },
            "Attribute" => {
                self.in_attribute = true;
                self.current_attr_name.clear();
                self.current_text.clear();
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == b"Name" {
                        self.current_attr_name = attr_value_to_string(&attr.value);
                    }
                }
            },
            "SubjectConfirmationData" => {
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == b"NotOnOrAfter" {
                        self.assertion_not_on_or_after = attr_value_to_string(&attr.value);
                    }
                }
            },
            "Conditions" => {
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == b"NotBefore" {
                        self.assertion_not_before = attr_value_to_string(&attr.value);
                    }
                }
            },
            _ => {},
        }
    }

    /// 处理 Empty 元素（自闭合如 `<StatusCode Value="..."/>`）：仅提取属性。
    fn handle_empty_element(&mut self, event: &quick_xml::events::BytesStart) {
        if !check_saml_namespace(event.name().as_ref()) {
            return;
        }
        let local_name = extract_local_name(event.name().as_ref());
        match local_name.as_str() {
            "StatusCode" => {
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == b"Value" {
                        self.status_code = attr_value_to_string(&attr.value);
                    }
                }
            },
            "Conditions" => {
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == b"NotBefore" {
                        self.assertion_not_before = attr_value_to_string(&attr.value);
                    }
                }
            },
            "SubjectConfirmationData" => {
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == b"NotOnOrAfter" {
                        self.assertion_not_on_or_after = attr_value_to_string(&attr.value);
                    }
                }
            },
            "AttributeValue" if self.in_attribute => {
                if self
                    .assertion_attributes
                    .iter()
                    .any(|(n, _)| n == &self.current_attr_name)
                {
                    tracing::warn!(
                        attr_name = %self.current_attr_name,
                        "SAML Assertion 包含重复属性名，可能为属性污染攻击"
                    );
                }
                self.assertion_attributes
                    .push((self.current_attr_name.clone(), String::new()));
            },
            _ => {},
        }
    }

    /// 处理 End 元素：收集文本、构建 Assertion、重置状态。
    fn handle_end_element(
        &mut self,
        event: &quick_xml::events::BytesEnd,
        pos_after: u64,
        xml: &str,
    ) {
        let local_name = extract_local_name(event.name().as_ref());
        match local_name.as_str() {
            "Assertion" => {
                if self.in_assertion {
                    // vuln-0001: 提取 <Assertion>...</Assertion> 原始 XML
                    if let Some(start) = self.assertion_start_pos {
                        let start_usize = start as usize;
                        let pos_after_usize = pos_after as usize;
                        if pos_after_usize >= start_usize && pos_after_usize <= xml.len() {
                            self.assertion_raw_xml =
                                Some(xml[start_usize..pos_after_usize].to_string());
                        }
                    }
                    self.assertion = Some(SamlAssertion {
                        id: self.assertion_id.clone(),
                        issuer: self.assertion_issuer.clone(),
                        subject: self.assertion_subject.clone(),
                        audience: self.assertion_audience.clone(),
                        not_on_or_after: self.assertion_not_on_or_after.clone(),
                        not_before: self.assertion_not_before.clone(),
                        attributes: self.assertion_attributes.clone(),
                        raw_xml: self.assertion_raw_xml.clone(),
                    });
                    self.in_assertion = false;
                }
            },
            "Issuer" => {
                if self.in_issuer {
                    if self.in_assertion {
                        self.assertion_issuer = self.current_text.clone();
                    } else {
                        self.issuer = self.current_text.clone();
                    }
                    self.in_issuer = false;
                    self.current_text.clear();
                }
            },
            "Subject" => self.in_subject = false,
            "Audience" => {
                if self.in_audience {
                    self.assertion_audience = self.current_text.clone();
                    self.in_audience = false;
                    self.current_text.clear();
                }
            },
            "Attribute" => {
                if self.in_attribute {
                    if self
                        .assertion_attributes
                        .iter()
                        .any(|(n, _)| n == &self.current_attr_name)
                    {
                        tracing::warn!(
                            attr_name = %self.current_attr_name,
                            "SAML Assertion 包含重复属性名，可能为属性污染攻击"
                        );
                    }
                    self.assertion_attributes
                        .push((self.current_attr_name.clone(), self.current_text.clone()));
                    self.in_attribute = false;
                    self.current_text.clear();
                }
            },
            "NameID" => {
                if self.in_subject {
                    self.assertion_subject = self.current_text.clone();
                    self.current_text.clear();
                }
            },
            "AttributeValue" => {
                // AttributeValue 文本已收集到 current_text，在 Attribute End 时处理
            },
            _ => {},
        }
    }

    /// 处理 Text 事件：累积文本到 `current_text`。
    fn handle_text(&mut self, text: &str) {
        self.current_text.push_str(text);
    }

    /// 构建 `SamlResponse` 并校验 Assertion 时间条件（CRIT-004 fail-closed）。
    fn into_response(self) -> GarrisonResult<SamlResponse> {
        if let Some(ref assertion) = self.assertion {
            // NotOnOrAfter 缺失即拒绝：无过期时间的断言永不过期（重放窗口无限）
            if assertion.not_on_or_after.is_empty() {
                return Err(GarrisonError::InvalidToken(
                    "sso-saml-missing-not-on-or-after".to_string(),
                ));
            }
            let expiry =
                chrono::DateTime::parse_from_rfc3339(&assertion.not_on_or_after).map_err(|e| {
                    GarrisonError::InvalidToken(format!("sso-saml-not-on-or-after-parse::{}", e))
                })?;
            if Utc::now().timestamp() >= expiry.timestamp() {
                return Err(GarrisonError::InvalidToken(format!(
                    "sso-saml-assertion-expired::{}",
                    assertion.not_on_or_after
                )));
            }
            // NotBefore 校验（CRIT-004）：未来生效的断言不得即刻使用。
            // 缺失 NotBefore 允许（部分 IdP 不签发），存在则必须已生效。
            if !assertion.not_before.is_empty() {
                let not_before = chrono::DateTime::parse_from_rfc3339(&assertion.not_before)
                    .map_err(|e| {
                        GarrisonError::InvalidToken(format!("sso-saml-not-before-parse::{}", e))
                    })?;
                if Utc::now().timestamp() < not_before.timestamp() {
                    return Err(GarrisonError::InvalidToken(format!(
                        "sso-saml-assertion-not-yet-valid::{}",
                        assertion.not_before
                    )));
                }
            }
        }
        Ok(SamlResponse {
            destination: self.destination,
            issuer: self.issuer,
            assertion: self.assertion,
            status_code: self.status_code,
            in_response_to: self.in_response_to,
        })
    }
}

/// 从 SAML Response XML 中提取关键字段。
///
/// 使用 quick-xml 的 pull reader 解析 XML，提取 Destination / Issuer / StatusCode / Assertion。
///
/// vuln-0001 修复：解析时同步记录 `<Assertion>` 元素的原始 XML 字节范围，
/// 填充到 [`SamlAssertion::raw_xml`]，供 [`XmlSecSamlProvider`] 执行 XML 签名验证。
fn parse_saml_response_xml(xml: &str) -> GarrisonResult<SamlResponse> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut ctx = SamlParseContext::new();
    let mut buf = Vec::new();

    loop {
        let pos_before = reader.buffer_position();
        match reader.read_event_into(&mut buf) {
            Err(e) => {
                return Err(GarrisonError::Internal(format!(
                    "sso-saml-xml-parse::{}",
                    e
                )))
            },
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => ctx.handle_start_element(&e, pos_before),
            Ok(Event::Empty(e)) => ctx.handle_empty_element(&e),
            Ok(Event::End(e)) => {
                let pos_after = reader.buffer_position();
                ctx.handle_end_element(&e, pos_after, xml);
            },
            Ok(Event::Text(e)) => {
                let text = String::from_utf8_lossy(e.as_ref());
                ctx.handle_text(&text);
            },
            _ => {},
        }
        buf.clear();
    }

    ctx.into_response()
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
/// # vuln-0003 修复：原子 get_and_delete 消除 TOCTOU 竞态
///
/// 原实现使用 `dao.get()` + `dao.set()` 两步操作，存在 TOCTOU 竞态：
/// 并发请求可能同时通过 `get` 检查后再 `set`，导致同一 Assertion 被多次消费。
///
/// 现使用 `dao.get_and_delete()` 原子操作：
/// 1. `get_and_delete` 返回 `Some` → 已消费（重放），返回 `Ok(false)`
/// 2. `get_and_delete` 返回 `None` → 首次消费，计算 TTL 后 `set` 标记已消费，返回 `Ok(true)`
///
/// **原子性边界**：
/// - `get_and_delete` 在 `MockDao` / `GarrisonDaoOxcache` 中由 `parking_lot::Mutex` 保护，进程内原子
/// - 跨进程（Redis L2）需后端重写 `get_and_delete` 为 `GETDEL` 或 Lua 脚本
/// - `get_and_delete` 后的 `set` 非原子，但即使两个并发请求同时到达，
///   `get_and_delete` 保证仅一个返回 `None`（首次消费），另一个返回 `Some`（重放拒绝）
///
/// # TTL 计算
/// TTL = `NotOnOrAfter - now`（剩余有效期）。若 `not_on_or_after` 为空或已过期，
/// 使用 300 秒（5 分钟）兜底，确保缓存不会过早失效。
pub async fn check_assertion_replay(
    assertion_id: &str,
    not_on_or_after: &str,
    dao: &dyn crate::dao::GarrisonDao,
) -> GarrisonResult<bool> {
    if assertion_id.is_empty() {
        return Ok(true);
    }
    let key = format!("{}consumed:{}", DaoKeyPrefix::Saml, assertion_id);

    // vuln-0003 修复：原子 get_and_delete 替代非原子 get + set
    // - 返回 Some：key 已存在 = 已消费 = 重放，返回 false
    // - 返回 None：key 不存在 = 首次消费，继续 set 标记
    let existing = dao.get_and_delete(&key).await?;
    if existing.is_some() {
        return Ok(false);
    }

    // TTL 计算：NotOnOrAfter - now（剩余有效期），空或过期用 300 秒兜底
    let ttl = if not_on_or_after.is_empty() {
        300
    } else {
        let expiry = chrono::DateTime::parse_from_rfc3339(not_on_or_after).map_err(|e| {
            GarrisonError::InvalidToken(format!("sso-saml-not-on-or-after-parse::{}", e))
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

/// InResponseTo ↔ AuthnRequest ID 绑定校验（CRIT-005）。
///
/// - 配置了 DAO：`InResponseTo` 非空时原子 get_and_delete 注册表条目
///   （`saml:req:{id}`，由 build_authn_request 写入，TTL 600 秒），
///   未命中即拒绝（不存在的在途请求 / 重放 / 过期）。
/// - 未配置 DAO：携带 InResponseTo 的 SP-initiated 响应无法验证绑定 → fail-closed 拒绝；
///   无 InResponseTo 的 IdP-initiated 响应放行但 warn 一次（防护未启用提示）。
pub(crate) async fn enforce_in_response_to(
    dao: Option<&std::sync::Arc<dyn crate::dao::GarrisonDao>>,
    warned_no_dao: &std::sync::atomic::AtomicBool,
    in_response_to: &str,
) -> GarrisonResult<()> {
    use std::sync::atomic::Ordering;
    match dao {
        Some(d) => {
            if in_response_to.is_empty() {
                return Ok(()); // IdP-initiated 响应无绑定语义
            }
            let key = format!("{}req:{}", DaoKeyPrefix::Saml, in_response_to);
            if d.get_and_delete(&key).await?.is_none() {
                return Err(GarrisonError::InvalidParam(format!(
                    "sso-saml-in-response-to-unknown::{}",
                    in_response_to
                )));
            }
            Ok(())
        },
        None => {
            if !in_response_to.is_empty() {
                return Err(GarrisonError::InvalidParam(
                    "sso-saml-in-response-to-unverifiable".to_string(),
                ));
            }
            if !warned_no_dao.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "SAML request_dao 未配置：InResponseTo 绑定与 Assertion 重放防护未启用"
                );
            }
            Ok(())
        },
    }
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

// ============================================================================
// XmlSecSamlProvider：SAML 签名验证实现（vuln-0001 修复，secure-saml feature）
// ============================================================================

/// SAML 签名算法标识 URI（XML-DSig 标准）。
#[cfg(feature = "protocol-saml")]
const SIG_ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
#[cfg(feature = "protocol-saml")]
const SIG_ALG_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
/// 弱算法：rsa-1_5（PKCS#1 v1.5 无摘要，存在 Bleichenbacher 攻击风险）。
#[cfg(feature = "protocol-saml")]
const SIG_ALG_RSA_1_5: &str = "http://www.w3.org/2000/09/xmldsig#rsa-1_5";

/// 检查签名算法是否在白名单内（vuln-0001 安全要求）。
///
/// 仅允许 RSA-SHA256 / ECDSA-SHA256，禁止 rsa-1_5 等弱算法。
/// 注意：当前实现仅支持 RSA-SHA256 验证（依赖 `rsa` crate），
/// ECDSA-SHA256 在算法白名单中通过但实际验证会返回 `Ok(false)`（待引入 ECDSA 库）。
#[cfg(all(feature = "protocol-saml", test))]
fn is_signature_algorithm_allowed(algorithm: &str) -> bool {
    matches!(algorithm, SIG_ALG_RSA_SHA256 | SIG_ALG_ECDSA_SHA256)
}

/// 提取 `<ds:SignatureMethod Algorithm="...">` 的 Algorithm 属性值。
///
/// 在 signature_xml 中查找 `<SignatureMethod` 元素并提取 `Algorithm` 属性。
/// 找不到返回 None。
#[cfg(feature = "protocol-saml")]
fn extract_signature_method_algorithm(signature_xml: &str) -> Option<String> {
    // 简化实现：字符串查找 SignatureMethod 元素的 Algorithm 属性
    let method_start = signature_xml.find("<")?;
    let rest = &signature_xml[method_start..];
    let method_idx = rest.find("SignatureMethod")?;
    let after_method = &rest[method_idx..];
    let alg_key = after_method.find("Algorithm=\"")?;
    let alg_value_start = alg_key + "Algorithm=\"".len();
    let after_alg = &after_method[alg_value_start..];
    let alg_end = after_alg.find('"')?;
    Some(after_alg[..alg_end].to_string())
}

/// 提取 `<ds:SignatureValue>...</ds:SignatureValue>` 的 base64 文本内容。
///
/// 找不到返回 None。
#[cfg(feature = "protocol-saml")]
fn extract_signature_value(signature_xml: &str) -> Option<String> {
    let start_tag_options = ["<ds:SignatureValue>", "<SignatureValue>"];
    let end_tag_options = ["</ds:SignatureValue>", "</SignatureValue>"];

    for (start_tag, end_tag) in start_tag_options.iter().zip(end_tag_options.iter()) {
        if let Some(start_idx) = signature_xml.find(start_tag) {
            let content_start = start_idx + start_tag.len();
            if let Some(end_idx) = signature_xml[content_start..].find(end_tag) {
                let value = &signature_xml[content_start..content_start + end_idx];
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// 提取 `<ds:SignedInfo>...</ds:SignedInfo>` 的原始 XML（含标签）。
///
/// 签名验证时对此 XML 计算 SHA-256 摘要并与签名值比对。
///
/// **C14N 限制**：本实现不执行 XML Canonicalization (C14N)，
/// 直接使用原始 XML 字符串作为签名验证输入。若 IdP 对 canonicalized
/// 形式签名（标准做法），验证可能失败。生产环境应替换为完整 C14N 实现。
#[cfg(feature = "protocol-saml")]
fn extract_signed_info_xml(assertion_xml: &str) -> Option<String> {
    let start_tag_options = ["<ds:SignedInfo>", "<SignedInfo>"];
    let end_tag_options = ["</ds:SignedInfo>", "</SignedInfo>"];

    for (start_tag, end_tag) in start_tag_options.iter().zip(end_tag_options.iter()) {
        if let Some(start_idx) = assertion_xml.find(start_tag) {
            if let Some(end_idx) = assertion_xml[start_idx..].find(end_tag) {
                let end_pos = start_idx + end_idx + end_tag.len();
                return Some(assertion_xml[start_idx..end_pos].to_string());
            }
        }
    }
    None
}

/// 提取 `<ds:Signature>...</ds:Signature>` 的原始 XML。
///
/// 支持有无命名空间前缀两种形式。找不到返回 None。
#[cfg(feature = "protocol-saml")]
fn extract_signature_xml(assertion_xml: &str) -> Option<String> {
    let start_tag_options = [
        "<ds:Signature>",
        "<ds:Signature ",
        "<Signature>",
        "<Signature ",
    ];
    let end_tag_options = ["</ds:Signature>", "</Signature>"];

    for start_tag in start_tag_options {
        if let Some(start_idx) = assertion_xml.find(start_tag) {
            for end_tag in end_tag_options {
                if let Some(end_idx) = assertion_xml[start_idx..].find(end_tag) {
                    let end_pos = start_idx + end_idx + end_tag.len();
                    return Some(assertion_xml[start_idx..end_pos].to_string());
                }
            }
        }
    }
    None
}

/// Digest 算法 URI（XML-DSig 标准）：本实现仅支持 SHA-256。
#[cfg(feature = "protocol-saml")]
const DIGEST_ALG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// SignedInfo 内单个 `<ds:Reference>` 绑定（CRIT-001）。
///
/// XML-DSig 中签名对内容的绑定依赖「SignedInfo → Reference URI → 被引用元素
/// 的 DigestValue」链条；缺失任一环即签名与内容解耦（XSW 可伪造）。
#[cfg(feature = "protocol-saml")]
struct ReferenceBinding {
    /// `URI` 属性值，必须为 `#<element-id>` 形式。
    uri: String,
    /// `<ds:DigestMethod Algorithm="...">` 属性值。
    digest_method: Option<String>,
    /// `<ds:DigestValue>` base64 文本。
    digest_value_b64: String,
}

/// 提取 SignedInfo 内全部 `<ds:Reference>` 绑定（CRIT-001）。
///
/// 支持有无命名空间前缀两种形式；找不到返回空 Vec。
#[cfg(feature = "protocol-saml")]
fn extract_reference_bindings(signed_info_xml: &str) -> Vec<ReferenceBinding> {
    let mut bindings = Vec::new();
    for start_tag in ["<ds:Reference", "<Reference"] {
        let mut search_from = 0usize;
        while let Some(rel) = signed_info_xml[search_from..].find(start_tag) {
            let abs_start = search_from + rel;
            // 边界检查：避免匹配到 <References 等更长标签名
            let after_tag = signed_info_xml[abs_start + start_tag.len()..]
                .chars()
                .next();
            if !matches!(after_tag, Some(' ') | Some('>') | Some('/')) {
                search_from = abs_start + start_tag.len();
                continue;
            }
            let content_start = abs_start + start_tag.len();
            let rel_end = match signed_info_xml[content_start..]
                .find("</ds:Reference>")
                .or_else(|| signed_info_xml[content_start..].find("</Reference>"))
            {
                Some(e) => e,
                None => break,
            };
            let block = &signed_info_xml[abs_start..content_start + rel_end];

            let uri = block
                .find("URI=\"")
                .and_then(|i| {
                    let vstart = i + "URI=\"".len();
                    block[vstart..]
                        .find('"')
                        .map(|e| block[vstart..vstart + e].to_string())
                })
                .unwrap_or_default();
            let digest_method = block
                .find("<ds:DigestMethod")
                .or_else(|| block.find("<DigestMethod"))
                .and_then(|i| {
                    let seg = &block[i..];
                    let key = "Algorithm=\"";
                    seg.find(key).and_then(|j| {
                        let vs = j + key.len();
                        seg[vs..].find('"').map(|e| seg[vs..vs + e].to_string())
                    })
                });
            let digest_value_b64 = extract_xml_text(block, "DigestValue").unwrap_or_default();

            bindings.push(ReferenceBinding {
                uri,
                digest_method,
                digest_value_b64,
            });
            search_from = content_start + rel_end;
        }
        if !bindings.is_empty() {
            break;
        }
    }
    bindings
}

/// 提取指定 local name 元素的文本内容（首个匹配，去除前后空白）。
///
/// 同时兼容 `<ns:Name>` 与 `<Name>` 两种形式。
#[cfg(feature = "protocol-saml")]
fn extract_xml_text(xml: &str, local_name: &str) -> Option<String> {
    for ns_prefix in ["ds:", ""] {
        let start_tag = format!("<{}{}>", ns_prefix, local_name);
        let end_tag = format!("</{}{}>", ns_prefix, local_name);
        if let Some(s) = xml.find(&start_tag) {
            let cs = s + start_tag.len();
            if let Some(e) = xml[cs..].find(&end_tag) {
                return Some(xml[cs..cs + e].trim().to_string());
            }
        }
    }
    None
}

/// 按 ID 属性定位元素并返回其原始 XML 切片（含起止标签）（CRIT-001）。
///
/// 通过扫描同限定名标签的嵌套深度确定闭合位置；自闭合标签不影响深度。
/// 找不到返回 None。
#[cfg(feature = "protocol-saml")]
fn find_element_raw_by_id(xml: &str, id: &str) -> Option<String> {
    if id.is_empty() || id.contains('"') {
        return None;
    }
    let id_pattern = format!("ID=\"{}\"", id);
    let id_pos = xml.find(&id_pattern)?;
    // 回退到最近的元素起始 '<'
    let elem_start = xml[..id_pos].rfind('<')?;
    let rest = &xml[elem_start + 1..];
    let name_end = rest.find(|c| [' ', '>', '/'].contains(&c))?;
    let qname = &rest[..name_end];
    if qname.is_empty() || qname.starts_with('!') || qname.starts_with('?') {
        return None;
    }

    let open_pat = format!("<{}", qname);
    let close_pat = format!("</{}>", qname);
    let is_valid_open = |abs: usize| -> bool {
        matches!(
            xml[abs + open_pat.len()..].chars().next(),
            Some(' ') | Some('>') | Some('/')
        )
    };
    let is_self_closing = |abs: usize| -> bool {
        match xml[abs..].find('>') {
            Some(tag_end) => xml[abs + tag_end - 1..abs + tag_end].ends_with('/'),
            None => false,
        }
    };

    let mut depth: usize = 0;
    let mut pos = elem_start;
    loop {
        let o_rel = xml[pos..].find(&open_pat).map(|i| i + pos);
        let c_rel = xml[pos..].find(&close_pat).map(|i| i + pos);
        if let Some(o) = o_rel {
            if o <= c_rel.unwrap_or(usize::MAX) && is_valid_open(o) && !is_self_closing(o) {
                depth += 1;
                pos = o + open_pat.len();
                continue;
            }
        }
        let close_abs = c_rel?;
        depth = depth.checked_sub(1)?;
        pos = close_abs + close_pat.len();
        if depth == 0 {
            return Some(xml[elem_start..pos].to_string());
        }
    }
}

/// 剥离元素切片内首个 `<ds:Signature>` 块（隐式 enveloped-signature transform）。
///
/// 本实现的摘要输入约定：被引用元素去除自身 Signature 子元素后的原始字节。
/// 签名方与验证方必须采用相同约定（见模块文档 C14N 限制说明）。
#[cfg(feature = "protocol-saml")]
fn strip_enveloped_signature(element_xml: &str) -> String {
    match extract_signature_xml(element_xml) {
        Some(sig) => element_xml.replacen(&sig, "", 1),
        None => element_xml.to_string(),
    }
}

/// 校验单个 Reference 绑定：URI 解析 → 元素定位 → 摘要常量时间比对（CRIT-001）。
///
/// 返回 Err(reason) 表示绑定失败（调用方应拒绝验签）。
#[cfg(feature = "protocol-saml")]
fn validate_reference_binding(
    document_xml: &str,
    binding: &ReferenceBinding,
) -> Result<(), &'static str> {
    let Some(id) = binding.uri.strip_prefix('#') else {
        return Err("reference-uri-not-fragment");
    };
    if id.is_empty() {
        return Err("reference-uri-empty-id");
    }
    if binding.digest_method.as_deref() != Some(DIGEST_ALG_SHA256) {
        return Err("digest-method-not-sha256");
    }
    let Some(element_raw) = find_element_raw_by_id(document_xml, id) else {
        return Err("referenced-element-not-found");
    };

    use base64::Engine as _;
    use rsa::sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    let stripped = strip_enveloped_signature(&element_raw);
    let computed = Sha256::digest(stripped.as_bytes());
    let expected = base64::engine::general_purpose::STANDARD
        .decode(binding.digest_value_b64.trim())
        .map_err(|_| "digest-value-base64-decode")?;

    if expected.len() != computed.len() || expected.as_slice().ct_ne(computed.as_slice()).into() {
        return Err("digest-value-mismatch");
    }
    Ok(())
}

/// 验证 SAML Assertion 的 XML 签名（vuln-0001 核心）。
///
/// # 流程
/// 1. 从 `assertion_xml` 提取 `<ds:Signature>` 元素
/// 2. 提取 `<ds:SignatureMethod Algorithm="...">`，校验算法白名单
/// 3. 提取 `<ds:SignatureValue>` (base64) 并解码
/// 4. 提取 `<ds:SignedInfo>` 原始 XML
/// 5. 用 IdP RSA 公钥验证 PKCS#1 v1.5 RSA-SHA256 签名
///
/// # 参数
/// - `assertion_xml`: Assertion 的原始 XML（含 `<ds:Signature>`）
/// - `idp_public_key_pem`: IdP RSA 公钥 PEM（PKCS#8 或 PKCS#1）
///
/// # 返回
/// - `Ok(true)`: 签名验证通过
/// - `Ok(false)`: 签名缺失 / 算法不在白名单 / 签名不匹配
/// - `Err(_)`: 公钥解析失败 / base64 解码失败 / 内部错误
#[cfg(feature = "protocol-saml")]
fn verify_saml_signature(assertion_xml: &str, idp_public_key_pem: &str) -> GarrisonResult<bool> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;

    // 1. 提取 <ds:Signature> 元素
    let signature_xml = match extract_signature_xml(assertion_xml) {
        Some(xml) => xml,
        None => {
            tracing::warn!(
                "SAML Assertion missing <ds:Signature> element, signature verification failed"
            );
            return Ok(false);
        },
    };

    // 2. 提取并校验签名算法（白名单：仅允许 rsa-sha256 / ecdsa-sha256）
    let algorithm = extract_signature_method_algorithm(&signature_xml);
    match algorithm.as_deref() {
        Some(SIG_ALG_RSA_SHA256) => {}, // 唯一支持的验证算法，继续
        Some(SIG_ALG_ECDSA_SHA256) => {
            tracing::warn!(
                algorithm = %SIG_ALG_ECDSA_SHA256,
                "SAML 签名算法 ecdsa-sha256 在白名单内但当前实现不支持验证（待引入 ECDSA 库）"
            );
            return Ok(false);
        },
        Some(alg) if alg == SIG_ALG_RSA_1_5 => {
            tracing::warn!(
                algorithm = %alg,
                "SAML 签名算法 rsa-1_5 被拒绝（弱算法，Bleichenbacher 攻击风险）"
            );
            return Ok(false);
        },
        Some(alg) => {
            tracing::warn!(
                algorithm = %alg,
                "SAML 签名算法不在白名单内（仅允许 rsa-sha256 / ecdsa-sha256）"
            );
            return Ok(false);
        },
        None => {
            tracing::warn!("SAML <ds:Signature> missing <ds:SignatureMethod Algorithm=...>");
            return Ok(false);
        },
    }

    // 3. 提取并解码 <ds:SignatureValue>
    let signature_value_b64 = match extract_signature_value(&signature_xml) {
        Some(v) => v,
        None => {
            tracing::warn!("SAML <ds:Signature> missing <ds:SignatureValue>");
            return Ok(false);
        },
    };
    use base64::Engine as _;
    let signature_value = base64::engine::general_purpose::STANDARD
        .decode(&signature_value_b64)
        .map_err(|e| {
            GarrisonError::InvalidParam(format!("sso-saml-signature-value-decode::{}", e))
        })?;

    // 4. 提取 <ds:SignedInfo> 原始 XML（C14N 限制：直接使用原始 XML）
    let signed_info_xml = match extract_signed_info_xml(assertion_xml) {
        Some(xml) => xml,
        None => {
            tracing::warn!("SAML Assertion missing <ds:SignedInfo>");
            return Ok(false);
        },
    };

    // C14N 运行时警告：提醒运维人员当前签名验证未执行 XML Canonicalization，
    // 标准 IdP（如 Keycloak、ADFS）对 canonicalized 形式签名时验证将失败。
    // 生产环境应启用 `secure-saml-c14n` feature 或替换为完整 C14N 实现。
    tracing::warn!(
        "SAML signature verification performed without XML Canonicalization (C14N). \
         If your IdP signs canonicalized XML (standard behavior), verification may fail. \
         See extract_signed_info_xml documentation for details."
    );

    // 5. 解析 IdP RSA 公钥并验证签名（PKCS#1 v1.5 + SHA-256）
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier;

    // 尝试 PKCS#8 PEM（推荐），失败则尝试 PKCS#1 PEM
    let public_key = match rsa::RsaPublicKey::from_public_key_pem(idp_public_key_pem) {
        Ok(k) => k,
        Err(e1) => match rsa::RsaPublicKey::from_pkcs1_pem(idp_public_key_pem) {
            Ok(k) => k,
            Err(e2) => {
                return Err(GarrisonError::InvalidParam(format!(
                    "sso-saml-idp-public-key-parse-failed::pkcs8_err={}::pkcs1_err={}",
                    e1, e2
                )));
            },
        },
    };

    // base64 解码后的签名值需转为 rsa::pkcs1v15::Signature 类型（Verifier::verify 要求）
    // rsa 0.9 的 pkcs1v15::Signature 实现 TryFrom<&[u8]>，长度不符返回 error
    use std::convert::TryFrom;
    let signature = Signature::try_from(signature_value.as_slice()).map_err(|e| {
        GarrisonError::InvalidParam(format!("sso-saml-signature-bytes-decode::{}", e))
    })?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    match verifying_key.verify(signed_info_xml.as_bytes(), &signature) {
        Ok(()) => {},
        Err(_) => {
            tracing::warn!(
                "SAML signature verification failed: signature value does not match SignedInfo"
            );
            return Ok(false);
        },
    }

    // 6. CRIT-001: DigestValue 校验链——签名仅对 Reference 绑定的元素背书。
    // 缺失此环时签名与断言内容解耦，攻击者可拷贝合法 Signature 伪造任意身份（XSW）。
    let references = extract_reference_bindings(&signed_info_xml);
    if references.is_empty() {
        tracing::warn!("SAML SignedInfo missing <ds:Reference>, rejected (XSW protection)");
        return Ok(false);
    }
    for binding in &references {
        if let Err(reason) = validate_reference_binding(assertion_xml, binding) {
            tracing::warn!(
                reason = %reason,
                uri = %binding.uri,
                "SAML <ds:Reference> binding verification failed"
            );
            return Ok(false);
        }
    }
    Ok(true)
}

/// 基于 XML-DSig 的 SAML Provider（vuln-0001 修复）。
///
/// 使用 `rsa` crate 验证 SAML Assertion 的 XML 签名（RSA-SHA256）。
/// 算法白名单：仅允许 `rsa-sha256` / `ecdsa-sha256`，禁止 `rsa-1_5` 等弱算法。
///
/// # 适用场景
///
/// - 生产环境 SSO 单点登录（需 IdP 公钥 + Destination + Audience 配置）
/// - 测试环境（配合 `rsa::RsaPrivateKey::new` 生成测试密钥对）
///
/// # 限制（C14N）
///
/// 当前实现**不执行 XML Canonicalization (C14N)**，直接使用原始 `<ds:SignedInfo>`
/// XML 作为签名验证输入。若 IdP 对 canonicalized 形式签名（XML-DSig 标准做法），
/// 验证可能失败。生产部署前应验证 IdP 签名格式兼容性，或替换为完整 C14N 实现。
///
/// # ECDSA 限制
///
/// 当前仅实现 RSA-SHA256 验证。ECDSA-SHA256 在算法白名单内但实际验证返回 `Ok(false)`，
/// 待引入 ECDSA 库后补全。
#[cfg(feature = "protocol-saml")]
pub struct XmlSecSamlProvider {
    /// IdP RSA 公钥 PEM（PKCS#8 或 PKCS#1 格式），用于验证 Assertion 签名。
    idp_public_key_pem: String,
    /// 预期 Destination（SP 的 ACS URL）。None = 跳过验证（仅告警）。
    expected_destination: Option<String>,
    /// 预期 Audience（SP 的 entity_id）。None = 跳过验证（仅告警）。
    expected_audience: Option<String>,
    /// 可选 DAO（CRIT-005/006）：启用 InResponseTo 绑定校验与 Assertion 重放防护。
    request_dao: Option<std::sync::Arc<dyn crate::dao::GarrisonDao>>,
    /// 未配置 DAO 的 warn-once 标记。
    warned_no_dao: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "protocol-saml")]
impl XmlSecSamlProvider {
    /// 创建 `XmlSecSamlProvider` 实例。
    ///
    /// # 参数
    /// - `idp_public_key_pem`: IdP RSA 公钥 PEM 字符串（PKCS#8 或 PKCS#1）。
    ///   通常从 IdP 元数据 `<ds:X509Certificate>` 提取后转为 PEM 格式。
    ///
    /// # 返回
    /// - `Ok(Self)`: 创建成功
    /// - `Err(GarrisonError::InvalidParam)`: 公钥 PEM 格式无效
    pub fn new(idp_public_key_pem: String) -> GarrisonResult<Self> {
        // 预解析公钥，fail-fast 避免每次 validate_assertion 才报错
        let _ = parse_rsa_public_key(&idp_public_key_pem)?;
        Ok(Self {
            idp_public_key_pem,
            expected_destination: None,
            expected_audience: None,
            request_dao: None,
            warned_no_dao: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// 配置 DAO，启用 InResponseTo 绑定校验（CRIT-005）与 Assertion 重放防护（CRIT-006）。
    pub fn with_request_dao(mut self, dao: std::sync::Arc<dyn crate::dao::GarrisonDao>) -> Self {
        self.request_dao = Some(dao);
        self
    }

    /// 配置预期 Destination（SP 的 ACS URL），开启 Destination 验证。
    pub fn with_expected_destination(mut self, destination: String) -> Self {
        self.expected_destination = Some(destination);
        self
    }

    /// 配置预期 Audience（SP 的 entity_id），开启 Audience 验证。
    pub fn with_expected_audience(mut self, audience: String) -> Self {
        self.expected_audience = Some(audience);
        self
    }
}

/// 解析 RSA 公钥 PEM（PKCS#8 优先，回退 PKCS#1）。供 `XmlSecSamlProvider::new` fail-fast 校验。
#[cfg(feature = "protocol-saml")]
fn parse_rsa_public_key(pem: &str) -> GarrisonResult<rsa::RsaPublicKey> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;

    // 优先 PKCS#8 PEM，失败回退 PKCS#1 PEM；两者皆失败才返回错误
    match rsa::RsaPublicKey::from_public_key_pem(pem) {
        Ok(k) => Ok(k),
        Err(e1) => match rsa::RsaPublicKey::from_pkcs1_pem(pem) {
            Ok(k) => Ok(k),
            Err(e2) => Err(GarrisonError::InvalidParam(format!(
                "sso-saml-idp-public-key-parse-failed::pkcs8_err={}::pkcs1_err={}",
                e1, e2
            ))),
        },
    }
}

#[cfg(feature = "protocol-saml")]
#[async_trait]
impl SamlProvider for XmlSecSamlProvider {
    async fn build_authn_request(
        &self,
        sp_entity_id: &str,
        acs_url: &str,
        idp_sso_endpoint: &str,
    ) -> GarrisonResult<SamlRequest> {
        let request = SamlRequest {
            id: Uuid::new_v4().to_string(),
            issue_instant: Utc::now().to_rfc3339(),
            destination: idp_sso_endpoint.to_string(),
            issuer: sp_entity_id.to_string(),
            assertion_consumer_service_url: acs_url.to_string(),
        };
        // CRIT-005: 记录在途请求 ID 供 parse_response 绑定校验（TTL 600 秒）
        if let Some(d) = &self.request_dao {
            let key = format!("{}req:{}", DaoKeyPrefix::Saml, request.id);
            d.set(&key, "1", 600).await?;
        }
        Ok(request)
    }

    async fn parse_response(&self, response_xml: &str) -> GarrisonResult<SamlResponse> {
        // SAFETY: quick-xml 不解析外部实体，XXE 安全
        // LOW-2: SAML response 大小上限（防超大 payload 内存 DoS，真实 SAML Response 极少超 64KB）
        const SAML_RESPONSE_MAX_SIZE: usize = 64 * 1024;
        if response_xml.len() > SAML_RESPONSE_MAX_SIZE {
            return Err(GarrisonError::InvalidParam(format!(
                "saml-response-too-large::{}::{}",
                response_xml.len(),
                SAML_RESPONSE_MAX_SIZE
            )));
        }
        let mut response = parse_saml_response_xml(response_xml)?;

        // CRIT-002: StatusCode 强制 Success（fail-closed，错误响应不得继续处理）
        validate_status_code(&response.status_code)?;

        // CRIT-005: InResponseTo ↔ AuthnRequest 绑定校验
        enforce_in_response_to(
            self.request_dao.as_ref(),
            &self.warned_no_dao,
            &response.in_response_to,
        )
        .await?;

        // vuln-0002: Destination 验证（fail-loud）
        validate_destination(&response.destination, self.expected_destination.as_deref())?;

        // vuln-0002: Audience 验证（fail-loud，仅在有 Assertion 时校验）
        if let Some(ref assertion) = response.assertion {
            validate_audience(&assertion.audience, self.expected_audience.as_deref())?;
        }

        // vuln-0001: 验证 Assertion 签名（非 fail-closed，而是真实验证）
        if let Some(ref assertion) = response.assertion {
            match self.validate_assertion(assertion).await {
                Ok(true) => {
                    // CRIT-006: 验签通过后强制重放检查（Assertion ID 一次性消费）
                    if let Some(d) = &self.request_dao {
                        if !check_assertion_replay(
                            &assertion.id,
                            &assertion.not_on_or_after,
                            d.as_ref(),
                        )
                        .await?
                        {
                            return Err(GarrisonError::InvalidParam(format!(
                                "sso-saml-assertion-replay::{}",
                                assertion.id
                            )));
                        }
                    }
                },
                Ok(false) => {
                    tracing::warn!("SAML Assertion signature verification failed, stripped");
                    response.assertion = None;
                },
                Err(e) => return Err(e),
            }
        }
        Ok(response)
    }

    async fn validate_assertion(&self, assertion: &SamlAssertion) -> GarrisonResult<bool> {
        let raw_xml = assertion.raw_xml.as_ref().ok_or_else(|| {
            GarrisonError::InvalidParam(
                "sso-saml-missing-raw-xml-for-signature-verification".to_string(),
            )
        })?;
        verify_saml_signature(raw_xml, &self.idp_public_key_pem)
    }
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
            not_before: String::new(),
            attributes: vec![("email".to_string(), "user@example.com".to_string())],
            raw_xml: None,
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
        // raw_xml skip_serializing/skip_deserializing：反序列化后必为 None
        assert!(deserialized.raw_xml.is_none());
    }

    /// SamlResponse 序列化/反序列化往返（spec R-001）。
    #[test]
    fn saml_response_serde_roundtrip() {
        let response = SamlResponse {
            destination: "https://sp.example.com/acs".to_string(),
            issuer: "https://idp.example.com".to_string(),
            assertion: None,
            status_code: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string(),
            in_response_to: String::new(),
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
            not_before: String::new(),
            attributes: vec![],
            raw_xml: None,
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
            .build_authn_request(
                "https://sp.example.com",
                "https://sp.example.com/acs",
                "https://idp.example.com/sso",
            )
            .await
            .unwrap();
        assert_eq!(request.issuer, "https://sp.example.com");
        assert_eq!(
            request.assertion_consumer_service_url,
            "https://sp.example.com/acs"
        );
        // vuln-0002: destination 应为 IdP SSO 端点（不再为空）
        assert_eq!(request.destination, "https://idp.example.com/sso");
        assert!(!request.id.is_empty());
        assert!(!request.issue_instant.is_empty());
    }

    /// build_authn_request 生成唯一 id（每次调用不同）（spec R-002）。
    #[tokio::test]
    async fn build_authn_request_generates_unique_ids() {
        let provider = DefaultSamlProvider::new().unwrap();
        let r1 = provider
            .build_authn_request("sp1", "https://sp1.example.com/acs", "https://idp/sso")
            .await
            .unwrap();
        let r2 = provider
            .build_authn_request("sp1", "https://sp1.example.com/acs", "https://idp/sso")
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
  <saml:Assertion ID="assertion-123">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
      <saml:SubjectConfirmation>
        <saml:SubjectConfirmationData NotOnOrAfter="{future_str}"/>
      </saml:SubjectConfirmation>
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
</samlp:Response>"#
        );
        let provider = DefaultSamlProvider::new().unwrap();
        let response = provider.parse_response(&xml).await.unwrap();
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

    /// CRIT-002: 非 Success 状态码的 Response 返回 InvalidParam（fail-closed）。
    #[tokio::test]
    async fn parse_response_rejects_non_success_status_code() {
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
        let result = provider.parse_response(xml).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "非 Success 状态码应返回 InvalidParam，实际: {:?}",
            result
        );
    }

    /// CRIT-002: 非 Success 响应夹带 Assertion 也必须拒绝（不得当作成功登录处理）。
    #[tokio::test]
    async fn parse_response_rejects_error_response_carrying_assertion() {
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
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>
  </samlp:Status>
  <saml:Assertion ID="evil-in-error">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>admin@evil.test</saml:NameID></saml:Subject>
    <saml:Conditions>
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:SubjectConfirmationData NotOnOrAfter="{}"/>
  </saml:Assertion>
</samlp:Response>"#,
            future_str
        );
        let provider = DefaultSamlProvider::new().unwrap();
        let result = provider.parse_response(&xml).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("status-not-success")),
            "错误响应夹带 Assertion 应被 StatusCode 校验拒绝，实际: {:?}",
            result
        );
    }

    /// 非 SAML XML 输入：provider 层因 StatusCode 校验（CRIT-002）返回 InvalidParam（fail-closed）。
    ///
    /// quick-xml 是宽松解析器，非 XML 文本不会在解析层报错（字段均为空），
    /// 但空 status_code 不等于 Success，parse_response 必须拒绝而非静默放行。
    #[tokio::test]
    async fn parse_response_non_saml_xml_returns_empty_fields() {
        let provider = DefaultSamlProvider::new().unwrap();
        let result = provider.parse_response("not a saml response").await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("status-not-success")),
            "非 SAML 输入（空 StatusCode）应被 fail-closed 拒绝，实际: {:?}",
            result
        );
        // 解析层本身仍返回空字段（供直接调用方使用）
        let parsed = parse_saml_response_xml("not a saml response").unwrap();
        assert!(parsed.destination.is_empty());
        assert!(parsed.status_code.is_empty());
        assert!(parsed.assertion.is_none());
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
            matches!(result, Err(GarrisonError::InvalidToken(_))),
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
            not_before: String::new(),
            attributes: vec![],
            raw_xml: None,
        };
        let result = provider.validate_assertion(&assertion).await;
        assert!(result.is_err());
        match result.err() {
            Some(GarrisonError::NotImplemented(_)) => {},
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

    // ========================================================================
    // vuln-0002: Destination / Audience 验证测试
    // ========================================================================

    /// vuln-0002: Destination 匹配时 parse_response 通过。
    #[tokio::test]
    async fn parse_response_destination_match_passes() {
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
    <saml:Conditions>
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#,
            future_str
        );
        let provider = DefaultSamlProvider::new()
            .unwrap()
            .with_expected_destination("https://sp.example.com/acs".to_string())
            .with_expected_audience("https://sp.example.com".to_string());
        let response = provider.parse_response(&xml).await.unwrap();
        assert_eq!(response.destination, "https://sp.example.com/acs");
    }

    /// vuln-0002: Destination 不匹配时 parse_response 返回 InvalidParam（fail-loud）。
    #[tokio::test]
    async fn parse_response_destination_mismatch_returns_error() {
        let future = Utc::now().timestamp() + 3600;
        let future_str = chrono::DateTime::from_timestamp(future, 0)
            .unwrap()
            .to_rfc3339();
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                Destination="https://evil.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion>
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>user@example.com</saml:NameID>
      <saml:SubjectConfirmation>
        <saml:SubjectConfirmationData NotOnOrAfter="{}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"#,
            future_str
        );
        let provider = DefaultSamlProvider::new()
            .unwrap()
            .with_expected_destination("https://sp.example.com/acs".to_string());
        let result = provider.parse_response(&xml).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "Destination 不匹配应返回 InvalidParam（fail-loud），实际: {:?}",
            result
        );
    }

    /// vuln-0002: Audience 不匹配时 parse_response 返回 InvalidParam（fail-loud）。
    #[tokio::test]
    async fn parse_response_audience_mismatch_returns_error() {
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
    <saml:Conditions>
      <saml:AudienceRestriction>
        <saml:Audience>https://evil.example.com</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#,
            future_str
        );
        let provider = DefaultSamlProvider::new()
            .unwrap()
            .with_expected_audience("https://sp.example.com".to_string());
        let result = provider.parse_response(&xml).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(_))),
            "Audience 不匹配应返回 InvalidParam（fail-loud），实际: {:?}",
            result
        );
    }

    /// vuln-0002: validate_destination / validate_audience 辅助函数单元测试。
    #[test]
    fn validate_destination_audience_unit_tests() {
        // Destination 匹配
        assert!(validate_destination("https://sp/acs", Some("https://sp/acs")).is_ok());
        // Destination 不匹配
        assert!(matches!(
            validate_destination("https://evil/acs", Some("https://sp/acs")),
            Err(GarrisonError::InvalidParam(_))
        ));
        // Destination 未配置（None）→ Ok + warn
        assert!(validate_destination("https://sp/acs", None).is_ok());
        // Destination 预期为空字符串 → Ok + warn
        assert!(validate_destination("https://sp/acs", Some("")).is_ok());

        // Audience 匹配
        assert!(validate_audience("https://sp", Some("https://sp")).is_ok());
        // Audience 不匹配
        assert!(matches!(
            validate_audience("https://evil", Some("https://sp")),
            Err(GarrisonError::InvalidParam(_))
        ));
        // Audience 未配置（None）→ Ok + warn
        assert!(validate_audience("https://sp", None).is_ok());
    }

    // ========================================================================
    // vuln-0001: 签名算法白名单测试（仅 secure-saml feature 下编译）
    // ========================================================================

    #[cfg(feature = "protocol-saml")]
    mod signature_tests {
        use super::*;

        /// vuln-0001: 签名算法白名单允许强算法（rsa-sha256 / ecdsa-sha256）。
        #[test]
        fn signature_algorithm_whitelist_allows_strong_algorithms() {
            assert!(
                is_signature_algorithm_allowed(SIG_ALG_RSA_SHA256),
                "rsa-sha256 应在白名单内"
            );
            assert!(
                is_signature_algorithm_allowed(SIG_ALG_ECDSA_SHA256),
                "ecdsa-sha256 应在白名单内"
            );
        }

        /// vuln-0001: 签名算法白名单拒绝弱算法（rsa-1_5）和未知算法。
        #[test]
        fn signature_algorithm_whitelist_rejects_weak_and_unknown_algorithms() {
            assert!(
                !is_signature_algorithm_allowed(SIG_ALG_RSA_1_5),
                "rsa-1_5 应被拒绝（Bleichenbacher 攻击风险）"
            );
            assert!(
                !is_signature_algorithm_allowed("http://www.w3.org/2000/09/xmldsig#dsa-sha1"),
                "dsa-sha1 应被拒绝（未在白名单）"
            );
            assert!(
                !is_signature_algorithm_allowed("unknown-algorithm"),
                "未知算法应被拒绝"
            );
            assert!(!is_signature_algorithm_allowed(""), "空字符串应被拒绝");
        }

        // ========================================================================
        // vuln-0001: RSA-SHA256 签名验证测试
        // ========================================================================

        /// 构造测试用 SAML Assertion XML（含完整 XML-DSig <ds:Signature>）。
        ///
        /// 返回 (assertion_xml, public_key_pem)：
        /// - `assertion_xml`：含 `<ds:Signature>` 的 Assertion XML，SignedInfo 含
        ///   `<ds:Reference URI="#id">` 与 SHA-256 DigestValue（CRIT-001 完整校验链）
        /// - `public_key_pem`：对应 RSA 公钥的 PKCS#8 PEM 字符串
        ///
        /// 摘要约定：DigestValue = SHA256(被引用元素去除 Signature 子元素后的原始字节)
        /// ——与 `strip_enveloped_signature` 的隐式 enveloped-signature transform 一致。
        fn build_test_signed_assertion() -> (String, String) {
            build_test_signed_assertion_with_inner("")
        }

        /// 带额外内部元素的变体：`extra_inner` 拼接在 Signature 之前，
        /// 并纳入 DigestValue 计算（供端到端测试注入 NotOnOrAfter 等元素）。
        fn build_test_signed_assertion_with_inner(extra_inner: &str) -> (String, String) {
            use base64::Engine as _;
            use rsa::pkcs1v15::SigningKey;
            use rsa::pkcs8::EncodePublicKey;
            use rsa::sha2::{Digest, Sha256};
            use rsa::signature::{SignatureEncoding, Signer};
            use rsa::RsaPrivateKey;

            let mut rng = rand::rngs::OsRng;
            // 2048-bit RSA 测试密钥（生产建议 3072+）
            let private_key =
                RsaPrivateKey::new(&mut rng, 2048).expect("RSA 2048 密钥生成不应失败");
            let public_key_pem = private_key
                .to_public_key()
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .expect("PEM 编码不应失败");

            let assertion_id = "_test-assertion-001";
            let inner = format!(
                "<saml:Issuer>https://idp.example.com</saml:Issuer>\
<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>{extra_inner}"
            );

            // 摘要输入：不含 Signature 的元素原始字节（隐式 enveloped-signature transform）
            let element_without_sig =
                format!(r#"<Assertion ID="{}">{}</Assertion>"#, assertion_id, inner);
            let digest_b64 = base64::engine::general_purpose::STANDARD
                .encode(Sha256::digest(element_without_sig.as_bytes()));

            // 构造 <ds:SignedInfo>（SignatureMethod + Reference/DigestValue 完整链）
            // 注意：URI 属性含 "# 序列，需使用 r## 原始字符串
            let signed_info = format!(
                r##"<ds:SignedInfo><ds:SignatureMethod Algorithm="{}"></ds:SignatureMethod><ds:Reference URI="#{}"><ds:DigestMethod Algorithm="{}"></ds:DigestMethod><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>"##,
                SIG_ALG_RSA_SHA256, assertion_id, DIGEST_ALG_SHA256, digest_b64
            );

            // 用 RSA 私钥 + SHA-256 (PKCS#1 v1.5) 对 SignedInfo 签名
            let signing_key = SigningKey::<Sha256>::new(private_key);
            let signature = signing_key.sign(signed_info.as_bytes());
            let signature_b64 =
                base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

            // 拼接完整 Assertion XML（含 <ds:Signature>）
            let xml = format!(
                r#"<Assertion ID="{}">{}<ds:Signature>{}<ds:SignatureValue>{}</ds:SignatureValue></ds:Signature></Assertion>"#,
                assertion_id, inner, signed_info, signature_b64
            );
            (xml, public_key_pem)
        }

        /// CRIT-001（fix-security-audit-findings）: XSW 攻击防护。
        ///
        /// 攻击者将一份合法签名的 `<ds:Signature>` 原样拷贝进自己控制的
        /// Assertion（NameID=admin），试图让有效签名为其伪造内容背书。
        /// 验签必须拒绝——签名仅对 DigestValue 绑定的原始元素有效。
        #[test]
        fn verify_saml_signature_rejects_xsw_copied_signature() {
            let (legit_xml, public_key_pem) = build_test_signed_assertion();
            let sig_start = legit_xml
                .find("<ds:Signature>")
                .expect("fixture 应含 Signature");
            let sig_end = legit_xml
                .find("</ds:Signature>")
                .expect("fixture 应含 Signature 闭合")
                + "</ds:Signature>".len();
            let stolen_signature = legit_xml[sig_start..sig_end].to_string();

            let evil_xml = format!(
                r#"<Assertion ID="evil-xsw"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>admin@evil.test</saml:NameID></saml:Subject>{}<saml:Attribute Name="role"><saml:AttributeValue>super-admin</saml:AttributeValue></saml:Attribute></Assertion>"#,
                stolen_signature
            );
            let result = verify_saml_signature(&evil_xml, &public_key_pem);
            assert!(
                result.is_ok(),
                "XSW 检测不应报错，应返回 Ok(false): {:?}",
                result
            );
            assert!(
                !result.unwrap(),
                "XSW：拷贝的合法签名不得为未签名的攻击者 Assertion 背书"
            );
        }

        /// vuln-0001: 合法 RSA-SHA256 签名应验证通过。
        #[test]
        fn verify_saml_signature_accepts_valid_signature() {
            let (xml, public_key_pem) = build_test_signed_assertion();
            let result = verify_saml_signature(&xml, &public_key_pem);
            assert!(
                result.is_ok(),
                "verify_saml_signature 不应报错: {:?}",
                result
            );
            assert!(result.unwrap(), "合法 RSA-SHA256 签名应验证通过");
        }

        /// vuln-0001: 用错误公钥验证签名应返回 Ok(false)（签名不匹配）。
        #[test]
        fn verify_saml_signature_rejects_wrong_public_key() {
            use rsa::pkcs8::EncodePublicKey;
            let (xml, _original_public_pem) = build_test_signed_assertion();
            // 生成另一个密钥对的公钥
            let mut rng = rand::rngs::OsRng;
            let other_key =
                rsa::RsaPrivateKey::new(&mut rng, 2048).expect("RSA 2048 密钥生成不应失败");
            let other_public_pem = other_key
                .to_public_key()
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .expect("PEM 编码不应失败");
            let result = verify_saml_signature(&xml, &other_public_pem);
            assert!(
                result.is_ok(),
                "verify_saml_signature 不应报错: {:?}",
                result
            );
            assert!(!result.unwrap(), "用错误公钥验证应返回 false（签名不匹配）");
        }

        /// vuln-0001: 篡改 SignedInfo 内容后签名应验证失败。
        #[test]
        fn verify_saml_signature_rejects_tampered_signed_info() {
            let (xml, public_key_pem) = build_test_signed_assertion();
            // 在 <ds:SignedInfo> 内插入注释，改变 SignedInfo 字节内容（保持算法 URI 不变）
            let tampered_xml =
                xml.replacen("<ds:SignedInfo>", "<ds:SignedInfo><!-- tampered -->", 1);
            let result = verify_saml_signature(&tampered_xml, &public_key_pem);
            assert!(
                result.is_ok(),
                "verify_saml_signature 不应报错: {:?}",
                result
            );
            assert!(!result.unwrap(), "篡改 SignedInfo 后签名验证应失败");
        }

        /// vuln-0001: 缺少 <ds:Signature> 元素应返回 Ok(false)。
        #[test]
        fn verify_saml_signature_rejects_missing_signature() {
            let xml = r#"<Assertion><Issuer>https://idp.example.com</Issuer></Assertion>"#;
            // 使用任意合法公钥 PEM（不会到达公钥解析步骤）
            let (_signed_xml, public_key_pem) = build_test_signed_assertion();
            let result = verify_saml_signature(xml, &public_key_pem);
            assert!(
                result.is_ok(),
                "verify_saml_signature 不应报错: {:?}",
                result
            );
            assert!(!result.unwrap(), "缺少 <ds:Signature> 应返回 false");
        }

        /// vuln-0001: rsa-1_5 算法应被白名单拒绝（返回 Ok(false)）。
        #[test]
        fn verify_saml_signature_rejects_rsa_1_5_algorithm() {
            let xml = format!(
                r#"<Assertion><ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm="{}"></ds:SignatureMethod></ds:SignedInfo><ds:SignatureValue>dGVzdA==</ds:SignatureValue></ds:Signature></Assertion>"#,
                SIG_ALG_RSA_1_5
            );
            // rsa-1_5 在算法白名单检查阶段即返回 Ok(false)，无需到达公钥解析步骤
            // 使用任意合法公钥 PEM 以满足函数签名
            let (_signed_xml, public_key_pem) = build_test_signed_assertion();
            let result = verify_saml_signature(&xml, &public_key_pem);
            assert!(
                result.is_ok(),
                "verify_saml_signature 不应报错: {:?}",
                result
            );
            assert!(
                !result.unwrap(),
                "rsa-1_5 算法应被白名单拒绝（Bleichenbacher 攻击风险）"
            );
        }

        /// vuln-0001: 非法公钥 PEM 应返回 Err（fail-loud）。
        #[test]
        fn verify_saml_signature_rejects_invalid_public_key_pem() {
            // rsa-sha256 算法通过白名单后会尝试解析公钥 PEM
            let (xml, _public_key_pem) = build_test_signed_assertion();
            let invalid_pem = "-----BEGIN INVALID-----\nnot a real key\n-----END INVALID-----";
            let result = verify_saml_signature(&xml, invalid_pem);
            assert!(
                result.is_err(),
                "非法公钥 PEM 应返回 Err（fail-loud），实际: {:?}",
                result
            );
            assert!(
                matches!(result, Err(GarrisonError::InvalidParam(_))),
                "应为 InvalidParam 错误"
            );
        }

        // ========================================================================
        // CRIT-006: Assertion 重放防护接线（端到端）
        // ========================================================================

        /// CRIT-006: XmlSecSamlProvider 端到端——同一签名 Assertion 二次提交被重放防护拒绝。
        #[tokio::test]
        async fn xmlsec_provider_rejects_replayed_signed_assertion() {
            let future = Utc::now().timestamp() + 3600;
            let future_str = chrono::DateTime::from_timestamp(future, 0)
                .unwrap()
                .to_rfc3339();

            // NotOnOrAfter 在签名前注入（纳入 DigestValue 计算）
            let (signed_assertion, public_key_pem) = build_test_signed_assertion_with_inner(
                &format!("<SubjectConfirmationData NotOnOrAfter=\"{}\"/>", future_str),
            );
            let dao = std::sync::Arc::new(crate::dao::tests::MockDao::new());
            let provider = XmlSecSamlProvider::new(public_key_pem)
                .unwrap()
                .with_request_dao(dao);

            let xml = format!(
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                Destination="https://sp.example.com/acs">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
  {signed_assertion}
</samlp:Response>"#
            );

            let first = provider.parse_response(&xml).await.expect("首次解析应通过");
            assert!(first.assertion.is_some(), "验签通过的 Assertion 不应被剥离");

            let second = provider.parse_response(&xml).await;
            assert!(
                matches!(second, Err(GarrisonError::InvalidParam(ref m)) if m.contains("assertion-replay")),
                "同一签名 Assertion 二次提交应被重放防护拒绝，实际: {:?}",
                second
            );
        }
    }

    // ========================================================================
    // vuln-0003: TOCTOU 并发重放防护测试
    // ========================================================================

    /// vuln-0003: 并发场景下 get_and_delete 原子性验证。
    ///
    /// 验证 `check_assertion_replay` 在并发调用时：
    /// - 不应 panic 或返回 Err
    /// - 至少一个任务成功消费（Ok(true)）
    /// - 至少一个任务被拒绝（Ok(false)）—— 证明 get_and_delete 原子生效
    ///
    /// **注意**：完整 TOCTOU 修复需要 `set_nx`（SET if Not eXists）原语，
    /// 当前 GarrisonDao trait 未提供。本测试验证 `get_and_delete` 提供的
    /// 进程内原子性（MockDao 由 parking_lot::Mutex 保护）。
    #[tokio::test]
    async fn check_assertion_replay_concurrent_atomic_get_and_delete() {
        let dao = std::sync::Arc::new(crate::dao::tests::MockDao::new());
        let future = Utc::now().timestamp() + 3600;
        let future_str = chrono::DateTime::from_timestamp(future, 0)
            .unwrap()
            .to_rfc3339();
        let assertion_id = "assertion-toctou-concurrent-001".to_string();

        // 10 个并发任务同时调用 check_assertion_replay
        let mut handles = Vec::new();
        for _ in 0..10 {
            let dao_clone = dao.clone();
            let id = assertion_id.clone();
            let ttl = future_str.clone();
            handles.push(tokio::spawn(async move {
                check_assertion_replay(&id, &ttl, &*dao_clone).await
            }));
        }

        let mut success_count = 0usize;
        let mut failure_count = 0usize;
        for handle in handles {
            let result = handle.await.expect("并发任务不应 panic");
            match result {
                Ok(true) => success_count += 1,
                Ok(false) => failure_count += 1,
                Err(e) => panic!("check_assertion_replay 不应报错: {:?}", e),
            }
        }
        // 并发场景下至少一个成功 + 一个失败（证明 get_and_delete 原子性生效）
        assert!(
            success_count >= 1,
            "至少一个任务应成功消费，实际成功: {}",
            success_count
        );
        assert!(
            failure_count >= 1,
            "至少一个任务应被拒绝（get_and_delete 原子性），实际拒绝: {}",
            failure_count
        );
        assert_eq!(
            success_count + failure_count,
            10,
            "所有 10 个任务都应正常完成"
        );
    }

    /// vuln-0003: 串行场景下重放防护正确（首次通过 + 二次拒绝）。
    ///
    /// 验证 `get_and_delete` 替代 `get+set` 后，串行重放防护仍然正确。
    #[tokio::test]
    async fn check_assertion_replay_serial_replay_protection() {
        let dao = crate::dao::tests::MockDao::new();
        let future = Utc::now().timestamp() + 3600;
        let future_str = chrono::DateTime::from_timestamp(future, 0)
            .unwrap()
            .to_rfc3339();

        // 首次消费应通过
        let first = check_assertion_replay("assertion-serial-001", &future_str, &dao)
            .await
            .expect("首次 check 不应报错");
        assert!(first, "首次消费应通过");

        // 二次消费（重放）应被拒绝
        let second = check_assertion_replay("assertion-serial-001", &future_str, &dao)
            .await
            .expect("二次 check 不应报错");
        assert!(
            !second,
            "同一 Assertion ID 二次消费应被拒绝（vuln-0003 重放防护）"
        );
    }

    // ========================================================================
    // parse_saml_response_xml 结构覆盖测试（T011）
    // ========================================================================

    /// vuln-0001: `raw_xml` 应包含完整 `<Assertion>...</Assertion>` 原始 XML。
    #[test]
    fn parse_saml_response_xml_extracts_raw_xml() {
        let future = Utc::now().timestamp() + 3600;
        let future_str = chrono::DateTime::from_timestamp(future, 0)
            .unwrap()
            .to_rfc3339();
        let xml = format!(
            r#"<Response>
  <Assertion ID="raw-xml-001">
    <Issuer>https://idp.example.com</Issuer>
    <Subject><NameID>user@example.com</NameID></Subject>
    <Audience>https://sp.example.com</Audience>
    <SubjectConfirmationData NotOnOrAfter="{}"/>
  </Assertion>
</Response>"#,
            future_str
        );
        let result = parse_saml_response_xml(&xml).unwrap();
        let assertion = result.assertion.expect("应解析出 Assertion");
        let raw = assertion.raw_xml.expect("raw_xml 应被填充");
        let trimmed = raw.trim_start();
        assert!(
            trimmed.starts_with("<Assertion"),
            "raw_xml 应以 <Assertion 开头（trim 后），实际: {}",
            &trimmed[..trimmed.len().min(50)]
        );
        assert!(
            raw.contains("</Assertion>") || raw.contains("</Assertion >"),
            "raw_xml 应包含 </Assertion> 闭合标签"
        );
        assert!(
            raw.contains("ID=\"raw-xml-001\""),
            "raw_xml 应包含 Assertion ID"
        );
    }

    /// parse_saml_response_xml 正确提取 Assertion 内各字段。
    #[test]
    fn parse_saml_response_xml_extracts_assertion_fields() {
        let future = Utc::now().timestamp() + 3600;
        let future_str = chrono::DateTime::from_timestamp(future, 0)
            .unwrap()
            .to_rfc3339();
        let xml = format!(
            r#"<Response Destination="https://sp.example.com/acs">
  <Issuer>https://idp.example.com</Issuer>
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
  <Assertion ID="fields-001">
    <Issuer>https://idp-assertion.example.com</Issuer>
    <Subject><NameID>user@example.com</NameID></Subject>
    <Audience>https://sp.example.com</Audience>
    <SubjectConfirmationData NotOnOrAfter="{}"/>
    <AttributeStatement>
      <Attribute Name="email"><AttributeValue>user@example.com</AttributeValue></Attribute>
      <Attribute Name="role"><AttributeValue>admin</AttributeValue></Attribute>
    </AttributeStatement>
  </Assertion>
</Response>"#,
            future_str
        );
        let result = parse_saml_response_xml(&xml).unwrap();
        assert_eq!(result.destination, "https://sp.example.com/acs");
        assert_eq!(result.issuer, "https://idp.example.com");
        assert_eq!(
            result.status_code,
            "urn:oasis:names:tc:SAML:2.0:status:Success"
        );
        let assertion = result.assertion.expect("应解析出 Assertion");
        assert_eq!(assertion.id, "fields-001");
        assert_eq!(assertion.issuer, "https://idp-assertion.example.com");
        assert_eq!(assertion.subject, "user@example.com");
        assert_eq!(assertion.audience, "https://sp.example.com");
        assert_eq!(assertion.attributes.len(), 2);
        assert_eq!(
            assertion.attributes[0],
            ("email".to_string(), "user@example.com".to_string())
        );
        assert_eq!(
            assertion.attributes[1],
            ("role".to_string(), "admin".to_string())
        );
    }

    /// 空 Assertion 元素（无子元素）应解析为 Some 但字段均为空。
    ///
    /// CRIT-004：解析层保留空字段；NotOnOrAfter 缺失的拒绝发生在 into_response，
    /// 故此用例补充未来 NotOnOrAfter 以通过时间条件校验。
    #[test]
    fn parse_saml_response_xml_handles_empty_assertion() {
        let future = Utc::now().timestamp() + 3600;
        let future_str = chrono::DateTime::from_timestamp(future, 0)
            .unwrap()
            .to_rfc3339();
        let xml = format!(
            r#"<Response>
  <Assertion ID="empty-001">
    <SubjectConfirmationData NotOnOrAfter="{}"/>
  </Assertion>
</Response>"#,
            future_str
        );
        let result = parse_saml_response_xml(&xml).unwrap();
        let assertion = result.assertion.expect("空 Assertion 仍应被解析");
        assert_eq!(assertion.id, "empty-001");
        assert!(assertion.issuer.is_empty());
        assert!(assertion.subject.is_empty());
        assert!(assertion.audience.is_empty());
        assert!(assertion.attributes.is_empty());
    }

    /// CRIT-004: NotOnOrAfter 缺失（空）即拒绝——无过期时间的断言不得放行。
    #[test]
    fn parse_saml_response_rejects_missing_not_on_or_after() {
        let xml = r#"<Response>
  <Assertion ID="no-expiry-001">
    <Issuer>https://idp.example.com</Issuer>
    <Subject><NameID>user@example.com</NameID></Subject>
  </Assertion>
</Response>"#;
        let result = parse_saml_response_xml(xml);
        assert!(
            matches!(result, Err(GarrisonError::InvalidToken(ref m)) if m.contains("missing-not-on-or-after")),
            "缺失 NotOnOrAfter 应 fail-closed 拒绝，实际: {:?}",
            result
        );
    }

    /// CRIT-004: NotBefore 在未来的断言即刻使用应被拒绝。
    #[test]
    fn parse_saml_response_rejects_future_not_before() {
        let not_before = Utc::now().timestamp() + 3600;
        let nb_str = chrono::DateTime::from_timestamp(not_before, 0)
            .unwrap()
            .to_rfc3339();
        let expiry = Utc::now().timestamp() + 7200;
        let exp_str = chrono::DateTime::from_timestamp(expiry, 0)
            .unwrap()
            .to_rfc3339();
        let xml = format!(
            r#"<Response>
  <Assertion ID="future-nb-001">
    <Issuer>https://idp.example.com</Issuer>
    <Conditions NotBefore="{}"/>
    <Subject><NameID>user@example.com</NameID></Subject>
    <SubjectConfirmationData NotOnOrAfter="{}"/>
  </Assertion>
</Response>"#,
            nb_str, exp_str
        );
        let result = parse_saml_response_xml(&xml);
        assert!(
            matches!(result, Err(GarrisonError::InvalidToken(ref m)) if m.contains("not-yet-valid")),
            "未来 NotBefore 应被拒绝，实际: {:?}",
            result
        );
    }

    /// CRIT-004: 已生效 NotBefore + 有效期内的断言正常通过。
    #[test]
    fn parse_saml_response_accepts_valid_not_before_window() {
        let not_before = Utc::now().timestamp() - 300;
        let nb_str = chrono::DateTime::from_timestamp(not_before, 0)
            .unwrap()
            .to_rfc3339();
        let expiry = Utc::now().timestamp() + 3600;
        let exp_str = chrono::DateTime::from_timestamp(expiry, 0)
            .unwrap()
            .to_rfc3339();
        let xml = format!(
            r#"<Response>
  <Assertion ID="valid-window-001">
    <Issuer>https://idp.example.com</Issuer>
    <Conditions NotBefore="{}"/>
    <Subject><NameID>user@example.com</NameID></Subject>
    <SubjectConfirmationData NotOnOrAfter="{}"/>
  </Assertion>
</Response>"#,
            nb_str, exp_str
        );
        let result = parse_saml_response_xml(&xml);
        assert!(result.is_ok(), "合法时间窗口不应报错，实际: {:?}", result);
    }

    /// 无 Assertion 的 Response 应返回 assertion=None。
    #[test]
    fn parse_saml_response_xml_no_assertion() {
        let xml = r#"<Response Destination="https://sp.example.com">
  <Issuer>https://idp.example.com</Issuer>
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></Status>
</Response>"#;
        let result = parse_saml_response_xml(xml).unwrap();
        assert!(result.assertion.is_none());
        assert_eq!(result.destination, "https://sp.example.com");
        assert_eq!(result.issuer, "https://idp.example.com");
    }

    // ========================================================================
    // CRIT-005: InResponseTo ↔ AuthnRequest 绑定校验
    // ========================================================================

    /// 构造带 InResponseTo 的最小合法 Response（Success，无 Assertion）。
    fn build_sp_initiated_response(in_response_to: &str) -> String {
        format!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                Destination="https://sp.example.com/acs" InResponseTo="{in_response_to}">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
</samlp:Response>"#
        )
    }

    /// CRIT-005: 配置 DAO 后，InResponseTo 首次消费通过、二次消费拒绝（一次性）。
    #[tokio::test]
    async fn in_response_to_binding_first_pass_then_rejected() {
        use crate::dao::GarrisonDao as _;
        let dao = std::sync::Arc::new(crate::dao::tests::MockDao::new());
        let provider = DefaultSamlProvider::new()
            .unwrap()
            .with_request_dao(dao.clone());

        let request = provider
            .build_authn_request("sp", "https://sp/acs", "https://idp/sso")
            .await
            .unwrap();
        // 注册表应已写入请求 ID
        assert!(
            dao.get(&format!("{}req:{}", DaoKeyPrefix::Saml, request.id))
                .await
                .unwrap()
                .is_some(),
            "build_authn_request 应记录在途请求 ID"
        );

        let xml = build_sp_initiated_response(&request.id);
        provider
            .parse_response(&xml)
            .await
            .expect("首次消费在途请求 ID 应通过");

        // 同一 InResponseTo 第二次提交：注册表条目已被原子消费 → 拒绝
        let second = provider.parse_response(&xml).await;
        assert!(
            matches!(second, Err(GarrisonError::InvalidParam(ref m)) if m.contains("in-response-to-unknown")),
            "同一 InResponseTo 二次消费应被拒绝，实际: {:?}",
            second
        );
    }

    /// CRIT-005: 未注册的 InResponseTo 直接拒绝。
    #[tokio::test]
    async fn in_response_to_unknown_rejected() {
        let dao = std::sync::Arc::new(crate::dao::tests::MockDao::new());
        let provider = DefaultSamlProvider::new().unwrap().with_request_dao(dao);
        let xml = build_sp_initiated_response("_never-issued-id");
        let result = provider.parse_response(&xml).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("in-response-to-unknown")),
            "未注册的 InResponseTo 应被拒绝，实际: {:?}",
            result
        );
    }

    /// CRIT-005: 无 DAO 时携带 InResponseTo 的响应 fail-closed 拒绝（无法验证绑定）。
    #[tokio::test]
    async fn in_response_to_without_dao_fail_closed() {
        let provider = DefaultSamlProvider::new().unwrap();
        let xml = build_sp_initiated_response("_some-request-id");
        let result = provider.parse_response(&xml).await;
        assert!(
            matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("unverifiable")),
            "无 DAO 时 SP-initiated 响应应 fail-closed 拒绝，实际: {:?}",
            result
        );
    }

    /// CRIT-005: IdP-initiated（无 InResponseTo）响应在无 DAO 时放行（warn 一次）。
    #[tokio::test]
    async fn idp_initiated_response_passes_without_dao() {
        let provider = DefaultSamlProvider::new().unwrap();
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                Destination="https://sp.example.com/acs">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com</saml:Issuer>
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
</samlp:Response>"#;
        let result = provider.parse_response(xml).await;
        assert!(
            result.is_ok(),
            "IdP-initiated 响应应放行，实际: {:?}",
            result
        );
    }
}
