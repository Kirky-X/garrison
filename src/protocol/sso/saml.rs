// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! SAML 2.0 协议支持骨架（`protocol-sso` feature）：核心数据结构（`SamlAssertion`/`SamlResponse`/`SamlRequest`）
//! 与 `SamlProvider` trait（`build_authn_request`/`parse_response`/`validate_assertion`）。
//!
//! `DefaultSamlProvider` 不执行 XML 签名验证：`validate_assertion` 返回 `NotImplemented`，
//! `parse_response` 对未验证 Assertion fail-closed 剥离（`assertion = None`）并告警——使用本
//! Provider 无法完成 SSO，生产须自行实现 `validate_assertion`（成熟签名库 + 证书信任链 + 算法
//! 白名单，禁 `rsa-1_5` 等弱算法）。
//!
//! `XmlSecSamlProvider`（`protocol-saml` feature）用 `rsa` 执行 RSA-SHA256 验签，`<ds:SignedInfo>`
//! 应用 Exclusive C14N 常用子集（注释剥离 / 自闭合展开 / 属性排序与空白规范化）；限制：命名空间声明
//! 不重写/不搬移、字符引用不展开，不满足时验签失败（fail-closed，不会错误放行）。
//! DigestValue 约定：被引用元素去除 Signature 子元素后的原始字节（隐式 enveloped-signature
//! transform），不做 C14N，仅与采用相同约定的 IdP/测试装置兼容。
//!
//! 已内置安全检查：NotOnOrAfter 过期校验（缺失即拒绝）、Assertion 重放防护
//! （[`check_assertion_replay`] 经 DAO 记录已消费 ID）、未验证 Assertion fail-closed 剥离、
//! quick-xml 纯 Rust 解析（不解析外部实体，无 XXE 风险）。

use crate::constants::DaoKeyPrefix;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// SAML 2.0 数据结构

/// SAML Assertion 结构（对应 `<saml:Assertion>`），IdP 签发的身份声明。
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
    /// 非空时必须晚于当前时间，未来生效的断言即刻使用将被拒绝。
    #[serde(default)]
    pub not_before: String,
    /// 属性集合（`<saml:AttributeStatement>` 中的键值对）。
    pub attributes: Vec<(String, String)>,
    /// Assertion 原始 XML（含 `<ds:Signature>`）：由 `parse_saml_response_xml` 填充，[`XmlSecSamlProvider::validate_assertion`] 依赖其验签；serde skip，反序列化恒为 `None`。
    #[serde(skip_serializing, skip_deserializing, default)]
    pub raw_xml: Option<String>,
}

/// SAML Response 结构（对应 `<samlp:Response>`），IdP 返回给 SP 的响应。
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
    /// SP 发起的 AuthnRequest ID（`InResponseTo` 属性，绑定校验用）。
    ///
    /// IdP-initiated（unsolicited）响应此字段为空。
    #[serde(default)]
    pub in_response_to: String,
}

/// SAML AuthnRequest 结构（对应 `<samlp:AuthnRequest>`），SP 发送给 IdP 的认证请求。
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

// SamlProvider trait

/// SAML 2.0 协议交互 trait：构建 AuthnRequest、解析 Response、验证 Assertion。
#[async_trait]
pub trait SamlProvider: Send + Sync {
    /// 构建 SAML AuthnRequest（`idp_sso_endpoint` 必传，避免生成的请求缺失 Destination）。
    async fn build_authn_request(
        &self,
        sp_entity_id: &str,
        acs_url: &str,
        idp_sso_endpoint: &str,
    ) -> GarrisonResult<SamlRequest>;

    /// 解析 SAML Response XML（输入为 base64 解码后的原始 XML，调用方负责解码）。
    async fn parse_response(&self, response_xml: &str) -> GarrisonResult<SamlResponse>;

    /// 验证 SAML Assertion 签名；默认实现返回 `NotImplemented`。
    async fn validate_assertion(&self, assertion: &SamlAssertion) -> GarrisonResult<bool>;
}

// DefaultSamlProvider

/// 默认 SAML Provider：基础 AuthnRequest 构建与 Response 解析；签名验证返回 `NotImplemented`（defer 到 [`XmlSecSamlProvider`]）。
///
/// 配置 [`Self::with_expected_destination`] / [`Self::with_expected_audience`] 后 `parse_response` 强制校验：
/// 不匹配返回 [`GarrisonError::InvalidParam`]（fail-loud），未配置仅告警（开发环境兼容）。
pub struct DefaultSamlProvider {
    /// 预期 Destination（SP 的 ACS URL）。None = 跳过验证（仅告警）。
    expected_destination: Option<String>,
    /// 预期 Audience（SP 的 entity_id）。None = 跳过验证（仅告警）。
    expected_audience: Option<String>,
    /// 可选 DAO：启用 InResponseTo 绑定校验与 Assertion 重放防护。
    request_dao: Option<std::sync::Arc<dyn crate::dao::GarrisonDao>>,
    /// 未配置 DAO 的 warn-once 标记。
    warned_no_dao: std::sync::atomic::AtomicBool,
}

impl DefaultSamlProvider {
    /// 创建实例（无 Destination / Audience 校验）；生产推荐显式配置预期值，或改用 [`XmlSecSamlProvider`]。
    pub fn new() -> GarrisonResult<Self> {
        Ok(Self {
            expected_destination: None,
            expected_audience: None,
            request_dao: None,
            warned_no_dao: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// 注入 DAO：启用 InResponseTo 绑定校验与 Assertion 重放防护（请求 ID 写入注册表，TTL 600 秒）。
    pub fn with_request_dao(mut self, dao: std::sync::Arc<dyn crate::dao::GarrisonDao>) -> Self {
        self.request_dao = Some(dao);
        self
    }

    /// 配置预期 Destination（SP 的 ACS URL），开启 Destination 校验。
    pub fn with_expected_destination(mut self, destination: String) -> Self {
        self.expected_destination = Some(destination);
        self
    }

    /// 配置预期 Audience（SP 的 entity_id），开启 Audience 校验。
    pub fn with_expected_audience(mut self, audience: String) -> Self {
        self.expected_audience = Some(audience);
        self
    }
}

impl Default for DefaultSamlProvider {
    fn default() -> Self {
        Self::new().expect("DefaultSamlProvider::new should not fail")
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
            // Destination 取调用方传入的 IdP SSO 端点
            destination: idp_sso_endpoint.to_string(),
            issuer: sp_entity_id.to_string(),
            assertion_consumer_service_url: acs_url.to_string(),
        };
        // 记录在途请求 ID 供 parse_response 绑定校验（TTL 600 秒）
        if let Some(d) = &self.request_dao {
            let key = format!("{}req:{}", DaoKeyPrefix::Saml, request.id);
            d.set(&key, "1", 600).await?;
        }
        Ok(request)
    }

    async fn parse_response(&self, response_xml: &str) -> GarrisonResult<SamlResponse> {
        // SAFETY: quick-xml 不解析外部实体，XXE 安全
        // SAML response 大小上限（防超大 payload 内存 DoS，真实 SAML Response 极少超 64KB）
        const SAML_RESPONSE_MAX_SIZE: usize = 64 * 1024;
        if response_xml.len() > SAML_RESPONSE_MAX_SIZE {
            return Err(GarrisonError::InvalidParam(format!(
                "saml-response-too-large::{}::{}",
                response_xml.len(),
                SAML_RESPONSE_MAX_SIZE
            )));
        }
        let mut response = parse_saml_response_xml(response_xml)?;

        // StatusCode 强制 Success（fail-closed，错误响应不得继续处理）
        validate_status_code(&response.status_code)?;

        // InResponseTo ↔ AuthnRequest 绑定校验
        enforce_in_response_to(
            self.request_dao.as_ref(),
            &self.warned_no_dao,
            &response.in_response_to,
        )
        .await?;

        // Destination 验证：本 Provider 恒剥离未验签 Assertion（fail-closed），故缺省 warn-only
        validate_destination(
            &response.destination,
            self.expected_destination.as_deref(),
            true,
        )?;

        // Audience 验证（fail-loud，仅在有 Assertion 时校验）
        if let Some(ref assertion) = response.assertion {
            validate_audience(&assertion.audience, self.expected_audience.as_deref(), true)?;
        }

        // DefaultSamlProvider 不实现签名验证（fail-closed 剥离 Assertion）
        if let Some(ref assertion) = response.assertion {
            match self.validate_assertion(assertion).await {
                Ok(true) => {
                    // 验签通过后强制重放检查（Assertion ID 一次性消费）
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
            "sso-saml-signature-not-implemented::".to_string(),
        ))
    }
}

// Destination / Audience 验证辅助

/// 校验 StatusCode 必须为 Success（fail-closed）：错误响应即使夹带 Assertion 也拒绝。
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

/// 校验 SAML Response 的 Destination：expected 非空须严格匹配（不匹配返回 [`GarrisonError::InvalidParam`]，fail-loud）；
/// 未配置且未豁免即拒绝（fail-closed）；`allow_unvalidated=true` 时告警放行（显式 opt-out，仅限开发环境）。
fn validate_destination(
    actual: &str,
    expected: Option<&str>,
    allow_unvalidated: bool,
) -> GarrisonResult<()> {
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
        _ if allow_unvalidated => {
            if !actual.is_empty() {
                tracing::warn!(
                    actual = %actual,
                    "SAML Destination validation opted out (allow_unvalidated_destination), open redirect attack risk"
                );
            }
            Ok(())
        },
        _ => Err(GarrisonError::InvalidParam(format!(
            "sso-saml-destination-not-configured::actual={}",
            actual
        ))),
    }
}

/// 校验 SAML Assertion 的 Audience：expected 非空须严格匹配（不匹配返回 [`GarrisonError::InvalidParam`]，fail-loud）；
/// 未配置且未豁免即拒绝（fail-closed）；`allow_unvalidated=true` 时告警放行（显式 opt-out，仅限开发环境）。
fn validate_audience(
    actual: &str,
    expected: Option<&str>,
    allow_unvalidated: bool,
) -> GarrisonResult<()> {
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
        _ if allow_unvalidated => {
            if !actual.is_empty() {
                tracing::warn!(
                    actual = %actual,
                    "SAML Audience validation opted out (allow_unvalidated_audience), cross-SP replay risk"
                );
            }
            Ok(())
        },
        _ => Err(GarrisonError::InvalidParam(format!(
            "sso-saml-audience-not-configured::actual={}",
            actual
        ))),
    }
}

// XML 解析辅助

/// SAML Response XML 解析上下文：收拢解析状态变量，主函数简化为 loop + dispatch
/// （`handle_start_element` / `handle_end_element` / `handle_empty_element` / `handle_text`）。
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

    // raw_xml 跟踪
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
                        "Destination" => {
                            self.destination = attr.value.to_string();
                        },
                        "InResponseTo" => {
                            self.in_response_to = attr.value.to_string();
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
                    if attr.key.as_ref() == "ID" {
                        self.assertion_id = attr.value.to_string();
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
                    if attr.key.as_ref() == "Name" {
                        self.current_attr_name = attr.value.to_string();
                    }
                }
            },
            "SubjectConfirmationData" => {
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == "NotOnOrAfter" {
                        self.assertion_not_on_or_after = attr.value.to_string();
                    }
                }
            },
            "Conditions" => {
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == "NotBefore" {
                        self.assertion_not_before = attr.value.to_string();
                    }
                }
            },
            _ => {
                tracing::trace!(element = %local_name, "saml-unknown-start-element");
            },
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
                    if attr.key.as_ref() == "Value" {
                        self.status_code = attr.value.to_string();
                    }
                }
            },
            "Conditions" => {
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == "NotBefore" {
                        self.assertion_not_before = attr.value.to_string();
                    }
                }
            },
            "SubjectConfirmationData" => {
                for attr in event.attributes().flatten() {
                    if attr.key.as_ref() == "NotOnOrAfter" {
                        self.assertion_not_on_or_after = attr.value.to_string();
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
                        "SAML Assertion contains duplicate attribute name, possible attribute pollution attack"
                    );
                }
                self.assertion_attributes
                    .push((self.current_attr_name.clone(), String::new()));
            },
            _ => {
                tracing::trace!(element = %local_name, "saml-unknown-empty-element");
            },
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
                    // 提取 <Assertion>...</Assertion> 原始 XML
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
                            "SAML Assertion contains duplicate attribute name, possible attribute pollution attack"
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
            _ => {
                tracing::trace!(element = %local_name, "saml-unknown-end-element");
            },
        }
    }

    /// 处理 Text 事件：累积文本到 `current_text`。
    fn handle_text(&mut self, text: &str) {
        self.current_text.push_str(text);
    }

    /// 构建 `SamlResponse` 并校验 Assertion 时间条件（fail-closed）。
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
            // NotBefore 校验：未来生效的断言不得即刻使用。
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

/// 提取 `<ds:Signature>` 原始 XML 并记录 `<Assertion>` 原始字节范围，供 [`XmlSecSamlProvider`] 验签。
///
/// quick-xml pull reader 解析，提取 Destination / Issuer / StatusCode / Assertion 字段。
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
                let text = e.as_ref().to_string();
                ctx.handle_text(&text);
            },
            _ => {},
        }
        buf.clear();
    }

    ctx.into_response()
}

/// 检查 SAML Assertion 是否被重放（生产环境应在 `parse_response` 后调用）：经 `dao.set_if_absent`
/// （语义等价 `SET NX EX`）单步原子预留，返回 `Ok(true)` 为首个消费者（键已写入、TTL = NotOnOrAfter
/// 剩余有效期，空或已过期用 300 秒兜底），`Ok(false)` 为已消费（重放拒绝）；原子性由 DAO 实现保证，
/// 跨进程后端应实现为 `SET NX EX` 或 Lua 脚本。
pub async fn check_assertion_replay(
    assertion_id: &str,
    not_on_or_after: &str,
    dao: &dyn crate::dao::GarrisonDao,
) -> GarrisonResult<bool> {
    if assertion_id.is_empty() {
        return Ok(true);
    }
    let key = format!("{}consumed:{}", DaoKeyPrefix::Saml, assertion_id);

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

    // 单步原子预留（SET NX 语义）：并发下仅首个请求返回 true
    let first = dao.set_if_absent(&key, "1", ttl).await?;
    Ok(first)
}

/// InResponseTo ↔ AuthnRequest ID 绑定校验：配置 DAO 时原子消费注册表条目（`saml:req:{id}`，TTL 600 秒），
/// 未命中即拒绝；未配置 DAO 时携带 InResponseTo 的响应 fail-closed 拒绝，IdP-initiated（无 InResponseTo）放行但 warn 一次。
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
                    "SAML request_dao not configured: InResponseTo binding and Assertion replay protection disabled"
                );
            }
            Ok(())
        },
    }
}

/// 提取 XML 元素的 local name（去除命名空间前缀）。
///
/// 例如 `samlp:Response` → `Response`，`saml:Issuer` → `Issuer`。
fn extract_local_name(qualified: &str) -> String {
    match qualified.rsplit_once(':') {
        Some((_, local)) => local.to_string(),
        None => qualified.to_string(),
    }
}

/// 检查 XML 限定名的命名空间前缀是否为 SAML 允许（`saml` / `samlp` / `ds` 或无前缀）；非法前缀（如 `evil:Assertion`）
/// 告警，防命名空间混淆攻击；返回前缀是否合法（调用方可跳过非法元素）。
fn check_saml_namespace(qualified: &str) -> bool {
    match qualified.rsplit_once(':') {
        Some((prefix, _)) => {
            let valid = matches!(prefix, "saml" | "samlp" | "ds");
            if !valid {
                tracing::warn!(
                    qualified = %qualified,
                    "SAML XML element uses non-standard namespace prefix, possible namespace confusion attack"
                );
            }
            valid
        },
        None => true,
    }
}

// XmlSecSamlProvider：SAML 签名验证实现（secure-saml feature）

/// SAML 签名算法标识 URI（XML-DSig 标准）。
#[cfg(feature = "protocol-saml")]
const SIG_ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
#[cfg(feature = "protocol-saml")]
const SIG_ALG_ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
/// 弱算法：rsa-1_5（PKCS#1 v1.5 无摘要，存在 Bleichenbacher 攻击风险）。
#[cfg(feature = "protocol-saml")]
const SIG_ALG_RSA_1_5: &str = "http://www.w3.org/2000/09/xmldsig#rsa-1_5";

/// 检查签名算法是否在白名单中：仅允许 RSA-SHA256 / ECDSA-SHA256，禁止 rsa-1_5 等弱算法；
/// ECDSA-SHA256 白名单通过但实际验证返回 `Ok(false)`（fail-closed，待引入 ECDSA 库后补全）。
#[cfg(all(feature = "protocol-saml", test))]
fn is_signature_algorithm_allowed(algorithm: &str) -> bool {
    matches!(algorithm, SIG_ALG_RSA_SHA256 | SIG_ALG_ECDSA_SHA256)
}

/// 提取 `<ds:SignatureMethod Algorithm="...">` 的 Algorithm 属性值（单双引号容错），找不到返回 None。
///
/// 有意用字符串查找而非 XML 解析（与 `extract_*` 函数风格一致；SAML 响应已由 quick-xml 上层解析）；
/// 防御：拒绝含 XML 特殊字符（`<`/`>`/`&`）的值，长度上限 128 字符。
#[cfg(feature = "protocol-saml")]
fn extract_signature_method_algorithm(signature_xml: &str) -> Option<String> {
    // 字符串查找 SignatureMethod 元素的 Algorithm 属性（兼容单/双引号）
    let method_start = signature_xml.find("<")?;
    let rest = &signature_xml[method_start..];
    let method_idx = rest.find("SignatureMethod")?;
    let after_method = &rest[method_idx..];
    let (alg_value_start, quote) = match (
        after_method.find("Algorithm=\""),
        after_method.find("Algorithm='"),
    ) {
        (Some(d), Some(s)) if s < d => (s + "Algorithm='".len(), '\''),
        (Some(d), _) => (d + "Algorithm=\"".len(), '"'),
        (None, Some(s)) => (s + "Algorithm='".len(), '\''),
        (None, None) => return None,
    };
    let after_alg = &after_method[alg_value_start..];
    let alg_end = after_alg.find(quote)?;
    let algorithm = &after_alg[..alg_end];

    // 安全防御：拒绝含 XML 特殊字符的 Algorithm 值（防注入）
    if algorithm.contains('<') || algorithm.contains('>') || algorithm.contains('&') {
        tracing::warn!("saml-algorithm-contains-xml-special-chars");
        return None;
    }
    // 安全防御：限制 Algorithm 值最大长度（标准 URI 通常 < 100 字符）
    if algorithm.len() > 128 {
        tracing::warn!(len = algorithm.len(), "saml-algorithm-exceeds-max-length");
        return None;
    }
    Some(algorithm.to_string())
}

/// 提取 `<ds:SignatureValue>` 的 base64 文本（支持带属性标签与混合前缀），找不到返回 None。
#[cfg(feature = "protocol-saml")]
fn extract_signature_value(signature_xml: &str) -> Option<String> {
    find_element_text_span(signature_xml, "SignatureValue")
}

/// 提取 `<ds:SignedInfo>...</ds:SignedInfo>` 原始 XML（含标签），验签前对其做 C14N 常用子集规范化；
/// 容错带属性标签与混合前缀形式，找不到返回 None。
#[cfg(feature = "protocol-saml")]
fn extract_signed_info_xml(assertion_xml: &str) -> Option<String> {
    find_element_span(assertion_xml, "SignedInfo")
        .map(|(start, end)| assertion_xml[start..end].to_string())
}

/// 提取 `<ds:Signature>...</ds:Signature>` 原始 XML（支持带属性标签与混合前缀），找不到返回 None。
#[cfg(feature = "protocol-saml")]
fn extract_signature_xml(assertion_xml: &str) -> Option<String> {
    find_element_span(assertion_xml, "Signature")
        .map(|(start, end)| assertion_xml[start..end].to_string())
}

/// Digest 算法 URI（XML-DSig 标准）：本实现仅支持 SHA-256。
#[cfg(feature = "protocol-saml")]
const DIGEST_ALG_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

/// SignedInfo 内单个 `<ds:Reference>` 绑定：XML-DSig 靠「SignedInfo → Reference URI → DigestValue」链条
/// 绑定内容，缺失任一环即签名与内容解耦（XSW 可伪造）。
#[cfg(feature = "protocol-saml")]
struct ReferenceBinding {
    /// `URI` 属性值，必须为 `#<element-id>` 形式。
    uri: String,
    /// `<ds:DigestMethod Algorithm="...">` 属性值。
    digest_method: Option<String>,
    /// `<ds:DigestValue>` base64 文本。
    digest_value_b64: String,
}

/// 提取 SignedInfo 内全部 `<ds:Reference>` 绑定。
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

/// 查找元素的完整 XML 片段范围（含起止标签），返回 `(start, end)` 字节偏移；找不到返回 None。
///
/// 容错：开始标签带属性、混合前缀（开始 `ds:` + 结束无前缀或反之，同前缀优先）均可配对；
/// 边界检查避免 `<ds:Signature` 误配 `<ds:SignedInfo` 这类更长标签名。
#[cfg(feature = "protocol-saml")]
fn find_element_span(xml: &str, local_name: &str) -> Option<(usize, usize)> {
    let prefixes = ["ds:", ""];
    for open_prefix in prefixes {
        let open = format!("<{}{}", open_prefix, local_name);
        // 对应的闭合标签候选：同前缀优先，其次另一前缀（混合前缀容错）
        let other = if open_prefix.is_empty() { "ds:" } else { "" };
        let closes = [
            format!("</{}{}>", open_prefix, local_name),
            format!("</{}{}>", other, local_name),
        ];

        let mut search_from = 0usize;
        while let Some(rel) = xml[search_from..].find(&open) {
            let abs = search_from + rel;
            // 边界检查：`<X` 之后必须是空白/`>`/`/`（避免匹配更长标签名）
            match xml[abs + open.len()..].chars().next() {
                Some(' ') | Some('>') | Some('/') | Some('\t') | Some('\n') | Some('\r') => {},
                _ => {
                    search_from = abs + 1;
                    continue;
                },
            }
            for close in &closes {
                if let Some(close_rel) = xml[abs..].find(close.as_str()) {
                    return Some((abs, abs + close_rel + close.len()));
                }
            }
            search_from = abs + 1;
        }
    }
    None
}

/// 查找元素的文本内容（首个匹配，去除前后空白；支持带属性标签与混合前缀），找不到返回 None。
#[cfg(feature = "protocol-saml")]
fn find_element_text_span(xml: &str, local_name: &str) -> Option<String> {
    let (start, end) = find_element_span(xml, local_name)?;
    let seg = &xml[start..end];
    // 内容 = 开始标签 `>` 之后到首个闭合标签 `</` 之前
    let gt = seg.find('>')?;
    let close_start = seg[gt..].find("</")? + gt;
    if close_start > gt {
        Some(seg[gt + 1..close_start].trim().to_string())
    } else {
        // `<X></X>`：空文本内容
        Some(String::new())
    }
}

/// 提取指定 local name 元素的文本内容（首个匹配，去除前后空白；兼容带属性标签与命名空间前缀）。
#[cfg(feature = "protocol-saml")]
fn extract_xml_text(xml: &str, local_name: &str) -> Option<String> {
    find_element_text_span(xml, local_name)
}

/// 提取被验元素切片根元素（位置 0 的开始标签）的限定名与 `ID` 属性值：验签输入恒以被验 Assertion
/// 开始标签开头，根元素 ID 即签名约束的主体；切片不以开始标签开头时返回 None（fail-closed）。
#[cfg(feature = "protocol-saml")]
fn root_element_identity(xml: &str) -> Option<(String, String)> {
    let bytes = xml.as_bytes();
    if bytes.first() != Some(&b'<') {
        return None;
    }
    let mut quote: Option<u8> = None;
    let mut i = 1usize;
    let gt = loop {
        if i >= bytes.len() {
            return None;
        }
        match quote {
            Some(q) => {
                if bytes[i] == q {
                    quote = None;
                }
            },
            None => {
                if bytes[i] == b'"' || bytes[i] == b'\'' {
                    quote = Some(bytes[i]);
                } else if bytes[i] == b'>' {
                    break i;
                }
            },
        }
        i += 1;
    };
    let (qname, attrs) = parse_tag_inner(&xml[1..gt]);
    if qname.is_empty() || qname.starts_with('!') || qname.starts_with('?') {
        return None;
    }
    let id = attrs
        .iter()
        .find(|(k, _)| k == "ID")
        .map(|(_, v)| v.clone())?;
    Some((qname, id))
}

/// 计算以位置 0 为根的元素完整字节范围（含起止标签），基于同限定名嵌套深度；自闭合标签不影响深度。
///
/// 摘要计算必须锚定切片根元素而非全文档 `ID="..."` 字符串扫描：CDATA 内的同限定名字面量
/// 无法改变「根元素从位置 0 开始」这一事实，避免 XSW CDATA 隐藏变体劫持摘要计算。
#[cfg(feature = "protocol-saml")]
fn root_element_span(xml: &str, qname: &str) -> Option<(usize, usize)> {
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
    let mut pos = 0usize;
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
            return Some((0, pos));
        }
    }
}

/// 剥离元素切片内首个 `<ds:Signature>` 块（隐式 enveloped-signature transform）：
/// 摘要输入约定为被引用元素去除自身 Signature 子元素后的原始字节，签名方与验证方须一致。
#[cfg(feature = "protocol-saml")]
fn strip_enveloped_signature(element_xml: &str) -> String {
    match extract_signature_xml(element_xml) {
        Some(sig) => element_xml.replacen(&sig, "", 1),
        None => element_xml.to_string(),
    }
}

// SignedInfo C14N 规范化（Exclusive C14N 常用子集）

/// 对 SignedInfo XML 做 Exclusive C14N 常用子集规范化，输出作为签名验证输入：
/// 移除注释（无注释模式）、自闭合标签展开、属性按限定名排序并统一双引号/空白，文本节点原样保留。
///
/// 限制（fail-closed）：命名空间声明不重写/不搬移、字符引用不展开——若 IdP 依赖完整 C14N，
/// 规范化输出与其签名输入不一致将验签失败（拒绝而非错误放行）。
#[cfg(feature = "protocol-saml")]
fn canonicalize_signed_info_c14n_subset(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < input.len() {
        // 1. 注释移除（无注释模式）
        if input[i..].starts_with("<!--") {
            match input[i + 4..].find("-->") {
                Some(end) => i += 4 + end + 3,
                None => i = input.len(), // 未闭合注释：丢弃剩余（畸形输入，验签将失败）
            }
            continue;
        }
        if bytes[i] == b'<' {
            match input[i..].find('>') {
                Some(gt_rel) => {
                    let inner_raw = &input[i + 1..i + gt_rel];
                    if let Some(rest) = inner_raw.strip_prefix('/') {
                        // 结束标签：`</ name >` → `</name>`
                        out.push_str("</");
                        out.push_str(rest.trim());
                        out.push('>');
                    } else {
                        let self_closing = inner_raw.ends_with('/');
                        let inner = inner_raw.trim_end_matches('/').trim();
                        let (qname, attrs) = parse_tag_inner(inner);
                        // 2 + 3：自闭合展开 + 属性排序/规范化
                        out.push('<');
                        out.push_str(&qname);
                        let mut attrs = attrs;
                        attrs.sort_by(|a, b| a.0.cmp(&b.0));
                        for (k, v) in attrs {
                            out.push(' ');
                            out.push_str(&k);
                            out.push_str("=\"");
                            out.push_str(&v);
                            out.push('"');
                        }
                        if self_closing {
                            out.push_str("></");
                            out.push_str(&qname);
                            out.push('>');
                        } else {
                            out.push('>');
                        }
                    }
                    i += gt_rel + 1;
                    continue;
                },
                None => {
                    // 未闭合标签：原样保留剩余（畸形输入，验签将失败）
                    out.push_str(&input[i..]);
                    i = input.len();
                },
            }
        } else {
            // 文本节点：原样保留到下一个 '<'
            let lt = input[i..].find('<').map(|p| i + p).unwrap_or(input.len());
            out.push_str(&input[i..lt]);
            i = lt;
        }
    }
    out
}

/// 解析开始标签内部（不含尖括号），返回 `(限定名, 属性列表)`；属性值支持双/单引号，属性间空白规范化。
#[cfg(feature = "protocol-saml")]
fn parse_tag_inner(inner: &str) -> (String, Vec<(String, String)>) {
    let inner = inner.trim();
    let (qname, rest) = match inner.find(|c: char| c.is_whitespace()) {
        Some(ws) => (inner[..ws].to_string(), &inner[ws..]),
        None => (inner.to_string(), ""),
    };
    let mut attrs: Vec<(String, String)> = Vec::new();
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // 属性名（到 '=' 或空白）
        let name_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let name = rest[name_start..i].to_string();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let quote = bytes[i];
                i += 1;
                let vstart = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                let value = rest[vstart..i].to_string();
                if i < bytes.len() {
                    i += 1;
                }
                attrs.push((name, value));
            } else {
                // 无引号值（畸形输入）：取到下一个空白
                let vstart = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                attrs.push((name, rest[vstart..i].to_string()));
            }
        } else {
            // 无值属性（畸形输入）
            attrs.push((name, String::new()));
        }
    }
    (qname, attrs)
}

/// 校验单个 Reference 绑定（XSW 双防线）：URI 必须为 `#<被验 Assertion 根元素 ID>`（指向他处或无 URI 即拒绝），
/// 摘要输入锚定为被验切片根元素子树（不做全文 `ID="..."` 扫描），比对用常量时间比较（subtle `ct_ne`，防时序侧信道）；返回 Err(reason) 表示绑定失败（调用方应拒绝验签）。
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
    // 切片头部可能带事件间空白（quick-xml trim_text_start 在读取 Start 事件时才
    // 跳过空白，而起始位置在跳过前记录），先修剪再锚定，保证切片以根元素开始标签开头。
    let xml = document_xml.trim_start();
    let Some((root_qname, root_id)) = root_element_identity(xml) else {
        return Err("verified-root-element-not-found");
    };
    if root_id != id {
        return Err("reference-uri-not-anchored-to-verified-assertion");
    }
    let Some((start, end)) = root_element_span(xml, &root_qname) else {
        return Err("referenced-element-not-found");
    };
    let element_raw = &xml[start..end];

    use base64::Engine as _;
    use rsa::sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    let stripped = strip_enveloped_signature(element_raw);
    let computed = Sha256::digest(stripped.as_bytes());
    let expected = base64::engine::general_purpose::STANDARD
        .decode(binding.digest_value_b64.trim())
        .map_err(|_| "digest-value-base64-decode")?;

    if expected.len() != computed.len() || expected.as_slice().ct_ne(&computed).into() {
        return Err("digest-value-mismatch");
    }
    Ok(())
}

/// 验证 SAML Assertion 的 XML 签名：提取 `<ds:Signature>` → 校验 SignatureMethod 算法白名单 →
/// 解码 `<ds:SignatureValue>` → 规范化 `<ds:SignedInfo>` → IdP 公钥验证 RSA-SHA256 签名 →
/// 校验 Reference/DigestValue 绑定链。
///
/// 返回 `Ok(false)` 表示签名缺失 / 算法不在白名单 / 签名或摘要不匹配；`Err` 为公钥解析或解码失败。
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
                "SAML signature algorithm ecdsa-sha256 is whitelisted but verification is not implemented yet (awaiting an ECDSA library)"
            );
            return Ok(false);
        },
        Some(alg) if alg == SIG_ALG_RSA_1_5 => {
            tracing::warn!(
                algorithm = %alg,
                "SAML signature algorithm rsa-1_5 rejected (weak algorithm, Bleichenbacher attack risk)"
            );
            return Ok(false);
        },
        Some(alg) => {
            tracing::warn!(
                algorithm = %alg,
                "SAML signature algorithm not whitelisted (only rsa-sha256 / ecdsa-sha256 allowed)"
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

    // 4. 提取 <ds:SignedInfo> 原始 XML
    let signed_info_xml = match extract_signed_info_xml(assertion_xml) {
        Some(xml) => xml,
        None => {
            tracing::warn!("SAML Assertion missing <ds:SignedInfo>");
            return Ok(false);
        },
    };

    // C14N 防御（fail-closed）：SignedInfo 不应含注释（C14N 无注释模式会剥离注释，
    // 攻击者可借注释差异构造语义不明的签名输入），出现即拒绝。
    if signed_info_xml.contains("<!--") {
        tracing::warn!(
            "SAML <ds:SignedInfo> contains XML comments, rejected (C14N no-comments mode)"
        );
        return Ok(false);
    }

    // C14N 规范化：XML-DSig 要求验证输入为 canonicalized SignedInfo 而非原始字节；此处用常用子集
    // （注释剥离/自闭合展开/属性排序与空白规范化）消除属性顺序等非语义差异，限制见函数文档（fail-closed）。
    let signed_info_canonical = canonicalize_signed_info_c14n_subset(&signed_info_xml);
    tracing::warn!(
        "SAML signature verification uses a common-subset Exclusive C14N for <ds:SignedInfo> \
         (namespace rewriting not implemented). If your IdP relies on full inclusive C14N, \
         verification may fail (fail-closed). See canonicalize_signed_info_c14n_subset docs."
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
    match verifying_key.verify(signed_info_canonical.as_bytes(), &signature) {
        Ok(()) => {},
        Err(_) => {
            tracing::warn!(
                "SAML signature verification failed: signature value does not match SignedInfo"
            );
            return Ok(false);
        },
    }

    // 6. DigestValue 校验链——签名仅对 Reference 绑定的元素背书。
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

/// 基于 XML-DSig 的 SAML Provider：用 `rsa` crate 验证 Assertion 的 RSA-SHA256 签名；
/// 算法白名单仅允许 `rsa-sha256` / `ecdsa-sha256`，禁止 `rsa-1_5` 等弱算法（ECDSA 白名单内但未实现验证，返回 `Ok(false)`）。
///
/// Destination / Audience 未配置时默认拒绝（fail-closed，跨 SP 断言重放防护）：生产部署必须
/// [`with_expected_destination`](Self::with_expected_destination) + [`with_expected_audience`](Self::with_expected_audience)
/// 显式配置；开发/测试可经 [`allow_unvalidated_destination`](Self::allow_unvalidated_destination) /
/// [`allow_unvalidated_audience`](Self::allow_unvalidated_audience) 显式豁免（warn 后放行，风险自担）。
#[cfg(feature = "protocol-saml")]
pub struct XmlSecSamlProvider {
    /// IdP RSA 公钥 PEM（PKCS#8 或 PKCS#1），用于验证 Assertion 签名。
    idp_public_key_pem: String,
    /// 预期 Destination（SP 的 ACS URL）。None = 未配置 → 拒绝（fail-closed），除非显式豁免。
    expected_destination: Option<String>,
    /// 预期 Audience（SP 的 entity_id）。None = 未配置 → 拒绝（fail-closed），除非显式豁免。
    expected_audience: Option<String>,
    /// Destination 校验豁免标记（显式 opt-out，缺省 false = fail-closed）。
    allow_unvalidated_destination: bool,
    /// Audience 校验豁免标记（显式 opt-out，缺省 false = fail-closed）。
    allow_unvalidated_audience: bool,
    /// 可选 DAO：启用 InResponseTo 绑定校验与 Assertion 重放防护。
    request_dao: Option<std::sync::Arc<dyn crate::dao::GarrisonDao>>,
    /// 未配置 DAO 的 warn-once 标记。
    warned_no_dao: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "protocol-saml")]
impl XmlSecSamlProvider {
    /// 创建实例：`idp_public_key_pem` 为 IdP RSA 公钥 PEM（PKCS#8 或 PKCS#1，通常从 IdP 元数据
    /// `<ds:X509Certificate>` 提取转换）；构造期预解析公钥 fail-fast，格式无效返回 `InvalidParam`。
    pub fn new(idp_public_key_pem: String) -> GarrisonResult<Self> {
        // 预解析公钥，fail-fast 避免每次 validate_assertion 才报错
        let _ = parse_rsa_public_key(&idp_public_key_pem)?;
        Ok(Self {
            idp_public_key_pem,
            expected_destination: None,
            expected_audience: None,
            allow_unvalidated_destination: false,
            allow_unvalidated_audience: false,
            request_dao: None,
            warned_no_dao: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// 配置 DAO，启用 InResponseTo 绑定校验与 Assertion 重放防护。
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

    /// 显式豁免 Destination 校验（opt-out 出口）：不匹配的响应仅告警放行，存在 open redirect 风险，
    /// 仅限开发/测试环境；生产必须改用 [`with_expected_destination`](Self::with_expected_destination)。
    #[must_use = "豁免 Destination 校验属显式安全决策，返回值必须被消费"]
    pub fn allow_unvalidated_destination(mut self) -> Self {
        self.allow_unvalidated_destination = true;
        self
    }

    /// 显式豁免 Audience 校验（opt-out 出口）：受众为其他 SP 的签名合法断言将被接受（跨 SP 重放风险），
    /// 仅限开发/测试环境；生产必须改用 [`with_expected_audience`](Self::with_expected_audience)。
    #[must_use = "豁免 Audience 校验属显式安全决策，返回值必须被消费"]
    pub fn allow_unvalidated_audience(mut self) -> Self {
        self.allow_unvalidated_audience = true;
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
        // 记录在途请求 ID 供 parse_response 绑定校验（TTL 600 秒）
        if let Some(d) = &self.request_dao {
            let key = format!("{}req:{}", DaoKeyPrefix::Saml, request.id);
            d.set(&key, "1", 600).await?;
        }
        Ok(request)
    }

    async fn parse_response(&self, response_xml: &str) -> GarrisonResult<SamlResponse> {
        // SAFETY: quick-xml 不解析外部实体，XXE 安全
        // SAML response 大小上限（防超大 payload 内存 DoS，真实 SAML Response 极少超 64KB）
        const SAML_RESPONSE_MAX_SIZE: usize = 64 * 1024;
        if response_xml.len() > SAML_RESPONSE_MAX_SIZE {
            return Err(GarrisonError::InvalidParam(format!(
                "saml-response-too-large::{}::{}",
                response_xml.len(),
                SAML_RESPONSE_MAX_SIZE
            )));
        }
        let mut response = parse_saml_response_xml(response_xml)?;

        // StatusCode 强制 Success（fail-closed，错误响应不得继续处理）
        validate_status_code(&response.status_code)?;

        // InResponseTo ↔ AuthnRequest 绑定校验
        enforce_in_response_to(
            self.request_dao.as_ref(),
            &self.warned_no_dao,
            &response.in_response_to,
        )
        .await?;

        // Destination 验证（fail-loud；未配置且未豁免时 fail-closed 拒绝）
        validate_destination(
            &response.destination,
            self.expected_destination.as_deref(),
            self.allow_unvalidated_destination,
        )?;

        // Audience 验证（fail-loud，仅在有 Assertion 时校验；未配置且未豁免时 fail-closed 拒绝）
        if let Some(ref assertion) = response.assertion {
            validate_audience(
                &assertion.audience,
                self.expected_audience.as_deref(),
                self.allow_unvalidated_audience,
            )?;
        }

        // 验证 Assertion 签名（真实 RSA-SHA256 验证）
        if let Some(ref assertion) = response.assertion {
            match self.validate_assertion(assertion).await {
                Ok(true) => {
                    // 验签通过后强制重放检查（Assertion ID 一次性消费）
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

    // 数据结构测试

    /// SamlAssertion 序列化/反序列化往返（所有结构实现 Serialize/Deserialize）。
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

    /// SamlResponse 序列化/反序列化往返。
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

    /// SamlRequest 序列化/反序列化往返。
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

    /// SamlAssertion 实现 Clone + Debug（验收标准）。
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

    // DefaultSamlProvider 测试

    /// DefaultSamlProvider::new() 返回可用实例（验收标准）。
    #[test]
    fn default_saml_provider_new_returns_ok() {
        let provider = DefaultSamlProvider::new();
        assert!(provider.is_ok());
    }

    /// SamlProvider trait 编译验证：DefaultSamlProvider 实现 SamlProvider trait。
    #[test]
    fn default_saml_provider_implements_saml_provider() {
        fn assert_saml_provider<T: SamlProvider>(_provider: &T) {}
        let provider = DefaultSamlProvider::new().unwrap();
        assert_saml_provider(&provider);
    }

    /// build_authn_request 返回包含正确字段的 SamlRequest。
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
        // destination 应为 IdP SSO 端点（不再为空）
        assert_eq!(request.destination, "https://idp.example.com/sso");
        assert!(!request.id.is_empty());
        assert!(!request.issue_instant.is_empty());
    }

    /// build_authn_request 生成唯一 id（每次调用不同）。
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

    /// parse_response 解析成功响应：validate_assertion 返回 NotImplemented 时 fail-closed 剥离 Assertion
    /// （不返回未验证的 Assertion），XML 字段（destination / issuer / status_code）仍正常解析。
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

    /// 非 Success 状态码的 Response 返回 InvalidParam（fail-closed）。
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

    /// 非 Success 响应夹带 Assertion 也必须拒绝（不得当作成功登录处理）。
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

    /// 非 SAML XML 输入：解析层返回空字段，但空 status_code 不等于 Success，provider 层 fail-closed 拒绝（InvalidParam）。
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

    /// 过期的 SAML Assertion（NotOnOrAfter < now）返回 InvalidToken 错误。
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

    /// 未过期的 SAML Assertion（NotOnOrAfter > now）正常解析（NotOnOrAfter 校验通过，不报错；
    /// 未验证的 Assertion 仍会被 fail-closed 剥离）。
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

    /// validate_assertion 返回 NotImplemented（签名验证 defer）。
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

    // 断言重放防护测试

    /// 同一 Assertion ID 首次消费通过，二次拒绝。
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

    /// 不同 Assertion ID 互不影响（隔离性）。
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

    /// 空 Assertion ID 放行（无法做重放检查）。
    #[tokio::test]
    async fn check_assertion_replay_empty_id_passes() {
        let dao = crate::dao::tests::MockDao::new();
        let result = check_assertion_replay("", "", &dao)
            .await
            .expect("空 ID 不应报错");
        assert!(result, "空 Assertion ID 应放行（无法做重放检查）");
    }

    // 辅助函数测试

    /// extract_local_name 正确去除命名空间前缀。
    #[test]
    fn extract_local_name_strips_namespace() {
        assert_eq!(extract_local_name("samlp:Response"), "Response");
        assert_eq!(extract_local_name("saml:Issuer"), "Issuer");
        assert_eq!(extract_local_name("Assertion"), "Assertion");
    }

    // SAML 命名空间强制测试

    /// check_saml_namespace 接受合法前缀（saml/samlp/ds/无前缀）。
    #[test]
    fn check_saml_namespace_accepts_valid_prefixes() {
        assert!(check_saml_namespace("samlp:Response"));
        assert!(check_saml_namespace("saml:Assertion"));
        assert!(check_saml_namespace("saml:Issuer"));
        assert!(check_saml_namespace("ds:Signature"));
        assert!(check_saml_namespace("Response")); // 无前缀
        assert!(check_saml_namespace("Assertion")); // 无前缀
    }

    /// check_saml_namespace 拒绝非标准前缀（evil/foo/xs 等）。
    #[test]
    fn check_saml_namespace_rejects_invalid_prefixes() {
        assert!(!check_saml_namespace("evil:Assertion"));
        assert!(!check_saml_namespace("foo:Response"));
        assert!(!check_saml_namespace("xs:Issuer"));
        assert!(!check_saml_namespace("attack:Attribute"));
    }

    /// 非标准命名空间的 Assertion 被跳过（不解析为 Assertion）。
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

    // SAML 属性污染告警测试

    /// 重复属性名的 Assertion 仍被解析（两个值都保留），但应触发告警。
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

    // Destination / Audience 验证测试

    /// Destination 匹配时 parse_response 通过。
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

    /// Destination 不匹配时 parse_response 返回 InvalidParam（fail-loud）。
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

    /// Audience 不匹配时 parse_response 返回 InvalidParam（fail-loud）。
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

    /// validate_destination / validate_audience 辅助函数单元测试。
    #[test]
    fn validate_destination_audience_unit_tests() {
        assert!(validate_destination("https://sp/acs", Some("https://sp/acs"), false).is_ok());
        assert!(matches!(
            validate_destination("https://evil/acs", Some("https://sp/acs"), false),
            Err(GarrisonError::InvalidParam(_))
        ));
        // Destination 未配置（None / Some("")）→ fail-closed 拒绝，
        // 显式豁免（allow_unvalidated=true）→ Ok + warn
        assert!(matches!(
            validate_destination("https://sp/acs", None, false),
            Err(GarrisonError::InvalidParam(ref m)) if m.contains("sso-saml-destination-not-configured")
        ));
        assert!(matches!(
            validate_destination("https://sp/acs", Some(""), false),
            Err(GarrisonError::InvalidParam(ref m)) if m.contains("sso-saml-destination-not-configured")
        ));
        assert!(validate_destination("https://sp/acs", None, true).is_ok());
        assert!(validate_destination("https://sp/acs", Some(""), true).is_ok());

        assert!(validate_audience("https://sp", Some("https://sp"), false).is_ok());
        assert!(matches!(
            validate_audience("https://evil", Some("https://sp"), false),
            Err(GarrisonError::InvalidParam(_))
        ));
        // Audience 未配置（None / Some("")）→ fail-closed 拒绝，
        // 显式豁免 → Ok + warn
        assert!(matches!(
            validate_audience("https://sp", None, false),
            Err(GarrisonError::InvalidParam(ref m)) if m.contains("sso-saml-audience-not-configured")
        ));
        assert!(matches!(
            validate_audience("https://sp", Some(""), false),
            Err(GarrisonError::InvalidParam(ref m)) if m.contains("sso-saml-audience-not-configured")
        ));
        assert!(validate_audience("https://sp", None, true).is_ok());
    }

    // 签名算法白名单测试（仅 secure-saml feature 下编译）

    #[cfg(feature = "protocol-saml")]
    mod signature_tests {
        use super::*;

        /// 签名算法白名单允许强算法（rsa-sha256 / ecdsa-sha256）。
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

        /// 签名算法白名单拒绝弱算法（rsa-1_5）和未知算法。
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

        // RSA-SHA256 签名验证测试

        /// 构造测试用 SAML Assertion XML（含完整 XML-DSig `<ds:Signature>`），返回 (assertion_xml, public_key_pem)：
        /// SignedInfo 含 `<ds:Reference URI="#id">` 与 SHA-256 DigestValue（完整校验链）；
        /// DigestValue = SHA256(被引用元素去除 Signature 子元素后的原始字节)，与 `strip_enveloped_signature` 约定一致。
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

            // rsa 0.9 基于 rand_core 0.6，rand 0.10 的 RNG trait 不兼容，用 rsa::rand_core::OsRng
            let mut rng = rsa::rand_core::OsRng;
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

        /// XSW 攻击防护：攻击者把合法 `<ds:Signature>` 拷贝进自己控制的 Assertion（NameID=admin），
        /// 试图让有效签名为伪造内容背书；验签必须拒绝（签名仅对 DigestValue 绑定的原始元素有效）。
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

        /// SAML XSW「CDATA 隐藏变体」回归测试：伪造 Assertion 内嵌入 (a) 受害者合法 `<ds:Signature>` 拷贝
        /// (b) `<![CDATA[受害者完整断言原文]]>`——quick-xml 不解析 CDATA（业务字段为伪造值），纯字符串扫描
        /// 却能在 CDATA 内命中被引用元素使 digest/签名全过。验签必须拒绝：URI 须锚定被验 Assertion 根元素
        /// 自身 ID，摘要计算锚定根元素子树。
        ///
        /// 返回 (evil_assertion_xml, victim_public_key_pem)。
        fn build_xsw_cdata_evil_assertion() -> (String, String) {
            let (victim_xml, public_key_pem) = build_test_signed_assertion();
            let sig_start = victim_xml
                .find("<ds:Signature>")
                .expect("victim fixture 应含 Signature");
            let sig_end = victim_xml
                .find("</ds:Signature>")
                .expect("victim fixture 应含 Signature 闭合")
                + "</ds:Signature>".len();
            let stolen_signature = victim_xml[sig_start..sig_end].to_string();

            // 伪造断言自带未来 NotOnOrAfter：排除解析层过期/缺失校验先拒的干扰，
            // 使端到端拒绝确实落在验签层（Reference 锚定/摘要校验）。
            let future = chrono::Utc::now().timestamp() + 3600;
            let future_str = chrono::DateTime::from_timestamp(future, 0)
                .unwrap()
                .to_rfc3339();

            let evil_xml = format!(
                r#"<Assertion ID="evil-cdata-xsw"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>admin@evil.test</saml:NameID><saml:SubjectConfirmationData NotOnOrAfter="{future_str}"/></saml:Subject>{}<![CDATA[{}]]><saml:Attribute Name="role"><saml:AttributeValue>super-admin</saml:AttributeValue></saml:Attribute></Assertion>"#,
                stolen_signature, victim_xml
            );
            (evil_xml, public_key_pem)
        }

        /// CDATA 隐藏变体：Reference 指向 CDATA 内受害者元素（非根元素）必须被拒。
        #[test]
        fn verify_saml_signature_rejects_xsw_cdata_hidden_variant() {
            let (evil_xml, public_key_pem) = build_xsw_cdata_evil_assertion();
            let result = verify_saml_signature(&evil_xml, &public_key_pem);
            assert!(
                result.is_ok(),
                "XSW 检测不应报错，应返回 Ok(false): {:?}",
                result
            );
            assert!(
                !result.unwrap(),
                "XSW CDATA 变体：拷贝的受害者签名不得为伪造断言背书"
            );
        }

        /// CDATA 隐藏变体（同 ID 变体）：伪造断言 ID 与受害者 ID 相同时，
        /// URI 锚定检查通过，但摘要必须锚定根元素子树——伪造内容 digest 不匹配。
        #[test]
        fn verify_saml_signature_rejects_xsw_cdata_same_id_variant() {
            let (victim_xml, public_key_pem) = build_test_signed_assertion();
            let sig_start = victim_xml
                .find("<ds:Signature>")
                .expect("victim fixture 应含 Signature");
            let sig_end = victim_xml
                .find("</ds:Signature>")
                .expect("victim fixture 应含 Signature 闭合")
                + "</ds:Signature>".len();
            let stolen_signature = victim_xml[sig_start..sig_end].to_string();
            // 伪造断言沿用受害者 ID（URI 锚定检查可过），内容为攻击者任意身份
            let evil_xml = format!(
                r#"<Assertion ID="_test-assertion-001"><saml:Subject><saml:NameID>admin@evil.test</saml:NameID></saml:Subject>{}<![CDATA[{}]]></Assertion>"#,
                stolen_signature, victim_xml
            );
            let result = verify_saml_signature(&evil_xml, &public_key_pem);
            assert!(result.is_ok(), "不应报错，应返回 Ok(false): {:?}", result);
            assert!(
                !result.unwrap(),
                "同 ID CDATA 变体：根子树摘要必须不匹配伪造内容"
            );
        }

        /// 合法 RSA-SHA256 签名应验证通过。
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

        /// 用错误公钥验证签名应返回 Ok(false)（签名不匹配）。
        #[test]
        fn verify_saml_signature_rejects_wrong_public_key() {
            use rsa::pkcs8::EncodePublicKey;
            let (xml, _original_public_pem) = build_test_signed_assertion();
            // 生成另一个密钥对的公钥
            // rsa 0.9 基于 rand_core 0.6，rand 0.10 的 RNG trait 不兼容，用 rsa::rand_core::OsRng
            let mut rng = rsa::rand_core::OsRng;
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

        /// 篡改 SignedInfo 内容后签名应验证失败。
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

        /// 缺少 <ds:Signature> 元素应返回 Ok(false)。
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

        /// rsa-1_5 算法应被白名单拒绝（返回 Ok(false)）。
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

        /// 非法公钥 PEM 应返回 Err（fail-loud）。
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

        // Assertion 重放防护接线（端到端）

        /// XmlSecSamlProvider 端到端——同一签名 Assertion 二次提交被重放防护拒绝。
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
                .with_request_dao(dao)
                // 本用例聚焦重放防护，Destination/Audience 显式豁免
                .allow_unvalidated_destination()
                .allow_unvalidated_audience();

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

        // Destination / Audience 缺省 fail-closed

        /// 构造带未来 NotOnOrAfter 与 Audience 的签名 Assertion Response
        /// （XmlSecSamlProvider e2e 用；extra 内容纳入 DigestValue 计算）。
        fn build_xsec_signed_response() -> (String, String) {
            let future = Utc::now().timestamp() + 3600;
            let future_str = chrono::DateTime::from_timestamp(future, 0)
                .unwrap()
                .to_rfc3339();
            let (signed_assertion, public_key_pem) = build_test_signed_assertion_with_inner(
                &format!(
                    "<SubjectConfirmationData NotOnOrAfter=\"{future_str}\"/>\
<saml:Conditions><saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction></saml:Conditions>"
                ),
            );
            let xml = format!(
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
  {signed_assertion}
</samlp:Response>"#
            );
            (xml, public_key_pem)
        }

        /// 缺省构造（未配置 Destination）→ fail-closed 拒绝（sso-saml-destination-not-configured，不再 warn 放行）。
        #[tokio::test]
        async fn xmlsec_provider_default_rejects_unconfigured_destination() {
            let (xml, public_key_pem) = build_xsec_signed_response();
            let provider = XmlSecSamlProvider::new(public_key_pem).unwrap();
            let result = provider.parse_response(&xml).await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("sso-saml-destination-not-configured")),
                "缺省未配置 Destination 应 fail-closed 拒绝，实际: {:?}",
                result
            );
        }

        /// 仅豁免 Destination（Audience 仍缺省）→ fail-closed 拒绝（sso-saml-audience-not-configured）。
        #[tokio::test]
        async fn xmlsec_provider_default_rejects_unconfigured_audience() {
            let (xml, public_key_pem) = build_xsec_signed_response();
            let provider = XmlSecSamlProvider::new(public_key_pem)
                .unwrap()
                .allow_unvalidated_destination();
            let result = provider.parse_response(&xml).await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidParam(ref m)) if m.contains("sso-saml-audience-not-configured")),
                "缺省未配置 Audience 应 fail-closed 拒绝，实际: {:?}",
                result
            );
        }

        /// 显式配置 expected_audience/expected_destination → 签名合法断言放行（缺省收紧不得破坏显式配置的正常路径）。
        #[tokio::test]
        async fn xmlsec_provider_with_expected_config_accepts_signed_assertion() {
            let (xml, public_key_pem) = build_xsec_signed_response();
            let provider = XmlSecSamlProvider::new(public_key_pem)
                .unwrap()
                .with_expected_destination("https://sp.example.com/acs".to_string())
                .with_expected_audience("https://sp.example.com".to_string());
            let response = provider.parse_response(&xml).await.unwrap();
            let assertion = response.assertion.expect("显式配置 + 签名合法断言应保留");
            assert_eq!(assertion.subject, "user@example.com");
        }

        /// 显式 opt-out（allow_unvalidated_*）→ warn 放行（开发/测试场景出口）。
        #[tokio::test]
        async fn xmlsec_provider_allow_unvalidated_opt_out_passes_signed_assertion() {
            let (xml, public_key_pem) = build_xsec_signed_response();
            let provider = XmlSecSamlProvider::new(public_key_pem)
                .unwrap()
                .allow_unvalidated_destination()
                .allow_unvalidated_audience();
            let response = provider.parse_response(&xml).await.unwrap();
            assert!(
                response.assertion.is_some(),
                "显式豁免 Destination/Audience 后签名合法断言应放行"
            );
        }

        /// XSW CDATA 隐藏变体端到端：伪造断言（拷贝的受害者签名 + CDATA 包裹的受害者断言）经完整
        /// parse_response 流程后必须被拒（断言剥离或整体拒绝），伪造 subject/attributes 不得存活。
        #[tokio::test]
        async fn xmlsec_provider_rejects_xsw_cdata_forged_assertion() {
            let (evil_assertion, public_key_pem) = build_xsw_cdata_evil_assertion();
            let xml = format!(
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <Status><StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></Status>
  {evil_assertion}
</samlp:Response>"#
            );

            let dao = std::sync::Arc::new(crate::dao::tests::MockDao::new());
            let provider = XmlSecSamlProvider::new(public_key_pem)
                .unwrap()
                .with_request_dao(dao)
                .with_expected_destination("https://sp.example.com/acs".to_string())
                .allow_unvalidated_audience();

            let out = provider.parse_response(&xml).await;
            match out {
                Ok(resp) => {
                    let a = resp.assertion.as_ref();
                    assert!(
                        a.is_none(),
                        "XSW CDATA 变体断言必须被剥离，实际保留: subject={:?} attrs={:?}",
                        a.map(|x| &x.subject),
                        a.map(|x| &x.attributes)
                    );
                },
                Err(e) => {
                    // 整体拒绝同样可接受（fail-closed），但必须是签名/绑定类错误
                    let msg = format!("{e:?}");
                    assert!(
                        !msg.contains("not-configured"),
                        "本用例已显式配置校验，不应因缺省配置拒绝: {msg}"
                    );
                },
            }
        }
    }

    // 并发重放防护测试

    /// 并发场景下 `set_if_absent` 原子性验证：10 个并发调用不应 panic / 报错，
    /// 至少一个成功消费（Ok(true)）且至少一个被拒绝（Ok(false)）。
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
        // 至少一个成功 + 一个失败（证明 set_if_absent 原子性生效）
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

    /// 串行场景下重放防护正确（首次通过 + 二次拒绝）。
    #[tokio::test]
    async fn check_assertion_replay_serial_replay_protection() {
        let dao = crate::dao::tests::MockDao::new();
        let future = Utc::now().timestamp() + 3600;
        let future_str = chrono::DateTime::from_timestamp(future, 0)
            .unwrap()
            .to_rfc3339();

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

    // parse_saml_response_xml 结构覆盖测试

    /// `raw_xml` 应包含完整 `<Assertion>...</Assertion>` 原始 XML。
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

    /// 空 Assertion 元素（无子元素）解析为 Some 但字段均为空；补未来 NotOnOrAfter 以通过时间条件校验
    /// （缺失拒绝发生在 into_response）。
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

    /// NotOnOrAfter 缺失（空）即拒绝——无过期时间的断言不得放行。
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

    /// NotBefore 在未来的断言即刻使用应被拒绝。
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

    /// 已生效 NotBefore + 有效期内的断言正常通过。
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

    // InResponseTo ↔ AuthnRequest 绑定校验

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

    /// 配置 DAO 后，InResponseTo 首次消费通过、二次消费拒绝（一次性）。
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

    /// 未注册的 InResponseTo 直接拒绝。
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

    /// 无 DAO 时携带 InResponseTo 的响应 fail-closed 拒绝（无法验证绑定）。
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

    /// IdP-initiated（无 InResponseTo）响应在无 DAO 时放行（warn 一次）。
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
